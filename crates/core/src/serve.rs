use std::path::PathBuf;
use std::sync::Arc;

use rmcp::serve_server;
use rmcp::transport::stdio;

use crate::caller::{Caller, Policy};
use crate::error::{Result, io_error, rejected};
use crate::mcp::{CallScope, context};
use crate::oauth::{AuthService, OAuthProvider};
use crate::root::NotedRoot;
use crate::store::{NotedDir, Store};
use crate::types::{Source, Ttl};

/// Everything the HTTP server needs, already resolved: no clap type, flag
/// spelling, or environment lookup crosses this boundary.
pub struct HttpConfig {
    pub dir: NotedDir,
    pub source: Option<Source>,
    pub host: String,
    pub port: u16,
    pub public_url: Option<String>,
    pub auth_db: Option<PathBuf>,
    #[cfg(unix)]
    pub admin_socket: Option<PathBuf>,
    pub default_ttl: Ttl,
    pub scope: CallScope,
}

/// The resolved counterpart of [`HttpConfig`] for the stdio MCP server.
pub struct StdioConfig {
    pub dir: NotedDir,
    pub source: Option<Source>,
    pub scope: CallScope,
}

fn build_root(dir: NotedDir, source: Option<Source>) -> Result<NotedRoot> {
    Ok(NotedRoot::new(
        Store::open(dir)?,
        Caller::new(Policy::any(), source),
    ))
}

fn block_on<F, T>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Runtime::new().map_err(|e| io_error("runtime", e))?;
    runtime.block_on(fut)
}

pub fn serve_http(cfg: HttpConfig) -> Result<()> {
    let auth = match &cfg.auth_db {
        Some(path) => {
            let db = Arc::new(crate::oauth::Db::open(path)?);
            let svc = Arc::new(AuthService::new(db, cfg.default_ttl));
            svc.sweep()?;
            Some(svc)
        }
        None => None,
    };
    let oauth = match (&cfg.public_url, &auth) {
        (Some(url), Some(svc)) => Some(Arc::new(OAuthProvider::new(url, svc.clone())?)),
        (Some(_), None) => return Err(rejected("a public URL requires an auth database")),
        (None, _) => None,
    };
    #[cfg(unix)]
    let admin_socket = match (&cfg.admin_socket, &auth) {
        (Some(_), None) => return Err(rejected("an admin socket requires an auth database")),
        (path, _) => path.clone(),
    };

    let mut ctx = context(build_root(cfg.dir, cfg.source)?);
    ctx.process_scope = cfg.scope;
    let auth_for_socket = auth.clone();
    let app = crate::http::build_app(ctx, auth, oauth.clone());
    let host = cfg.host;
    let port = cfg.port;

    block_on(async move {
        #[cfg(unix)]
        let admin_handle = match (&admin_socket, &auth_for_socket) {
            (Some(path), Some(svc)) => {
                let listener = crate::oauth::admin::bind_socket(path).await?;
                tracing::info!(socket = %path.display(), "admin socket listening");
                Some(tokio::spawn(crate::oauth::admin::serve_socket(
                    listener,
                    svc.clone(),
                )))
            }
            _ => None,
        };
        let addr = format!("{host}:{port}");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| rejected(format!("bind {addr}: {e}")))?;
        tracing::info!(
            %addr,
            auth = auth_for_socket.is_some(),
            oauth = oauth.is_some(),
            "serving http"
        );
        let server = std::future::IntoFuture::into_future(axum::serve(listener, app));
        tokio::pin!(server);
        #[cfg(unix)]
        if let Some(mut handle) = admin_handle {
            use crate::error::unavailable;
            return tokio::select! {
                r = &mut server => {
                    handle.abort();
                    let _ = handle.await;
                    r.map_err(|e| rejected(format!("serve: {e}")))
                }
                joined = &mut handle => match joined {
                    Ok(()) => Err(unavailable("admin socket server exited unexpectedly")),
                    Err(e) if e.is_cancelled() => Ok(()),
                    Err(e) => Err(unavailable(format!("admin socket task failed: {e}"))),
                },
            };
        }
        server.await.map_err(|e| rejected(format!("serve: {e}")))
    })
}

pub fn serve_stdio(cfg: StdioConfig) -> Result<()> {
    let mut ctx = context(build_root(cfg.dir, cfg.source)?);
    ctx.process_scope = cfg.scope;

    block_on(async move {
        let running = serve_server(ctx, stdio())
            .await
            .map_err(|e| rejected(format!("mcp stdio: {e}")))?;
        running
            .waiting()
            .await
            .map_err(|e| rejected(format!("mcp stdio: {e}")))?;
        Ok(())
    })
}
