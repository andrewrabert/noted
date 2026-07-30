use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::serve_server;
use rmcp::transport::stdio;

use crate::error::{Result, io_error, rejected};
use crate::mcp::{CallScope, context};
use crate::notes::Notes;
use crate::oauth::{AuthService, OAuthProvider};
use crate::tasks::Tasks;
use crate::types::Ttl;

/// Everything the HTTP server needs, already resolved: no clap type, flag
/// spelling, or environment lookup crosses this boundary.
pub struct HttpConfig {
    pub root: PathBuf,
    pub source: Option<String>,
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
    pub root: PathBuf,
    pub source: Option<String>,
    pub scope: CallScope,
}

fn build_cores(root: &Path, source: Option<String>) -> Result<(Notes, Tasks)> {
    let notes = Notes::new(root, source.filter(|s| !s.is_empty()))?;
    let tasks = Tasks::new(notes.root());
    Ok((notes, tasks))
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

    let (notes, tasks) = build_cores(&cfg.root, cfg.source)?;
    let mut ctx = context(notes, tasks);
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
    let (notes, tasks) = build_cores(&cfg.root, cfg.source)?;
    let mut ctx = context(notes, tasks);
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
