use std::path::PathBuf;
use std::sync::Arc;

use rmcp::serve_server;
use rmcp::transport::stdio;

use crate::mcp::context;
use noted::error::{Result, io_error, rejected};
use noted::types::Ttl;
use noted::{Backend, BackendArgs};
use noted_auth::{AuthService, OAuthProvider};

/// Everything the HTTP server needs, already resolved: no clap type, flag
/// spelling, or environment lookup crosses this boundary.
pub struct HttpConfig {
    pub backend: BackendArgs,
    pub host: String,
    pub port: u16,
    pub public_url: Option<String>,
    pub auth_db: Option<PathBuf>,
    #[cfg(unix)]
    pub admin_socket: Option<PathBuf>,
    pub default_ttl: Ttl,
}

/// The resolved counterpart of [`HttpConfig`] for the stdio MCP server.
pub struct StdioConfig {
    pub backend: BackendArgs,
}

fn block_on<F, T>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Runtime::new().map_err(|e| io_error("runtime", e))?;
    runtime.block_on(fut)
}

pub fn serve_http(cfg: HttpConfig) -> Result<()> {
    let proxying = cfg
        .backend
        .url
        .as_deref()
        .is_some_and(|url| !url.is_empty());
    if proxying && cfg.auth_db.is_some() {
        return Err(rejected(
            "a server standing in front of another holds no auth database",
        ));
    }
    let auth = match (&cfg.auth_db, proxying) {
        (Some(path), _) => {
            let db = Arc::new(noted_auth::oauth::Db::open(path)?);
            let svc = Arc::new(AuthService::new(db, cfg.default_ttl));
            svc.sweep()?;
            Some(svc)
        }
        (None, true) => match cfg.backend.token.as_ref() {
            Some(token) => Some(Arc::new(AuthService::upstream(
                token.expose(),
                cfg.default_ttl,
            )?)),
            None => None,
        },
        (None, false) => None,
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

    let backend = Arc::new(Backend::new(cfg.backend)?);
    let auth_for_socket = auth.clone();
    let app = crate::http::build_app(backend, auth, oauth.clone());
    let host = cfg.host;
    let port = cfg.port;

    block_on(async move {
        #[cfg(unix)]
        let admin_handle = match (&admin_socket, &auth_for_socket) {
            (Some(path), Some(svc)) => {
                let listener = noted_auth::oauth::admin::bind_socket(path).await?;
                tracing::info!(socket = %path.display(), "admin socket listening");
                Some(tokio::spawn(noted_auth::oauth::admin::serve_socket(
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
            use noted::error::unavailable;
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
    let ctx = context(Arc::new(Backend::new(cfg.backend)?));

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
