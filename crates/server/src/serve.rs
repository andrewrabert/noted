use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::serve_server;
use rmcp::transport::stdio;

use crate::mcp::context;
use noted::error::{Result, rejected, unavailable};
use noted::types::Ttl;
use noted::{Backend, BackendArgs};
use noted_auth::{AuthService, OAuthProvider};

/// What the HTTP app listens on.
pub enum Bind {
    Tcp {
        host: String,
        port: u16,
    },
    #[cfg(unix)]
    Socket(PathBuf),
}

/// Everything the HTTP server needs, already resolved: no clap type, flag
/// spelling, or environment lookup crosses this boundary.
pub struct HttpConfig {
    pub backend: BackendArgs,
    pub bind: Bind,
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

/// Opens the auth database off the blocking pool and sweeps it.
async fn open_auth(path: &Path, default_ttl: Ttl) -> Result<Arc<AuthService>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let db = Arc::new(noted_auth::oauth::Db::open(&path)?);
        let svc = Arc::new(AuthService::new(db, default_ttl));
        svc.sweep()?;
        Ok(svc)
    })
    .await
    .map_err(|e| unavailable(format!("cannot open auth database: {e}")))?
}

pub async fn serve_http(cfg: HttpConfig) -> Result<()> {
    let proxying = cfg.backend.endpoint.is_some();
    if proxying && cfg.auth_db.is_some() {
        return Err(rejected(
            "a server standing in front of another holds no auth database",
        ));
    }
    let auth = match (&cfg.auth_db, proxying) {
        (Some(path), _) => Some(open_auth(path, cfg.default_ttl).await?),
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
    let bind = cfg.bind;

    {
        #[cfg(not(unix))]
        let admin_handle: Option<tokio::task::JoinHandle<()>> = None;
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
        match bind {
            Bind::Tcp { host, port } => {
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
                serve_listener(listener, app, admin_handle).await
            }
            #[cfg(unix)]
            Bind::Socket(path) => {
                let (listener, _guard) = crate::socket::bind_unix_socket(&path)?;
                tracing::info!(
                    socket = %path.display(),
                    auth = auth_for_socket.is_some(),
                    oauth = oauth.is_some(),
                    "serving http"
                );
                serve_listener(listener, app, admin_handle).await
            }
        }
    }
}

/// Resolves when the process is told to stop: SIGINT or SIGTERM. The serve
/// future then finishes in-flight requests and returns, so every bind guard
/// drops and every socket file is unlinked.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(term) => term,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Serves the app until a stop signal lands, the listener fails, or the
/// admin socket task ends.
async fn serve_listener<L>(
    listener: L,
    app: axum::Router,
    admin: Option<tokio::task::JoinHandle<()>>,
) -> Result<()>
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()),
    );
    tokio::pin!(server);
    if let Some(mut handle) = admin {
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
}

pub async fn serve_stdio(cfg: StdioConfig) -> Result<()> {
    let ctx = context(Arc::new(Backend::new(cfg.backend)?));
    let running = serve_server(ctx, stdio())
        .await
        .map_err(|e| rejected(format!("mcp stdio: {e}")))?;
    running
        .waiting()
        .await
        .map_err(|e| rejected(format!("mcp stdio: {e}")))?;
    Ok(())
}
