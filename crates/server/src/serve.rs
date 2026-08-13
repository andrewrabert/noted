use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::serve_server;
use rmcp::transport::stdio;

use crate::http::Served;
use crate::mcp::context;
use crate::relay::Relay;
use noted::error::{Result, rejected, unavailable};
use noted::store::NotedDir;
use noted::types::{Source, Ttl};
use noted::{Bearer, Endpoint, NotedRoot, PolicyArgs, PolicyFragment, Transport};
use noted_auth::authority::RelayCredential;
use noted_auth::{AuthService, AuthState, OAuthProvider};

/// What a served process stands on: its own notes tree, or another server.
pub enum ServedConfig {
    Origin {
        dir: NotedDir,
        source: Option<Source>,
        policy: PolicyArgs,
    },
    Relay {
        endpoint: Endpoint,
        bearer: Option<Bearer>,
        policy: PolicyArgs,
        transport: Transport,
    },
}

impl ServedConfig {
    fn is_origin(&self) -> bool {
        matches!(self, ServedConfig::Origin { .. })
    }
}

/// What the HTTP app listens on.
pub enum Bind {
    Tcp {
        host: String,
        port: u16,
    },
    #[cfg(unix)]
    Socket(crate::socket::SocketBind),
}

impl Bind {
    /// `http://<host>:<port>` or `unix://<path>`. A picked socket names its
    /// path only once bound, so [`serve_http`] asks after the bind.
    pub fn endpoint(&self) -> String {
        match self {
            Bind::Tcp { host, port } => format!("http://{host}:{port}"),
            #[cfg(unix)]
            Bind::Socket(crate::socket::SocketBind::Explicit(path)) => {
                format!("unix://{}", path.display())
            }
            #[cfg(unix)]
            Bind::Socket(crate::socket::SocketBind::Picked(_)) => "unix://".to_string(),
        }
    }
}

/// Everything the HTTP server needs, already resolved: no clap type, flag
/// spelling, or environment lookup crosses this boundary.
pub struct HttpConfig {
    pub served: ServedConfig,
    pub bind: Bind,
    pub public_url: Option<String>,
    pub auth_db: Option<PathBuf>,
    #[cfg(unix)]
    pub admin_socket: Option<PathBuf>,
    pub default_ttl: Ttl,
}

/// The resolved counterpart of [`HttpConfig`] for the stdio MCP server.
pub struct StdioConfig {
    pub served: ServedConfig,
}

/// Opens the auth database off the blocking pool and sweeps it.
async fn open_auth(path: &Path, default_ttl: Ttl) -> Result<Arc<AuthService>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let db = Arc::new(noted_auth::Db::open(&path)?);
        let svc = Arc::new(AuthService::new(db, default_ttl));
        svc.sweep()?;
        Ok(svc)
    })
    .await
    .map_err(|e| unavailable(format!("cannot open auth database: {e}")))?
}

fn one_fragment(policy: &PolicyArgs) -> Result<PolicyFragment> {
    Ok(policy.fragments()?.into_iter().next().unwrap_or_default())
}

fn origin(
    dir: NotedDir,
    source: Option<Source>,
    policy: PolicyArgs,
    auth: Option<&Arc<AuthService>>,
    oauth: Option<Arc<OAuthProvider>>,
) -> Result<(Served, AuthState)> {
    let root = NotedRoot::open(dir, source)?.with_authority(&policy.fragments()?)?;
    let state = match auth {
        Some(service) => AuthState::origin(service.clone(), oauth),
        None => AuthState::open(),
    };
    Ok((Served::Origin(root), state))
}

fn relay(
    endpoint: Endpoint,
    bearer: Option<Bearer>,
    policy: PolicyArgs,
    transport: Transport,
    ledger: Option<Arc<AuthService>>,
    at: String,
) -> Result<(Served, AuthState)> {
    let credential = Arc::new(RelayCredential::open(
        bearer.as_ref(),
        one_fragment(&policy)?,
        ledger,
        at,
    )?);
    let relay = Arc::new(Relay::open(credential.clone(), endpoint, transport)?);
    Ok((Served::Relay(relay), AuthState::relay(credential)))
}

/// What a bound listener answers on, kept together with the guard that
/// unlinks its socket when the process stops.
enum Bound {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Socket(tokio::net::UnixListener, crate::socket::SocketGuard),
}

async fn bind(spec: Bind) -> Result<(Bound, String)> {
    match spec {
        Bind::Tcp { host, port } => {
            let addr = format!("{host}:{port}");
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .map_err(|e| rejected(format!("bind {addr}: {e}")))?;
            let endpoint = Bind::Tcp { host, port }.endpoint();
            Ok((Bound::Tcp(listener), endpoint))
        }
        #[cfg(unix)]
        Bind::Socket(spec) => {
            let (listener, guard) = spec.bind()?;
            let socket = guard.path().to_path_buf();
            tokio::task::spawn_blocking({
                let socket = socket.clone();
                move || crate::socket::write_endpoint_line(&mut std::io::stdout().lock(), &socket)
            })
            .await
            .map_err(|e| unavailable(format!("endpoint line: {e}")))??;
            let endpoint = Bind::Socket(crate::socket::SocketBind::Explicit(socket)).endpoint();
            Ok((Bound::Socket(listener, guard), endpoint))
        }
    }
}

pub async fn serve_http(cfg: HttpConfig) -> Result<()> {
    if cfg.public_url.is_some() && !cfg.served.is_origin() {
        return Err(rejected("a public URL requires a notes directory"));
    }
    let auth = match &cfg.auth_db {
        Some(path) => Some(open_auth(path, cfg.default_ttl).await?),
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

    let (bound, endpoint) = bind(cfg.bind).await?;
    let (served, auth_state) = match cfg.served {
        ServedConfig::Origin {
            dir,
            source,
            policy,
        } => origin(dir, source, policy, auth.as_ref(), oauth.clone())?,
        ServedConfig::Relay {
            endpoint: upstream,
            bearer,
            policy,
            transport,
        } => relay(
            upstream,
            bearer,
            policy,
            transport,
            auth.clone(),
            endpoint.clone(),
        )?,
    };
    let app = crate::http::build_app(served, auth_state.clone());

    #[cfg(not(unix))]
    let admin_handle: Option<tokio::task::JoinHandle<()>> = None;
    #[cfg(unix)]
    let (admin_handle, _admin_guard) = match (&admin_socket, &auth, auth_state.minter()) {
        (Some(path), Some(svc), Some(minter)) => {
            let (listener, guard) = crate::socket::bind_unix_socket(path, Some(0o600))?;
            tracing::info!(socket = %path.display(), "admin socket listening");
            let admin = noted_auth::admin::Admin::new(svc.clone(), minter.clone());
            let task = tokio::spawn(noted_auth::admin::serve_socket(listener, admin));
            (Some(task), Some(guard))
        }
        _ => (None, None),
    };

    tracing::info!(
        %endpoint,
        auth = auth.is_some(),
        oauth = oauth.is_some(),
        "serving http"
    );
    match bound {
        Bound::Tcp(listener) => serve_listener(listener, app, admin_handle).await,
        #[cfg(unix)]
        Bound::Socket(listener, guard) => {
            let _guard = guard;
            serve_listener(listener, app, admin_handle).await
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
    match cfg.served {
        ServedConfig::Origin {
            dir,
            source,
            policy,
        } => {
            let root = NotedRoot::open(dir, source)?.with_authority(&policy.fragments()?)?;
            let running = serve_server(context(root), stdio())
                .await
                .map_err(|e| rejected(format!("mcp stdio: {e}")))?;
            running
                .waiting()
                .await
                .map_err(|e| rejected(format!("mcp stdio: {e}")))?;
            Ok(())
        }
        ServedConfig::Relay {
            endpoint,
            bearer,
            policy,
            transport,
        } => {
            let at = endpoint.to_string();
            let credential = Arc::new(RelayCredential::open(
                bearer.as_ref(),
                one_fragment(&policy)?,
                None,
                at,
            )?);
            Relay::open(credential, endpoint, transport)?
                .pipe_stdio()
                .await
        }
    }
}
