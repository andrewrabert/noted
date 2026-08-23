use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use rmcp::serve_server;
use rmcp::transport::stdio;

use crate::auth::{AuthState, run_blocking};
use crate::http::Served;
use crate::mcp::context;
use crate::oauth::OAuthProvider;
use crate::relay::Relay;
use noted::error::{Result, rejected, unavailable};
use noted::store::NotedDir;
use noted::types::Source;
use noted::{Bearer, Endpoint, NotedRoot, PolicyArgs, PolicyFragment, Transport};
use noted_auth::AuthService;

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

/// Everything the HTTP server needs, already resolved: no clap type, flag
/// spelling, or environment lookup crosses this boundary.
pub struct HttpConfig {
    pub served: ServedConfig,
    pub bind: Bind,
    pub public_url: Option<String>,
    pub authentication: Option<Arc<AuthService>>,
    #[cfg(unix)]
    pub admin_socket: Option<PathBuf>,
}

/// The resolved counterpart of [`HttpConfig`] for the stdio MCP server.
pub struct StdioConfig {
    pub served: ServedConfig,
}

async fn open_origin(
    dir: NotedDir,
    source: Option<Source>,
    policy: PolicyArgs,
) -> Result<NotedRoot> {
    run_blocking(move || {
        let fragments = policy.fragments()?;
        NotedRoot::open(dir, source)?.with_authority(&fragments)
    })
    .await?
}

async fn origin(
    dir: NotedDir,
    source: Option<Source>,
    policy: PolicyArgs,
    auth: Option<&Arc<AuthService>>,
    oauth: Option<Arc<OAuthProvider>>,
) -> Result<Served> {
    let root = open_origin(dir, source, policy).await?;
    let state = match auth {
        Some(service) => AuthState::origin(service.clone(), oauth).await?,
        None => AuthState::open(),
    };
    Ok(Served::origin(root, state))
}

fn confinement(policy: PolicyArgs) -> Result<PolicyFragment> {
    Ok(policy.fragments()?.into_iter().next().unwrap_or_default())
}

async fn relay(
    upstream_endpoint: Endpoint,
    bound: &Bound,
    bearer: Option<Bearer>,
    policy: PolicyArgs,
    transport: Transport,
) -> Result<Served> {
    let policy = listener_endpoint_result(bound.endpoint(), confinement(policy))?;
    let relay = Arc::new(Relay::open(
        bearer,
        policy,
        upstream_endpoint,
        bound,
        transport,
    )?);
    Ok(Served::relay(relay))
}

fn stdio_relay(
    upstream_endpoint: Endpoint,
    bearer: Option<Bearer>,
    policy: PolicyArgs,
    transport: Transport,
) -> Result<Relay> {
    Relay::open_stdio(bearer, confinement(policy)?, upstream_endpoint, transport)
}

pub(crate) fn listener_endpoint_error(
    endpoint: &ListenerEndpoint,
    error: noted::error::NotedError,
) -> noted::error::NotedError {
    let message = format!("{endpoint}: {}", error.message());
    if error.is_rejection() {
        rejected(message)
    } else {
        unavailable(message)
    }
}

fn listener_endpoint_result<T>(endpoint: &ListenerEndpoint, result: Result<T>) -> Result<T> {
    result.map_err(|error| listener_endpoint_error(endpoint, error))
}

/// What a bound listener answers on, kept together with the guard that
/// unlinks its socket when the process stops.
enum BoundListener {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Socket(tokio::net::UnixListener, crate::socket::SocketGuard),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ListenerEndpoint {
    kind: ListenerEndpointKind,
}

#[derive(Debug, PartialEq, Eq)]
enum ListenerEndpointKind {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ListenerEndpoint {
    pub(crate) fn tcp_addr(&self) -> Option<SocketAddr> {
        match self.kind {
            ListenerEndpointKind::Tcp(addr) => Some(addr),
            #[cfg(unix)]
            ListenerEndpointKind::Unix(_) => None,
        }
    }

    #[cfg(unix)]
    pub(crate) fn unix_path(&self) -> Option<&Path> {
        match &self.kind {
            ListenerEndpointKind::Tcp(_) => None,
            ListenerEndpointKind::Unix(path) => Some(path),
        }
    }
}

impl std::fmt::Display for ListenerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(addr) = self.tcp_addr() {
            return write!(f, "http://{addr}");
        }
        #[cfg(unix)]
        if let Some(path) = self.unix_path() {
            return write!(f, "unix://{}", path.display());
        }
        Err(std::fmt::Error)
    }
}

#[doc = "```compile_fail"]
#[doc = "use noted_server::serve::ListenerEndpoint;"]
#[doc = "```"]
pub struct Bound {
    listener: BoundListener,
    endpoint: Arc<ListenerEndpoint>,
}

impl Bind {
    pub async fn bind(self) -> Result<Bound> {
        match self {
            Bind::Tcp { host, port } => {
                let addr = format!("{host}:{port}");
                let listener = tokio::net::TcpListener::bind(&addr)
                    .await
                    .map_err(|error| rejected(format!("bind {addr}: {error}")))?;
                let local_addr = listener
                    .local_addr()
                    .map_err(|error| unavailable(format!("bound address: {error}")))?;
                if local_addr.port() == 0 {
                    return Err(rejected("a bound TCP listener must have a nonzero port"));
                }
                Ok(Bound {
                    listener: BoundListener::Tcp(listener),
                    endpoint: Arc::new(ListenerEndpoint {
                        kind: ListenerEndpointKind::Tcp(local_addr),
                    }),
                })
            }
            #[cfg(unix)]
            Bind::Socket(spec) => {
                let (listener, guard) = spec.bind()?;
                let socket = guard.path().to_path_buf();
                if !socket.is_absolute() {
                    return Err(rejected(format!(
                        "a bound unix socket is named by an absolute path: {}",
                        socket.display()
                    )));
                }
                let endpoint = Arc::new(ListenerEndpoint {
                    kind: ListenerEndpointKind::Unix(socket.clone()),
                });
                tokio::task::spawn_blocking(move || {
                    crate::socket::write_endpoint_line(&mut std::io::stdout().lock(), &socket)
                })
                .await
                .map_err(|error| unavailable(format!("endpoint line: {error}")))??;
                Ok(Bound {
                    listener: BoundListener::Socket(listener, guard),
                    endpoint,
                })
            }
        }
    }
}

impl Bound {
    pub(crate) fn endpoint(&self) -> &Arc<ListenerEndpoint> {
        &self.endpoint
    }
}

pub async fn serve_http(cfg: HttpConfig) -> Result<()> {
    if cfg.public_url.is_some() && !cfg.served.is_origin() {
        return Err(rejected("a public URL requires a notes directory"));
    }
    let auth = cfg.authentication.as_ref();
    let oauth = match (&cfg.public_url, auth) {
        (Some(url), Some(auth)) => Some(Arc::new(OAuthProvider::new(url, auth.clone()).await?)),
        (Some(_), None) => return Err(rejected("a public URL requires an auth database")),
        (None, _) => None,
    };
    #[cfg(unix)]
    let admin_socket = match (&cfg.admin_socket, auth) {
        (Some(_), None) => return Err(rejected("an admin socket requires an auth database")),
        (path, _) => path.clone(),
    };

    let bound = cfg.bind.bind().await?;
    let served = match cfg.served {
        ServedConfig::Origin {
            dir,
            source,
            policy,
        } => origin(dir, source, policy, auth, oauth.clone()).await?,
        ServedConfig::Relay {
            endpoint: upstream,
            bearer,
            policy,
            transport,
        } => relay(upstream, &bound, bearer, policy, transport).await?,
    };
    let auth_state = served.auth().clone();
    let app = crate::http::build_app(served);

    #[cfg(not(unix))]
    let admin_handle: Option<tokio::task::JoinHandle<()>> = None;
    #[cfg(unix)]
    let (admin_handle, _admin_guard) = match (&admin_socket, auth, auth_state.minter()) {
        (Some(path), Some(svc), Some(minter)) => {
            let (listener, guard) = crate::socket::bind_unix_socket(path, Some(0o600))?;
            tracing::info!(socket = %path.display(), "admin socket listening");
            let administration = noted_auth::Administration::new(svc.clone(), minter.clone());
            let task = tokio::spawn(crate::admin::serve_socket(listener, administration));
            (Some(task), Some(guard))
        }
        _ => (None, None),
    };

    tracing::info!(
        endpoint = %bound.endpoint(),
        auth = auth.is_some(),
        oauth = oauth.is_some(),
        "serving http"
    );
    match bound.listener {
        BoundListener::Tcp(listener) => serve_tcp_listener(listener, app, admin_handle).await,
        #[cfg(unix)]
        BoundListener::Socket(listener, guard) => {
            let _guard = guard;
            serve_unix_listener(listener, app, admin_handle).await
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

async fn serve_tcp_listener(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    admin: Option<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let server = std::future::IntoFuture::into_future(
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal()),
    );
    tokio::pin!(server);
    wait_for_server(&mut server, admin).await
}

#[cfg(unix)]
async fn serve_unix_listener(
    listener: tokio::net::UnixListener,
    app: axum::Router,
    admin: Option<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()),
    );
    tokio::pin!(server);
    wait_for_server(&mut server, admin).await
}

async fn wait_for_server<F>(
    server: &mut std::pin::Pin<&mut F>,
    admin: Option<tokio::task::JoinHandle<()>>,
) -> Result<()>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    if let Some(mut handle) = admin {
        return tokio::select! {
            result = server => {
                handle.abort();
                let _ = handle.await;
                result.map_err(|error| rejected(format!("serve: {error}")))
            }
            joined = &mut handle => match joined {
                Ok(()) => Err(unavailable("admin socket server exited unexpectedly")),
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(unavailable(format!("admin socket task failed: {error}"))),
            },
        };
    }
    server
        .await
        .map_err(|error| rejected(format!("serve: {error}")))
}

pub async fn serve_stdio(cfg: StdioConfig) -> Result<()> {
    match cfg.served {
        ServedConfig::Origin {
            dir,
            source,
            policy,
        } => {
            let root = open_origin(dir, source, policy).await?;
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
            stdio_relay(endpoint, bearer, policy, transport)?
                .pipe_stdio()
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_port_zero_produces_the_os_selected_listener_endpoint() {
        let bound = Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .bind()
        .await
        .unwrap();
        let BoundListener::Tcp(listener) = &bound.listener else {
            panic!("TCP bind returned a Unix listener");
        };
        let selected = listener.local_addr().unwrap();

        assert_ne!(selected.port(), 0);
        assert_eq!(bound.endpoint().tcp_addr(), Some(selected));
        assert_eq!(bound.endpoint().to_string(), format!("http://{selected}"));
    }

    #[tokio::test]
    async fn a_failed_tcp_bind_produces_no_listener_endpoint() {
        let occupied = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = occupied.local_addr().unwrap().port();

        let result = Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port,
        }
        .bind()
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn listener_endpoint_failures_keep_their_error_class_and_bound_identity() {
        let bound = Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .bind()
        .await
        .unwrap();
        let endpoint = bound.endpoint();

        let rejection = listener_endpoint_error(endpoint, rejected("invalid credential"));
        assert_eq!(
            rejection.to_string(),
            format!("{endpoint}: invalid credential")
        );
        assert!(rejection.is_rejection());

        let failure = listener_endpoint_error(endpoint, unavailable("blocking failed"));
        assert_eq!(failure.to_string(), format!("{endpoint}: blocking failed"));
        assert!(!failure.is_rejection());
    }

    #[test]
    fn stdio_relay_policy_errors_name_no_upstream_endpoint() {
        let endpoint: Endpoint = "http://upstream.test/presented".parse().unwrap();
        let result = stdio_relay(
            endpoint,
            None,
            PolicyArgs {
                policy: Some("not json".to_string()),
                ..PolicyArgs::default()
            },
            Transport::Router(axum::Router::new()),
        );
        let Err(error) = result else {
            panic!("invalid relay policy was accepted");
        };

        assert!(error.to_string().contains("invalid policy"));
        assert!(!error.to_string().contains("upstream.test"));
    }

    #[test]
    fn a_stdio_relay_carries_whatever_bearer_it_was_configured_with() {
        let endpoint: Endpoint = "http://upstream.test/presented".parse().unwrap();
        assert!(
            stdio_relay(
                endpoint,
                Some(Bearer::new("not-a-macaroon")),
                PolicyArgs::default(),
                Transport::Router(axum::Router::new()),
            )
            .is_ok()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_relative_bound_unix_socket_returns_no_identity_and_leaves_no_socket_or_lock() {
        let workspace = std::env::current_dir().unwrap();
        let dir = tempfile::Builder::new()
            .prefix(".relative-bound-")
            .tempdir_in(&workspace)
            .unwrap();
        let socket = dir
            .path()
            .strip_prefix(&workspace)
            .unwrap()
            .join("noted.sock");
        assert!(!socket.is_absolute());
        let lock = crate::socket::lock_path(&socket);

        let result = Bind::Socket(crate::socket::SocketBind::Explicit(socket.clone()))
            .bind()
            .await;
        let Err(error) = result else {
            panic!("relative bound socket produced an identity");
        };

        assert!(error.is_rejection());
        assert!(!error.to_string().contains("unix://"));
        assert!(!socket.exists());
        assert!(!lock.exists());
    }
}
