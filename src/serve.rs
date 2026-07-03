use std::sync::Arc;

use rmcp::serve_server;
use rmcp::transport::stdio;

use crate::cli::{McpCmd, ServeCmd};
use crate::config::{self, expand_home, resolve_root};
use crate::error::{rejected, unavailable, Result};
use crate::mcp::context;
use crate::notes::Notes;
use crate::oauth::{AuthService, OAuthProvider};
use crate::tasks::Tasks;

fn build_cores(dir: Option<String>, source: Option<String>) -> Result<(Notes, Tasks)> {
    let root = resolve_root(dir.as_deref())?;
    let notes = Notes::new(&root, source.filter(|s| !s.is_empty()))?;
    let tasks = Tasks::new(notes.root());
    Ok((notes, tasks))
}

pub(crate) fn serve(cmd: ServeCmd, dir: Option<String>) -> Result<()> {
    let host = cmd.host.clone();
    let port = cmd.port;
    let source = cmd.source.clone();

    let auth = match &cmd.auth_db {
        Some(path) => {
            let db = Arc::new(crate::oauth::Db::open(&expand_home(
                &path.to_string_lossy(),
            ))?);
            let svc = Arc::new(AuthService::new(db, cmd.default_ttl));
            svc.sweep()?;
            Some(svc)
        }
        None => None,
    };
    if cmd.admin_socket.is_some() && auth.is_none() {
        return Err(rejected("--admin-socket requires --auth-db"));
    }
    let oauth = match (&cmd.public_url, &auth) {
        (Some(url), Some(svc)) => Some(Arc::new(OAuthProvider::new(url, svc.clone())?)),
        (Some(_), None) => return Err(rejected("--public-url requires --auth-db")),
        (None, _) => None,
    };
    let admin_socket = cmd.admin_socket.clone();

    let (notes, tasks) = build_cores(dir, source)?;
    let mut ctx = context(notes, tasks);
    ctx.process_scope = cmd.scope.to_call_scope()?;
    let auth_for_socket = auth.clone();
    let app = crate::http::build_app(ctx, auth, oauth.clone());

    config::block_on(async move {
        let admin_handle = match (&admin_socket, &auth_for_socket) {
            (Some(path), Some(svc)) => {
                let listener = crate::oauth::admin::bind_socket(path)?;
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
        match admin_handle {
            Some(mut handle) => {
                tokio::select! {
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
                }
            }
            None => server.await.map_err(|e| rejected(format!("serve: {e}"))),
        }
    })
}

pub(crate) fn mcp_stdio(cmd: McpCmd, dir: Option<String>) -> Result<()> {
    let source = cmd.source.clone();
    let (notes, tasks) = build_cores(dir, source)?;
    let mut ctx = context(notes, tasks);
    ctx.process_scope = cmd.scope.to_call_scope()?;

    config::block_on(async move {
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
