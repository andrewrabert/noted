use std::sync::{Arc, LazyLock};

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value, json};

use crate::auth::AuthState;
use crate::mcp::McpContext;
use crate::relay::Relay;
use noted::error::NotedError;
use noted::{NotedRoot, PolicyFragment, ToolCall};
use noted_auth::{Denial, Verified};
use url::form_urlencoded;

const APP_JS: &str = "/noted_ui.js";
const GLUE: &str = include_str!(concat!(env!("OUT_DIR"), "/noted_ui.js"));

static DOCUMENT: LazyLock<String> = LazyLock::new(|| {
    format!(
        "<!DOCTYPE html>\
         <html lang=\"en\">\
         <head>\
         <meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>noted</title>\
         <style>html,body{{margin:0;height:100%;overflow:hidden;background:#1a1b26}}</style>\
         </head>\
         <body>\
         <script type=\"module\">\
         import init, {{ WASM }} from \"{APP_JS}\";\
         init({{ module_or_path: Uint8Array.from(atob(WASM), c => c.charCodeAt(0)) }});\
         </script>\
         </body>\
         </html>"
    )
});

async fn document() -> Html<&'static str> {
    Html(DOCUMENT.as_str())
}

async fn glue() -> ([(HeaderName, &'static str); 1], &'static str) {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        GLUE,
    )
}

fn error_response(error: NotedError) -> Response {
    let status = match &error {
        NotedError::NotFound => StatusCode::NOT_FOUND,
        NotedError::Forbidden => StatusCode::FORBIDDEN,
        NotedError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        NotedError::Conflict => StatusCode::CONFLICT,
        NotedError::Unavailable(_)
        | NotedError::Io { .. }
        | NotedError::Json { .. }
        | NotedError::Db { .. }
        | NotedError::Http { .. } => StatusCode::SERVICE_UNAVAILABLE,
    };
    detail(status, error.message().into_owned())
}

fn detail(status: StatusCode, message: String) -> Response {
    (status, Json(json!({ "detail": message }))).into_response()
}

/// What the app answers from and the authentication derived for that same
/// source.
#[derive(Clone)]
pub struct Served {
    kind: ServedKind,
    auth: AuthState,
}

#[derive(Clone)]
enum ServedKind {
    Origin(NotedRoot),
    Relay(Arc<Relay>),
}

impl Served {
    pub fn origin(root: NotedRoot, auth: AuthState) -> Served {
        Served {
            kind: ServedKind::Origin(root),
            auth,
        }
    }

    pub fn relay(relay: Arc<Relay>) -> Served {
        let auth = AuthState::relay(relay.clone());
        Served {
            kind: ServedKind::Relay(relay),
            auth,
        }
    }

    pub(crate) fn auth(&self) -> &AuthState {
        &self.auth
    }
}

#[derive(Clone)]
struct AppState {
    auth: AuthState,
}

impl AppState {
    fn requires_bearer(&self) -> bool {
        self.auth.minter().is_some()
    }
}

pub fn build_app(served: Served) -> Router {
    let state = AppState {
        auth: served.auth.clone(),
    };

    let inner = match &served.kind {
        ServedKind::Origin(root) => Router::new()
            .route("/tool/{name}", post(origin_tool))
            .with_state(root.clone())
            .nest_service("/mcp", mcp_service(root.clone())),
        ServedKind::Relay(relay) => Router::new()
            .route("/tool/{name}", post(relay_forward))
            .route("/mcp", post(relay_forward))
            .with_state(relay.clone()),
    };

    inner
        .merge(crate::auth::routes(served.auth))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            |State(state): State<AppState>, request, next| auth_middleware(state, request, next),
        ))
        .route("/", get(document))
        .route(APP_JS, get(glue))
}

fn mcp_service(root: NotedRoot) -> StreamableHttpService<McpContext, LocalSessionManager> {
    let context = crate::mcp::context(root);
    let mut config = StreamableHttpServerConfig::default();
    config.legacy_session_mode = false;
    config.json_response = true;
    config.allowed_hosts.clear();
    StreamableHttpService::new(
        move || Ok(context.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn accept(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::ACCEPT)?.to_str().ok()
}

/// The policy the request asks to be held to, outermost first. No `policy=`
/// is an empty ask, which narrows nothing.
fn query_policy(request: &axum::extract::Request) -> noted::error::Result<Vec<PolicyFragment>> {
    form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "policy")
        .map(|(_, value)| value.parse())
        .collect()
}

/// The path the caller asked for, before any nested service stripped its
/// prefix: `/mcp/token` is no more public than `/mcp` itself.
fn requested_path(request: &axum::extract::Request) -> String {
    request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| request.uri().path().to_string())
}

fn is_public(path: &str) -> bool {
    path.starts_with("/.well-known/")
        || matches!(path, "/register" | "/authorize" | "/login" | "/token")
}

async fn auth_middleware(
    state: AppState,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = requested_path(&request);
    if is_public(&path) {
        request.extensions_mut().insert(Verified::anonymous());
        return next.run(request).await;
    }
    let presented =
        bearer(request.headers()).map(noted_auth::types::CredentialPresentation::submitted);
    if presented.is_none() && state.requires_bearer() {
        return denial_response(&Denial::Unauthorized("unauthorized".into()), &state);
    }
    let verifier = state.auth.verifier().clone();
    match crate::auth::run_blocking(move || verifier.verify(presented.as_ref())).await {
        Ok(Ok(caller)) => match query_policy(&request) {
            Ok(query) => {
                request.extensions_mut().insert(query);
                request.extensions_mut().insert(caller);
                next.run(request).await
            }
            Err(error) => error_response(error),
        },
        Ok(Err(denial)) => denial_response(&denial, &state),
        Err(error) => detail(
            StatusCode::SERVICE_UNAVAILABLE,
            state.auth.relay_self_error(error).to_string(),
        ),
    }
}

fn denial_response(denial: &Denial, state: &AppState) -> Response {
    match denial {
        Denial::Malformed(message) => detail(StatusCode::BAD_REQUEST, message.clone()),
        Denial::Forbidden(message) => detail(StatusCode::FORBIDDEN, message.clone()),
        Denial::Unauthorized(_) => {
            let mut response = detail(StatusCode::UNAUTHORIZED, "unauthorized".to_string());
            if let Some(oauth) = state.auth.oauth()
                && let Ok(value) = HeaderValue::from_str(&oauth.resource_metadata_challenge())
            {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
            response
        }
    }
}

async fn origin_tool(
    State(root): State<NotedRoot>,
    Path(name): Path<String>,
    Extension(caller): Extension<Verified>,
    Extension(query): Extension<Vec<PolicyFragment>>,
    body: Bytes,
) -> Response {
    let args = if body.is_empty() {
        Value::Object(Default::default())
    } else {
        match serde_json::from_slice(&body) {
            Ok(args) => args,
            Err(e) => return detail(StatusCode::BAD_REQUEST, e.to_string()),
        }
    };
    match run(&root, &name, args, &caller, &query).await {
        Ok(output) => Json(json!({ "ok": output })).into_response(),
        Err(e) => error_response(e),
    }
}

async fn run(
    root: &NotedRoot,
    name: &str,
    args: Value,
    caller: &Verified,
    query: &[PolicyFragment],
) -> noted::Result<noted::tools::ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    root.with_authority(caller.fragments())?
        .with_authority(query)?
        .invoke(&call)
        .await
}

async fn relay_forward(
    State(relay): State<Arc<Relay>>,
    OriginalUri(uri): OriginalUri,
    Extension(asked): Extension<Vec<PolicyFragment>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay
        .forward(uri.path(), accept(&headers), &asked, body)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use noted::Transport;

    #[tokio::test]
    async fn relay_middleware_blocking_failure_names_the_relays_listener_endpoint() {
        let bound = crate::serve::Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .bind()
        .await
        .unwrap();
        let relay = Arc::new(
            Relay::open(
                None,
                PolicyFragment::default(),
                "http://upstream.test/internal".parse().unwrap(),
                &bound,
                Transport::Router(Router::new()),
            )
            .unwrap(),
        );
        let auth = AuthState::relay(relay);
        let error = crate::auth::run_blocking(|| panic!("verification failed"))
            .await
            .unwrap_err();

        let detail = auth.relay_self_error(error).to_string();
        assert!(detail.starts_with(&format!("{}: ", bound.endpoint())));
        assert!(detail.contains("blocking authentication task failed"));
    }

    #[tokio::test]
    async fn origin_middleware_blocking_failure_claims_no_listener_endpoint() {
        let auth = AuthState::open();
        let error = crate::auth::run_blocking(|| panic!("verification failed"))
            .await
            .unwrap_err();

        let detail = auth.relay_self_error(error).to_string();
        assert!(!detail.contains("http://"));
        assert!(detail.starts_with("blocking authentication task failed"));
    }
}
