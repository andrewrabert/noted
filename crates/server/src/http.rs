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

use crate::mcp::McpContext;
use crate::relay::Relay;
use noted::error::NotedError;
use noted::{NotedRoot, ToolCall};
use noted_auth::{AuthState, Denial, Verified};

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

/// What the app answers from: the notes tree on this host, or another server
/// reached through a relay.
#[derive(Clone)]
pub enum Served {
    Origin(NotedRoot),
    Relay(Arc<Relay>),
}

#[derive(Clone)]
struct AppState {
    served: Served,
    auth: AuthState,
}

impl AppState {
    /// An origin that holds an auth database admits nobody without a bearer.
    /// An open origin and a relay both answer a caller that presents none.
    fn requires_bearer(&self) -> bool {
        matches!(self.served, Served::Origin(_)) && self.auth.minter().is_some()
    }
}

pub fn build_app(served: Served, auth: AuthState) -> Router {
    let state = AppState {
        served: served.clone(),
        auth: auth.clone(),
    };

    let inner = match &served {
        Served::Origin(root) => Router::new()
            .route("/tool/{name}", post(origin_tool))
            .with_state(root.clone())
            .nest_service("/mcp", mcp_service(root.clone())),
        Served::Relay(relay) => Router::new()
            .route("/tool/{name}", post(relay_forward))
            .route("/mcp", post(relay_forward))
            .with_state(relay.clone()),
    };

    inner
        .merge(noted_auth::routes(auth))
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
    let presented = bearer(request.headers());
    if presented.is_none() && state.requires_bearer() {
        return denial_response(&Denial::Unauthorized("unauthorized".into()), &state);
    }
    match state.auth.verifier().verify(presented) {
        Ok(caller) => {
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        Err(denial) => denial_response(&denial, &state),
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
    match run(&root, &name, args, &caller).await {
        Ok(output) => Json(json!({ "ok": output })).into_response(),
        Err(e) => error_response(e),
    }
}

async fn run(
    root: &NotedRoot,
    name: &str,
    args: Value,
    caller: &Verified,
) -> noted::Result<noted::tools::ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    root.with_authority(caller.fragments())?.invoke(&call).await
}

async fn relay_forward(
    State(relay): State<Arc<Relay>>,
    OriginalUri(uri): OriginalUri,
    Extension(caller): Extension<Verified>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay
        .forward(uri.path(), accept(&headers), &caller, body)
        .await
}
