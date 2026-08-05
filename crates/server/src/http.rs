use std::sync::{Arc, LazyLock};

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value, json};
use tower::ServiceBuilder;

use crate::mcp::McpContext;
use noted::authorization::{Authorization, Bearer};
use noted::error::NotedError;
use noted::{Backend, ToolCall};
use noted_auth::oauth::service::BearerKind;
use noted_auth::oauth::types::Secret;
use noted_auth::{AuthService, AuthState, OAuthProvider};

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
    (status, Json(json!({"detail": error.message()}))).into_response()
}

#[derive(Clone)]
pub struct AppState {
    pub backend: Arc<Backend>,
    auth: Option<AuthState>,
}

impl AppState {
    pub fn auth(&self) -> Option<&Arc<AuthService>> {
        self.auth.as_ref().map(AuthState::auth)
    }

    pub fn oauth(&self) -> Option<&Arc<OAuthProvider>> {
        self.auth.as_ref().and_then(AuthState::oauth)
    }
}

pub fn build_app(
    backend: Arc<Backend>,
    auth: Option<Arc<AuthService>>,
    oauth: Option<Arc<OAuthProvider>>,
) -> Router {
    let auth = auth.map(|auth| AuthState::new(auth, oauth));
    let state = AppState { backend, auth };

    let mcp_ctx = McpContext {
        backend: state.backend.clone(),
    };
    let mut mcp_config = StreamableHttpServerConfig::default();
    mcp_config.legacy_session_mode = false;
    mcp_config.json_response = true;
    mcp_config.allowed_hosts.clear();
    let mcp_service = StreamableHttpService::new(
        move || Ok(mcp_ctx.clone()),
        Arc::new(LocalSessionManager::default()),
        mcp_config,
    );
    let mcp_service = ServiceBuilder::new()
        .layer(middleware::from_fn_with_state(
            state.clone(),
            |State(state): State<AppState>, request, next| auth_middleware(state, request, next),
        ))
        .service(mcp_service);

    let mut tool_router = Router::new()
        .route("/tool/{name}", post(tool_handler))
        .with_state(state.clone());
    if let Some(auth) = state.auth.clone() {
        tool_router = tool_router.merge(noted_auth::routes(auth));
    }
    let tool_router = tool_router.layer(middleware::from_fn_with_state(
        state.clone(),
        |State(state): State<AppState>, request, next| auth_middleware(state, request, next),
    ));

    Router::new()
        .nest_service("/mcp", mcp_service)
        .merge(tool_router)
        .route("/", get(document))
        .route(APP_JS, get(glue))
}

fn bearer(headers: &HeaderMap) -> Option<Secret> {
    use axum_extra::headers::{Authorization, HeaderMapExt, authorization::Bearer};
    headers
        .typed_get::<Authorization<Bearer>>()
        .map(|auth| Secret::new(auth.token()))
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"detail": "unauthorized"})),
    )
        .into_response()
}

async fn auth_middleware(
    state: AppState,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    match resolve(&state, request.headers(), &path).await {
        Ok(authorization) => {
            request.extensions_mut().insert(authorization);
            next.run(request).await
        }
        Err(resp) => resp,
    }
}

fn is_public(path: &str) -> bool {
    path.starts_with("/.well-known/")
        || matches!(path, "/register" | "/authorize" | "/login" | "/token")
}

async fn resolve(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> std::result::Result<Option<Authorization>, Response> {
    if is_public(path) {
        return Ok(None);
    }
    let Some(auth) = state.auth() else {
        return Ok(None);
    };
    if let Some(token) = bearer(headers) {
        match BearerKind::from_secret(token.expose()) {
            Some(BearerKind::Access) | Some(BearerKind::ApiKey) => {
                if let Ok(Some((_owner, grant))) = auth.resolve_bearer(token.expose())
                    && let Ok(authorization) = Authorization::new(vec![grant], None)
                {
                    return Ok(Some(authorization));
                }
            }
            Some(BearerKind::Macaroon) => {
                if let Ok(macaroon) = auth.from_bearer(token.expose())
                    && let Ok(grants) = macaroon.authority()
                    && let Ok(authorization) =
                        Authorization::new(grants.to_vec(), Some(Bearer::new(macaroon.expose())))
                {
                    return Ok(Some(authorization));
                }
            }
            Some(BearerKind::Refresh) | None => {}
        }
    }
    Err(if state.oauth().is_some() {
        oauth_challenge(state)
    } else {
        unauthorized()
    })
}

async fn tool_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Extension(authorization): Extension<Option<Authorization>>,
    Json(args): Json<Value>,
) -> Response {
    match run(&state, &name, args, authorization).await {
        Ok(output) => Json(json!({ "ok": output })).into_response(),
        Err(e) => error_response(e),
    }
}

async fn run(
    state: &AppState,
    name: &str,
    args: Value,
    authorization: Option<Authorization>,
) -> noted::Result<noted::tools::ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    let backend = state.backend.with_authority(authorization.as_ref())?;
    backend.invoke(&call).await
}

fn oauth_challenge(state: &AppState) -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response();
    if let Some(oauth) = state.oauth()
        && let Ok(v) = HeaderValue::from_str(&oauth.resource_metadata_challenge())
    {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}
