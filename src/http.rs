use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{json, Value};
use tower::ServiceBuilder;

use crate::error::NotedError;
use crate::mcp::{authorize_and_run, CallScope, Dispatch, McpContext};
use crate::oauth::service::BearerKind;
use crate::oauth::types::Secret;
use crate::oauth::{AuthService, OAuthProvider};

impl IntoResponse for NotedError {
    fn into_response(self) -> Response {
        let status = match &self {
            NotedError::NotFound(_) => StatusCode::NOT_FOUND,
            NotedError::Forbidden(_) => StatusCode::FORBIDDEN,
            NotedError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            NotedError::Unavailable(_)
            | NotedError::Io { .. }
            | NotedError::Json { .. }
            | NotedError::Yaml { .. }
            | NotedError::Db { .. }
            | NotedError::Http { .. } => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"detail": self.message()}))).into_response()
    }
}

#[derive(Clone)]
pub enum Authn {
    Disabled,
    Enabled {
        auth: Arc<AuthService>,
        oauth: Option<Arc<OAuthProvider>>,
    },
}

#[derive(Clone)]
pub struct AppState {
    pub ctx: McpContext,
    authn: Authn,
}

impl AppState {
    pub fn auth(&self) -> Option<&Arc<AuthService>> {
        match &self.authn {
            Authn::Disabled => None,
            Authn::Enabled { auth, .. } => Some(auth),
        }
    }

    pub fn oauth(&self) -> Option<&Arc<OAuthProvider>> {
        match &self.authn {
            Authn::Disabled => None,
            Authn::Enabled { oauth, .. } => oauth.as_ref(),
        }
    }
}

pub fn build_app(
    ctx: McpContext,
    auth: Option<Arc<AuthService>>,
    oauth: Option<Arc<OAuthProvider>>,
) -> Router {
    let authn = match auth {
        Some(auth) => Authn::Enabled { auth, oauth },
        None => Authn::Disabled,
    };
    let state = AppState { ctx, authn };

    let mcp_ctx = state.ctx.clone();
    let mut mcp_config = StreamableHttpServerConfig::default();
    mcp_config.stateful_mode = false;
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

    let mut tool_router = Router::new().route("/tool/{name}", post(tool_handler));
    if let Some(oauth) = state.oauth() {
        tool_router = crate::oauth::mount_routes(tool_router, oauth.clone());
    }
    if state.auth().is_some() {
        tool_router = crate::oauth::macaroon::mount_routes(tool_router);
    }
    let tool_router = tool_router.layer(middleware::from_fn_with_state(
        state.clone(),
        |State(state): State<AppState>, request, next| auth_middleware(state, request, next),
    ));

    Router::new()
        .nest_service("/mcp", mcp_service)
        .merge(tool_router)
        .with_state(state)
}

fn bearer(headers: &HeaderMap) -> Option<Secret> {
    use axum_extra::headers::{authorization::Bearer, Authorization, HeaderMapExt};
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
        Ok(scope) => {
            request.extensions_mut().insert(scope);
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
) -> std::result::Result<CallScope, Response> {
    if is_public(path) {
        return Ok(CallScope::Unconfined);
    }
    let Some(auth) = state.auth() else {
        return Ok(state.ctx.process_scope.clone());
    };
    if let Some(token) = bearer(headers) {
        match BearerKind::from_secret(token.expose()) {
            Some(BearerKind::Access) | Some(BearerKind::ApiKey) => {
                if let Ok(Some((_owner, scope))) = auth.resolve_bearer(token.expose()) {
                    return Ok(CallScope::Scoped(scope));
                }
            }
            Some(BearerKind::Macaroon) => {
                if let Some(scope) = crate::oauth::macaroon::verify(auth, token.expose()) {
                    return Ok(CallScope::Scoped(scope));
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
    Extension(scope): Extension<CallScope>,
    Json(args): Json<Value>,
) -> Response {
    match authorize_and_run(&state.ctx, &name, &args, &scope).await {
        Dispatch::Ok(output) => Json(json!({ "ok": output })).into_response(),
        Dispatch::Unknown => (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown tool"})),
        )
            .into_response(),
        Dispatch::Forbidden => (
            StatusCode::FORBIDDEN,
            Json(json!({"detail": "tool not permitted for this token"})),
        )
            .into_response(),
        Dispatch::Invalid(msg) => {
            (StatusCode::BAD_REQUEST, Json(json!({"detail": msg}))).into_response()
        }
        Dispatch::Failed(e) => e.into_response(),
    }
}

fn oauth_challenge(state: &AppState) -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response();
    if let Some(oauth) = state.oauth() {
        if let Ok(v) = HeaderValue::from_str(&oauth.resource_metadata_challenge()) {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
    }
    resp
}
