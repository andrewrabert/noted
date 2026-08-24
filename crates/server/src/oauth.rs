use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{RawQuery, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::auth::AuthState;
use noted::error::Result;
use noted_auth::service::AuthService;
use noted_auth::types::{AuthorizationTransactionId, LoginName, Password, RedirectUri};

use crate::auth::run_blocking;
pub(crate) mod presentation;
const REDIRECT_URIS: &str = "redirect_uris";
const TOKEN_AUTH: &str = "token_endpoint_auth_method";
const CLIENT_ID: &str = "client_id";
const ISSUED_AT: &str = "client_id_issued_at";

pub struct OAuthProvider {
    public_url: String,
    protocol: Arc<noted_auth::oauth::OAuthProtocol>,
}

impl OAuthProvider {
    pub async fn new(public_url: &str, auth: Arc<AuthService>) -> Result<OAuthProvider> {
        let public_url = public_url.trim_end_matches('/').to_string();
        let protocol = Arc::new(
            run_blocking({
                let auth = auth.clone();
                move || noted_auth::oauth::OAuthProtocol::open(auth)
            })
            .await??,
        );
        Ok(OAuthProvider {
            public_url,
            protocol,
        })
    }

    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    fn issuer(&self) -> &str {
        &self.public_url
    }

    fn resource_url(&self) -> String {
        format!("{}/mcp", self.public_url)
    }

    fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource/mcp",
            self.public_url
        )
    }

    pub fn resource_metadata_challenge(&self) -> String {
        format!(
            "Bearer resource_metadata=\"{}\"",
            self.resource_metadata_url()
        )
    }
}

#[derive(serde::Serialize)]
struct AuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: String,
    response_types_supported: [&'static str; 1],
    response_modes_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 2],
    token_endpoint_auth_methods_supported: [&'static str; 1],
    code_challenge_methods_supported: [&'static str; 1],
}

#[derive(serde::Serialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: [String; 1],
    bearer_methods_supported: [&'static str; 1],
}

fn authorization_server_metadata(p: &OAuthProvider) -> AuthServerMetadata {
    let base = p.issuer();
    AuthServerMetadata {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        registration_endpoint: format!("{base}/register"),
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported: ["none"],
        code_challenge_methods_supported: ["S256"],
    }
}

fn protected_resource_metadata(p: &OAuthProvider) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: p.resource_url(),
        authorization_servers: [p.issuer().to_string()],
        bearer_methods_supported: ["header"],
    }
}

pub fn mount_routes(router: Router<AuthState>) -> Router<AuthState> {
    router
        .route("/.well-known/oauth-authorization-server", get(meta_as))
        .route("/.well-known/oauth-authorization-server/mcp", get(meta_as))
        .route("/.well-known/oauth-protected-resource", get(meta_pr))
        .route("/.well-known/oauth-protected-resource/mcp", get(meta_pr))
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/login", get(login_get).post(login_post))
        .route("/token", post(token))
}

fn provider(state: &AuthState) -> &Arc<OAuthProvider> {
    state.oauth().expect("oauth routes require a provider")
}

async fn meta_as(State(state): State<AuthState>) -> Response {
    Json(authorization_server_metadata(provider(&state))).into_response()
}

async fn meta_pr(State(state): State<AuthState>) -> Response {
    Json(protected_resource_metadata(provider(&state))).into_response()
}

fn parse_form(bytes: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(bytes)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn query_map(raw: &Option<String>) -> HashMap<String, String> {
    match raw {
        Some(q) => parse_form(q.as_bytes()),
        None => HashMap::new(),
    }
}

async fn register(State(state): State<AuthState>, body: Bytes) -> Response {
    let p = provider(&state).clone();
    let info: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata"),
    };
    let Value::Object(mut values) = info else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    };
    let Some(Value::Array(redirects)) = values.get(REDIRECT_URIS) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    };
    if redirects.is_empty() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    let redirects = match redirects
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(())
                .and_then(|value| RedirectUri::new(value).map_err(|_| ()))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .and_then(|redirects| {
            noted_auth::oauth::RegisterOAuthClient::new(redirects).map_err(|_| ())
        }) {
        Ok(redirects) => redirects,
        Err(()) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri"),
    };
    let protocol = p.protocol.clone();
    let client = match run_blocking(move || protocol.register_client(redirects)).await {
        Ok(Ok(client)) => client,
        Ok(Err(error)) | Err(error) => {
            tracing::error!(%error, "oauth client registration failed");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    values.insert(
        REDIRECT_URIS.to_string(),
        Value::Array(
            client
                .redirect_uris()
                .iter()
                .map(|redirect| Value::String(redirect.as_str().to_owned()))
                .collect(),
        ),
    );
    values.insert(
        CLIENT_ID.to_string(),
        Value::String(client.client_id().as_str().to_string()),
    );
    values.insert(ISSUED_AT.to_string(), json!(client.issued_at().as_secs()));
    values
        .entry(TOKEN_AUTH.to_string())
        .or_insert_with(|| Value::String("none".to_string()));

    (StatusCode::CREATED, Json(Value::Object(values))).into_response()
}

async fn authorize(State(state): State<AuthState>, RawQuery(raw): RawQuery) -> Response {
    let provider = provider(&state).clone();
    let query = query_map(&raw);
    let request = noted_auth::oauth::AuthorizationRequest::new(
        query
            .get("response_type")
            .map(|value| noted_auth::types::AuthorizationResponseType::submitted(value)),
        query
            .get("client_id")
            .map(|value| noted_auth::types::ClientId::new(value.clone())),
        query
            .get("redirect_uri")
            .map(|value| noted_auth::types::SubmittedRedirectUri::submitted(value.clone())),
        query
            .get("scope")
            .map(|value| noted_auth::types::RequestedScope::submitted(value.clone())),
        query
            .get("state")
            .map(|value| noted_auth::types::ClientState::submitted(value.clone())),
        query
            .get("code_challenge")
            .map(|value| noted_auth::types::CodeChallenge::submitted(value.clone())),
        query
            .get("code_challenge_method")
            .map(|value| noted_auth::types::CodeChallengeMethod::submitted(value)),
    );
    let protocol = provider.protocol.clone();
    let outcome = match run_blocking(move || protocol.begin_authorization(request)).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::error!(%error, "oauth authorization task failed");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    presentation::begin_authorization(provider.public_url(), outcome)
}

async fn login_get(State(state): State<AuthState>, RawQuery(raw): RawQuery) -> Response {
    let p = provider(&state);
    let q = query_map(&raw);
    let txn = AuthorizationTransactionId::submitted(q.get("txn").cloned().unwrap_or_default());
    let protocol = p.protocol.clone();
    let status = match run_blocking(move || protocol.authorization_status(&txn)).await {
        Ok(status) => status,
        Err(error) => {
            tracing::error!(%error, "oauth login status task failed");
            noted_auth::oauth::AuthorizationStatus::Unknown
        }
    };
    match status {
        noted_auth::oauth::AuthorizationStatus::Pending => Html(presentation::login_page(
            q.get("txn").map_or("", String::as_str),
            None,
        ))
        .into_response(),
        noted_auth::oauth::AuthorizationStatus::Unknown => (
            StatusCode::BAD_REQUEST,
            Html(presentation::login_page("", Some("unknown login request"))),
        )
            .into_response(),
    }
}

async fn login_post(State(state): State<AuthState>, body: Bytes) -> Response {
    let p = provider(&state);
    let form = parse_form(&body);
    let txn = form.get("txn").cloned().unwrap_or_default();
    let name = LoginName::submitted(form.get("username").cloned().unwrap_or_default());
    let password = Password::new(form.get("password").cloned().unwrap_or_default());
    let transaction = AuthorizationTransactionId::submitted(txn.clone());
    let protocol = p.protocol.clone();
    let outcome = match run_blocking(move || {
        protocol.authorize_login(noted_auth::oauth::AuthorizationLogin::new(
            transaction,
            name,
            password,
        ))
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::error!(%error, "oauth login task failed");
            noted_auth::oauth::AuthorizationLoginOutcome::ServerError
        }
    };
    presentation::authorization_login(&txn, outcome)
}

async fn token(State(state): State<AuthState>, body: Bytes) -> Response {
    let provider = provider(&state);
    let form = parse_form(&body);
    let request = match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => noted_auth::oauth::TokenRequest::AuthorizationCode(
            noted_auth::oauth::AuthorizationCodeExchange::new(
                form.get("code")
                    .map(|value| noted_auth::types::AuthorizationCode::submitted(value.clone())),
                form.get("redirect_uri")
                    .map(|value| noted_auth::types::SubmittedRedirectUri::submitted(value.clone())),
                form.get("client_id")
                    .map(|value| noted_auth::types::ClientId::new(value.clone())),
                form.get("code_verifier")
                    .map(|value| noted_auth::types::CodeVerifier::submitted(value.clone())),
            ),
        ),
        Some("refresh_token") => noted_auth::oauth::TokenRequest::RefreshToken(
            noted_auth::oauth::RefreshTokenExchange::new(
                form.get("refresh_token")
                    .map(|value| noted_auth::types::RefreshToken::new(value.clone())),
                form.get("client_id")
                    .map(|value| noted_auth::types::ClientId::new(value.clone())),
                form.get("scope")
                    .map(|value| noted_auth::types::RequestedScope::submitted(value.clone())),
            ),
        ),
        _ => noted_auth::oauth::TokenRequest::Unsupported,
    };
    let protocol = provider.protocol.clone();
    let outcome = match run_blocking(move || protocol.exchange_token(request)).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::error!(%error, "oauth token task failed");
            noted_auth::oauth::TokenOutcome::ServerError
        }
    };
    presentation::token(outcome)
}

fn oauth_error(status: StatusCode, message: &str) -> Response {
    let (error, desc) = match message.split_once(':') {
        Some((e, d)) => (e.to_string(), d.trim().to_string()),
        None => (message.to_string(), String::new()),
    };
    (
        status,
        Json(json!({"error": error, "error_description": desc})),
    )
        .into_response()
}
