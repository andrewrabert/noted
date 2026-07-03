use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use oxide_auth::endpoint::{AccessTokenFlow, AuthorizationFlow, OwnerConsent, RefreshFlow};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::frontends::simple::extensions::{AddonList, Extended, Pkce};
use oxide_auth::frontends::simple::request::{
    Body as OxBody, Request as OxRequest, Response as OxResponse, Status as OxStatus,
};
use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::generator::RandomGenerator;
use oxide_auth::primitives::registrar::{Client, ClientMap, RegisteredUrl};
use oxide_auth::primitives::scope::Scope;
use serde_json::{json, Value};

use crate::error::Result;
use crate::http::AppState;
use crate::password::{verify_dummy, verify_password};
use crate::types::{Ttl, UnixEpochSeconds};
use crate::util::random_token;

#[cfg(unix)]
pub mod admin;
mod db;
mod issuer;
pub mod macaroon;
pub mod service;
pub mod types;
pub use db::{CredentialKind, CredentialRecord, CredentialStatus, Db, KeyRecord, UserRecord};
pub use issuer::DbIssuer;
pub use service::AuthService;
pub use types::Owner;

const TXN_TTL: Ttl = Ttl::from_secs(10 * 60);
const MAX_TXNS: usize = 1024;
const DEFAULT_SCOPE: &str = "notes";

struct Txn {
    query: HashMap<String, String>,
    expires_at: UnixEpochSeconds,
}

type LoginKey = (String, String);
type KeyedGovernor = governor::RateLimiter<
    LoginKey,
    governor::state::keyed::DefaultKeyedStateStore<LoginKey>,
    governor::clock::DefaultClock,
>;

struct RateLimiter {
    inner: KeyedGovernor,
}

impl RateLimiter {
    fn new() -> RateLimiter {
        let quota = governor::Quota::with_period(std::time::Duration::from_secs(60))
            .expect("non-zero period")
            .allow_burst(std::num::NonZeroU32::new(5).expect("non-zero burst"));
        RateLimiter {
            inner: governor::RateLimiter::keyed(quota),
        }
    }

    fn check(&self, key: &LoginKey) -> bool {
        self.inner.check_key(key).is_ok()
    }
}

struct Oxide {
    registrar: ClientMap,
    authorizer: AuthMap<RandomGenerator>,
    issuer: DbIssuer,
}

impl Oxide {
    fn new(auth: Arc<AuthService>) -> Oxide {
        Oxide {
            registrar: ClientMap::new(),
            authorizer: AuthMap::new(RandomGenerator::new(16)),
            issuer: DbIssuer::new(auth),
        }
    }
}

fn addons() -> AddonList {
    let mut list = AddonList::new();
    list.push_authorization(Pkce::required());
    list.push_access_token(Pkce::required());
    list
}

pub struct OAuthProvider {
    public_url: String,
    auth: Arc<AuthService>,
    oxide: Mutex<Oxide>,
    txns: Mutex<HashMap<String, Txn>>,
    limiter: RateLimiter,
}

impl OAuthProvider {
    pub fn new(public_url: &str, auth: Arc<AuthService>) -> Result<OAuthProvider> {
        let public_url = public_url.trim_end_matches('/').to_string();
        let mut oxide = Oxide::new(auth.clone());
        for (cid, data) in auth.db().all_clients()? {
            if let Ok(v) = serde_json::from_str::<Value>(&data) {
                register_oxide_client(&mut oxide.registrar, &cid, &v);
            }
        }
        Ok(OAuthProvider {
            public_url,
            auth,
            oxide: Mutex::new(oxide),
            txns: Mutex::new(HashMap::new()),
            limiter: RateLimiter::new(),
        })
    }

    pub fn auth(&self) -> &Arc<AuthService> {
        &self.auth
    }

    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    fn issuer(&self) -> &str {
        &self.public_url
    }

    #[doc(hidden)]
    pub fn has_client(&self, client_id: &str) -> bool {
        self.auth
            .db()
            .all_clients()
            .map(|clients| clients.iter().any(|(cid, _)| cid == client_id))
            .unwrap_or(false)
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

    fn pop_txn(&self, txn: &str) -> Option<HashMap<String, String>> {
        let now = UnixEpochSeconds::now().ok()?;
        let mut txns = self.txns.lock().unwrap();
        let entry = txns.get(txn)?;
        if entry.expires_at < now {
            txns.remove(txn);
            return None;
        }
        Some(entry.query.clone())
    }

    fn park_txn(&self, txn: String, query: HashMap<String, String>) -> Result<()> {
        let now = UnixEpochSeconds::now()?;
        let mut txns = self.txns.lock().unwrap();
        txns.retain(|_, t| t.expires_at >= now);
        if txns.len() >= MAX_TXNS {
            return Err(crate::error::unavailable(
                "too many pending authorizations; try again later",
            ));
        }
        txns.insert(
            txn,
            Txn {
                query,
                expires_at: now + TXN_TTL,
            },
        );
        Ok(())
    }
}

fn register_oxide_client(registrar: &mut ClientMap, client_id: &str, data: &Value) {
    let uris: Vec<RegisteredUrl> = data
        .get("redirect_uris")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|u| u.as_str())
                .filter_map(|u| url::Url::parse(u).ok())
                .map(RegisteredUrl::from)
                .collect()
        })
        .unwrap_or_default();
    let mut it = uris.into_iter();
    let Some(primary) = it.next() else {
        return;
    };
    let scope = Scope::from_str(DEFAULT_SCOPE).expect("valid default scope");
    let client =
        Client::public(client_id, primary, scope).with_additional_redirect_uris(it.collect());
    registrar.register_client(client);
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
    scopes_supported: [&'static str; 0],
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
        scopes_supported: [],
    }
}

fn protected_resource_metadata(p: &OAuthProvider) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: p.resource_url(),
        authorization_servers: [p.issuer().to_string()],
        bearer_methods_supported: ["header"],
    }
}

pub fn mount_routes(
    router: Router<AppState>,
    _oauth: std::sync::Arc<OAuthProvider>,
) -> Router<AppState> {
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

fn provider(state: &AppState) -> &OAuthProvider {
    state.oauth().expect("oauth routes require a provider")
}

async fn meta_as(State(state): State<AppState>) -> Response {
    Json(authorization_server_metadata(provider(&state))).into_response()
}

async fn meta_pr(State(state): State<AppState>) -> Response {
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

fn ox_to_axum(r: OxResponse) -> Response {
    let status = match r.status {
        OxStatus::Ok => StatusCode::OK,
        OxStatus::Redirect => StatusCode::SEE_OTHER,
        OxStatus::BadRequest => StatusCode::BAD_REQUEST,
        OxStatus::Unauthorized => StatusCode::UNAUTHORIZED,
    };
    let mut resp = status.into_response();
    if let Some(url) = r.location {
        if let Ok(v) = header::HeaderValue::from_str(url.as_str()) {
            resp.headers_mut().insert(header::LOCATION, v);
        }
    }
    if let Some(wa) = r.www_authenticate {
        if let Ok(v) = header::HeaderValue::from_str(&wa) {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
    }
    match r.body {
        Some(OxBody::Json(s)) => {
            (status, [(header::CONTENT_TYPE, "application/json")], s).into_response()
        }
        Some(OxBody::Text(s)) => {
            let mut with_body = (status, s).into_response();
            *with_body.headers_mut() = resp.headers().clone();
            with_body
        }
        None => resp,
    }
}

async fn register(State(state): State<AppState>, body: Bytes) -> Response {
    let p = provider(&state);
    let mut info: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata"),
    };
    let redirect_uris = info.get("redirect_uris").and_then(|v| v.as_array());
    if redirect_uris.map(|a| a.is_empty()).unwrap_or(true) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    let client_id = random_token(24);
    if let Value::Object(map) = &mut info {
        map.insert("client_id".into(), json!(client_id));
        let issued_at = UnixEpochSeconds::now().map(|n| n.as_secs()).unwrap_or(0);
        map.insert("client_id_issued_at".into(), json!(issued_at));
        map.entry("token_endpoint_auth_method")
            .or_insert(json!("none"));
    }
    if let Err(e) = p.auth.db().put_client(&client_id, &info.to_string()) {
        tracing::error!(error = %e, "oauth client persistence failed");
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    register_oxide_client(&mut p.oxide.lock().unwrap().registrar, &client_id, &info);
    (StatusCode::CREATED, Json(info)).into_response()
}

async fn authorize(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let p = provider(&state);
    let query = query_map(&raw);
    let txn = random_token(24);
    if p.park_txn(txn.clone(), query.clone()).is_err() {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let login_url = match url::Url::parse(&format!("{}/login?txn={}", p.issuer(), txn)) {
        Ok(u) => u,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let req = OxRequest {
        query,
        urlbody: HashMap::new(),
        auth: None,
    };
    let mut oxide = p.oxide.lock().unwrap();
    let Oxide {
        registrar,
        authorizer,
        ..
    } = &mut *oxide;
    let mut solicitor = FnSolicitor(|_: &mut OxRequest, _: oxide_auth::endpoint::Solicitation| {
        OwnerConsent::InProgress(OxResponse {
            status: OxStatus::Redirect,
            location: Some(login_url.clone()),
            ..Default::default()
        })
    });
    let generic = Generic {
        registrar: &*registrar,
        authorizer,
        issuer: Vacant,
        solicitor: &mut solicitor,
        scopes: Vacant,
        response: Vacant,
    };
    let mut flow = match AuthorizationFlow::prepare(Extended::extend_with(generic, addons())) {
        Ok(f) => f,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    match flow.execute(req) {
        Ok(resp) => ox_to_axum(resp),
        Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

async fn login_get(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let p = provider(&state);
    let q = query_map(&raw);
    let txn = q.get("txn").cloned().unwrap_or_default();
    if p.pop_txn(&txn).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Html(login_page("", Some("expired or invalid"))),
        )
            .into_response();
    }
    Html(login_page(&txn, None)).into_response()
}

async fn login_post(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let p = provider(&state);
    let form = parse_form(&body);
    let txn = form.get("txn").cloned().unwrap_or_default();
    let username = form.get("username").cloned().unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();
    let Some(query) = p.pop_txn(&txn) else {
        return (
            StatusCode::BAD_REQUEST,
            Html(login_page("", Some("expired or invalid"))),
        )
            .into_response();
    };
    let ip = client_ip(&headers);
    let key = (username.clone(), ip);
    if !p.limiter.check(&key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(login_page(&txn, Some("too many attempts, try later"))),
        )
            .into_response();
    }
    let record = p.auth.login_user(&username).ok().flatten();
    let pw = password.clone();
    let ok = tokio::task::spawn_blocking(move || match record {
        Some(user) => verify_password(&pw, user.password_hash.as_str()),
        None => {
            verify_dummy();
            false
        }
    })
    .await
    .unwrap_or(false);
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Html(login_page(&txn, Some("invalid credentials"))),
        )
            .into_response();
    }
    p.txns.lock().unwrap().remove(&txn);
    let req = OxRequest {
        query,
        urlbody: HashMap::new(),
        auth: None,
    };
    let mut oxide = p.oxide.lock().unwrap();
    let Oxide {
        registrar,
        authorizer,
        ..
    } = &mut *oxide;
    let mut solicitor = FnSolicitor(|_: &mut OxRequest, _: oxide_auth::endpoint::Solicitation| {
        OwnerConsent::Authorized(username.clone())
    });
    let generic = Generic {
        registrar: &*registrar,
        authorizer,
        issuer: Vacant,
        solicitor: &mut solicitor,
        scopes: Vacant,
        response: Vacant,
    };
    let mut flow = match AuthorizationFlow::prepare(Extended::extend_with(generic, addons())) {
        Ok(f) => f,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    match flow.execute(req) {
        Ok(resp) => ox_to_axum(resp),
        Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "?".to_string())
}

async fn token(State(state): State<AppState>, body: Bytes) -> Response {
    let p = provider(&state);
    let form = parse_form(&body);
    let req = OxRequest {
        query: HashMap::new(),
        urlbody: form.clone(),
        auth: None,
    };
    let mut oxide = p.oxide.lock().unwrap();
    match form.get("grant_type").map(|s| s.as_str()) {
        Some("authorization_code") => {
            let result = {
                let Oxide {
                    registrar,
                    authorizer,
                    issuer,
                } = &mut *oxide;
                let generic = Generic {
                    registrar: &*registrar,
                    authorizer,
                    issuer,
                    solicitor: Vacant,
                    scopes: Vacant,
                    response: Vacant,
                };
                match AccessTokenFlow::prepare(Extended::extend_with(generic, addons())) {
                    Ok(mut flow) => flow.execute(req),
                    Err(_) => {
                        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
                    }
                }
            };
            match result {
                Ok(resp) => ox_to_axum(resp),
                Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
            }
        }
        Some("refresh_token") => {
            let result = {
                let Oxide {
                    registrar, issuer, ..
                } = &mut *oxide;
                let generic = Generic {
                    registrar: &*registrar,
                    authorizer: Vacant,
                    issuer,
                    solicitor: Vacant,
                    scopes: Vacant,
                    response: Vacant,
                };
                match RefreshFlow::prepare(generic) {
                    Ok(mut flow) => flow.execute(req),
                    Err(_) => {
                        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
                    }
                }
            };
            match result {
                Ok(resp) => ox_to_axum(resp),
                Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
            }
        }
        _ => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
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

fn login_page(txn: &str, error: Option<&str>) -> String {
    let input_style = "width:100%;padding:.5rem;box-sizing:border-box";
    maud::html! {
        (maud::DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                title { "noted sign in" }
            }
            body style="font-family:sans-serif;max-width:22rem;margin:4rem auto" {
                h1 { "noted" }
                @if let Some(e) = error {
                    p style="color:#c00" { (e) }
                }
                form method="post" action="/login" {
                    input type="hidden" name="txn" value=(txn);
                    p { input name="username" placeholder="username" autofocus style=(input_style); }
                    p { input name="password" type="password" placeholder="password" style=(input_style); }
                    p { button type="submit" style="padding:.5rem 1rem" { "Sign in" } }
                }
            }
        }
    }
    .into_string()
}
