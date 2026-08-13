use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::{Value, json};

use crate::AuthState;
use crate::authority::{Denial, Mint, Minted, Minter, Revoke, Verified};
use crate::credential::MacaroonId;
use crate::types::SessionId;
use noted::PolicyFragment;
use noted::types::Ttl;

pub(crate) fn mount_routes(router: Router<AuthState>) -> Router<AuthState> {
    router
        .route("/macaroon/mint", post(mint))
        .route("/macaroon/revoke", post(revoke))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn detail(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "detail": message }))).into_response()
}

fn denied(denial: &Denial) -> Response {
    match denial {
        Denial::Malformed(m) => detail(StatusCode::BAD_REQUEST, m),
        Denial::Unauthorized(_) => detail(StatusCode::UNAUTHORIZED, "unauthorized"),
        Denial::Forbidden(m) => detail(StatusCode::FORBIDDEN, m),
    }
}

fn caller(state: &AuthState, headers: &HeaderMap) -> std::result::Result<Verified, Box<Response>> {
    state
        .verifier()
        .verify(bearer(headers))
        .map_err(|denial| Box::new(denied(&denial)))
}

fn minter(state: &AuthState) -> std::result::Result<&dyn Minter, Box<Response>> {
    match state.minter() {
        Some(minter) => Ok(minter.as_ref()),
        None => Err(Box::new(StatusCode::NOT_FOUND.into_response())),
    }
}

async fn mint(State(state): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    let minter = match minter(&state) {
        Ok(minter) => minter,
        Err(response) => return *response,
    };
    let caller = match caller(&state, &headers) {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    let asked: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let policy = match asked.get("policy") {
        Some(value) => match serde_json::from_value::<PolicyFragment>(value.clone()) {
            Ok(policy) => policy,
            Err(e) => return detail(StatusCode::BAD_REQUEST, &e.to_string()),
        },
        None => PolicyFragment::default(),
    };
    let ask = Mint {
        policy,
        ttl: asked
            .get("ttl")
            .and_then(Value::as_u64)
            .map(Ttl::from_secs)
            .unwrap_or_else(|| crate::service::DEFAULT_CREDENTIAL_TTL),
        session: asked
            .get("session")
            .and_then(Value::as_str)
            .map(SessionId::new),
        label: None,
    };
    match minter.mint(&caller, &ask) {
        Ok(Minted {
            macaroon,
            token_id,
            fingerprint,
            expires_at,
        }) => Json(json!({
            "macaroon": macaroon.expose(),
            "token_id": token_id,
            "fingerprint": fingerprint,
            "expires_at": expires_at,
        }))
        .into_response(),
        Err(_) => detail(StatusCode::UNAUTHORIZED, "unauthorized"),
    }
}

async fn revoke(State(state): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    let minter = match minter(&state) {
        Ok(minter) => minter,
        Err(response) => return *response,
    };
    let caller = match caller(&state, &headers) {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    let asked: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let ask = if asked.get("all").and_then(Value::as_bool) == Some(true) {
        Revoke::All
    } else if let Some(id) = asked.get("id").and_then(Value::as_str) {
        Revoke::Token(MacaroonId::new(id))
    } else if let Some(session) = asked.get("session").and_then(Value::as_str) {
        Revoke::Session(SessionId::new(session))
    } else {
        return detail(StatusCode::BAD_REQUEST, "provide id, session, or all");
    };
    match minter.revoke(&caller, &ask) {
        Ok(n) => Json(json!({ "revoked": n })).into_response(),
        Err(e) => detail(StatusCode::BAD_REQUEST, &e.message()),
    }
}
