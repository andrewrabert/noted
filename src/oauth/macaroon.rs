use std::sync::OnceLock;

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use macaroon::{ByteString, Caveat, Format, Macaroon, MacaroonKey, Verifier};
use rand::RngCore;
use serde_json::{json, Value};

use super::service::{AuthService, PREFIX_MAC};
use super::KeyRecord;
use crate::error::{rejected, Result};
use crate::http::AppState;
use crate::scope::{RuleSpec, TokenScope};
use crate::types::{Ttl, UnixEpochSeconds};
use crate::util::random_token;

const CAV_POLICY: &str = "policy = ";
const CAV_BEFORE: &str = "before = ";
const CAV_ID: &str = "id = ";
const CAV_SESSION: &str = "session = ";
const CAV_EPOCH: &str = "epoch = ";

fn init() {
    static I: OnceLock<()> = OnceLock::new();
    I.get_or_init(|| {
        let _ = macaroon::initialize();
    });
}

fn bs(s: &str) -> ByteString {
    ByteString(s.as_bytes().to_vec())
}

fn strip_wire(token: &str) -> &str {
    token.strip_prefix(PREFIX_MAC).unwrap_or(token)
}

pub fn attenuate(
    root: &str,
    policy: Option<&[RuleSpec]>,
    ttl: Ttl,
    id: &str,
    session: Option<&str>,
) -> Result<(String, u64)> {
    init();
    let mut m = Macaroon::deserialize(strip_wire(root))
        .map_err(|e| rejected(format!("invalid root macaroon: {e}")))?;
    if let Some(specs) = policy {
        let encoded =
            serde_json::to_string(specs).map_err(|e| rejected(format!("encode policy: {e}")))?;
        m.add_first_party_caveat(bs(&format!("{CAV_POLICY}{encoded}")));
    }
    let expires = UnixEpochSeconds::now()? + ttl;
    m.add_first_party_caveat(bs(&format!("{CAV_BEFORE}{expires}")));
    m.add_first_party_caveat(bs(&format!("{CAV_ID}{id}")));
    if let Some(s) = session {
        m.add_first_party_caveat(bs(&format!("{CAV_SESSION}{s}")));
    }
    let token = m
        .serialize(Format::V2)
        .map_err(|e| rejected(format!("serialize macaroon: {e}")))?;
    Ok((format!("{PREFIX_MAC}{token}"), expires.as_secs()))
}

pub fn mint_child(
    root: &str,
    policy: Option<&[RuleSpec]>,
    ttl: Ttl,
    session: Option<&str>,
) -> Result<(String, String, u64)> {
    let id = random_token(16);
    let (token, expires_at) = attenuate(root, policy, ttl, &id, session)?;
    Ok((token, id, expires_at))
}

pub fn username_of(token: &str) -> Option<String> {
    init();
    let m = Macaroon::deserialize(strip_wire(token)).ok()?;
    let ident = String::from_utf8(m.identifier().0).ok()?;
    ident.parse::<super::Owner>().is_ok().then_some(ident)
}

pub fn verify(auth: &AuthService, token: &str) -> Option<TokenScope> {
    init();
    let m = Macaroon::deserialize(strip_wire(token)).ok()?;
    let ident = String::from_utf8(m.identifier().0).ok()?;
    let key_rec = auth.db().mac_root(&ident).ok().flatten()?;

    let key = MacaroonKey::generate(&key_rec.secret);
    let mut v = Verifier::default();
    v.satisfy_general(|_| true);
    v.verify(&m, &key, Vec::new()).ok()?;

    let mut effective = auth.resolve_scope(&ident).ok().flatten()?;
    let now = UnixEpochSeconds::now().ok()?;
    for caveat in m.first_party_caveats() {
        let Caveat::FirstParty(fp) = caveat else {
            return None;
        };
        let pred = String::from_utf8(fp.predicate().0).ok()?;
        if let Some(ts) = pred.strip_prefix(CAV_BEFORE) {
            if now >= ts.parse::<UnixEpochSeconds>().ok()? {
                return None;
            }
        } else if let Some(e) = pred.strip_prefix(CAV_EPOCH) {
            if e.trim().parse::<u64>().ok()? < key_rec.min_epoch {
                return None;
            }
        } else if let Some(id) = pred.strip_prefix(CAV_ID) {
            if auth.db().is_revoked(id.trim()).unwrap_or(true) {
                return None;
            }
        } else if let Some(s) = pred.strip_prefix(CAV_SESSION) {
            if auth.db().is_revoked(s.trim()).unwrap_or(true) {
                return None;
            }
        } else {
            let encoded = pred.strip_prefix(CAV_POLICY)?;
            let specs: Vec<RuleSpec> = serde_json::from_str(encoded).ok()?;
            let scope = crate::scope::compile_rules(&specs).ok()?;
            effective = effective.intersect(&scope);
        }
    }
    Some(effective)
}

pub fn mount_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/macaroon/root", post(root))
        .route("/macaroon/revoke", post(revoke))
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_string)
}

fn caller_owner(auth: &AuthService, headers: &HeaderMap) -> Option<String> {
    let token = bearer(headers)?;
    auth.resolve_bearer(&token)
        .ok()
        .flatten()
        .map(|(owner, _)| owner.to_string())
}

fn detail(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "detail": msg }))).into_response()
}

async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(auth) = state.auth() else {
        return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
    };
    let location = state
        .oauth()
        .map(|p| p.public_url().to_string())
        .unwrap_or_else(|| "noted".to_string());
    let Some(owner) = caller_owner(auth, &headers) else {
        return detail(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let key_rec = match auth.db().mac_root(&owner) {
        Ok(Some(r)) => r,
        Ok(None) => {
            let mut secret = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            let rec = KeyRecord {
                secret,
                min_epoch: 0,
            };
            if auth.db().put_mac_root(&owner, &rec).is_err() {
                return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
            }
            rec
        }
        Err(_) => return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    };
    init();
    let key = MacaroonKey::generate(&key_rec.secret);
    let ident = ByteString(owner.clone().into_bytes());
    let Ok(mut m) = Macaroon::create(Some(location), &key, ident) else {
        return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
    };
    let Ok(expires) = UnixEpochSeconds::now().map(|n| n + auth.default_ttl()) else {
        return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
    };
    m.add_first_party_caveat(bs(&format!("{CAV_EPOCH}{}", key_rec.min_epoch)));
    m.add_first_party_caveat(bs(&format!("{CAV_BEFORE}{expires}")));
    match m.serialize(Format::V2) {
        Ok(token) => Json(json!({
            "macaroon": format!("{PREFIX_MAC}{token}"),
            "expires_at": expires
        }))
        .into_response(),
        Err(_) => detail(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
}

async fn revoke(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(auth) = state.auth() else {
        return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
    };
    let Some(owner) = caller_owner(auth, &headers) else {
        return detail(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Ok(deadline) = UnixEpochSeconds::now().map(|n| n + auth.default_ttl()) else {
        return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
    };
    if v.get("all").and_then(Value::as_bool) == Some(true) {
        let _ = auth.db().bump_root_epoch(&owner);
    } else if let Some(id) = v.get("id").and_then(Value::as_str) {
        let _ = auth.db().revoke_id(id, deadline);
    } else if let Some(s) = v.get("session").and_then(Value::as_str) {
        let _ = auth.db().revoke_id(s, deadline);
    } else {
        return detail(StatusCode::BAD_REQUEST, "provide id, session, or all");
    }
    Json(json!({ "ok": true })).into_response()
}
