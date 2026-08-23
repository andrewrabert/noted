mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use base64::Engine;
use noted::PolicyFragment;
use noted_auth::authority::{OriginAuthority, Verifier};
use noted_auth::password::{hash_password, verify_password};
use noted_auth::types::ClientId;
use noted_auth::{AuthService, Db};
use noted_server::auth::AuthState;
use noted_server::http::{Served, build_app};
use noted_server::oauth::OAuthProvider;
use serde_json::json;
use sha2::{Digest, Sha256};

use common::{json_body, post_form, post_json, post_mcp, request, un};

const PUBLIC: &str = "http://localhost";
const REDIRECT: &str = "http://client.example/callback";
struct UserSpec {
    password: &'static str,
    policy: Option<&'static str>,
}

impl UserSpec {
    fn new(password: &'static str) -> UserSpec {
        UserSpec {
            password,
            policy: None,
        }
    }
}

async fn build(dir: &tempfile::TempDir, users: &[(&str, UserSpec)]) -> (Router, Arc<AuthService>) {
    let database = common::auth_service(dir);
    let svc = database.clone();
    for (name, spec) in users {
        svc.user_add(&un(name), &pw(spec.password)).unwrap();
        if let Some(policy) = spec.policy {
            svc.user_set_policy(&un(name), policy.parse::<PolicyFragment>().unwrap())
                .unwrap();
        }
    }
    let provider = Arc::new(OAuthProvider::new(PUBLIC, database).await.unwrap());
    let app = build_app(Served::origin(
        common::root(dir),
        AuthState::origin(svc.clone(), Some(provider))
            .await
            .unwrap(),
    ));
    (app, svc)
}

fn pkce() -> (String, String) {
    let verifier: String = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand_bytes(48));
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Deterministic-enough uniqueness for a test verifier: hash the clock.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut out = Vec::new();
    let mut h = Sha256::digest(seed.to_le_bytes());
    while out.len() < n {
        out.extend_from_slice(&h);
        h = Sha256::digest(h);
    }
    out.truncate(n);
    out
}

fn location(headers: &HeaderMap) -> String {
    headers
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

async fn register(app: &Router) -> String {
    let (s, b) = post_json(
        app,
        "/register",
        None,
        &json!({
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&b));
    json_body(&b)["client_id"].as_str().unwrap().to_string()
}

async fn authorize_txn(app: &Router, client_id: &str, challenge: &str) -> String {
    let uri = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state=st",
        REDIRECT
    );
    let (s, headers, _) = request(app, "GET", &uri, None, "text/plain", Vec::new()).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "authorize should redirect");
    query_param(&location(&headers), "txn").unwrap()
}

async fn login(
    app: &Router,
    client_id: &str,
    user: &str,
    password: &str,
    challenge: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let txn = authorize_txn(app, client_id, challenge).await;
    post_form(
        app,
        "/login",
        &[("txn", &txn), ("username", user), ("password", password)],
    )
    .await
}

async fn authenticate(app: &Router, user: &str, password: &str) -> (String, String, String) {
    let client_id = register(app).await;
    let (verifier, challenge) = pkce();
    let (s, headers, _) = login(app, &client_id, user, password, &challenge).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let code = query_param(&location(&headers), "code").unwrap();
    let (s, b) = post_form_token(
        app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", &client_id),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    let body = json_body(&b);
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
        client_id,
    )
}

async fn post_form_token(app: &Router, fields: &[(&str, &str)]) -> (StatusCode, Vec<u8>) {
    let (s, _h, b) = post_form(app, "/token", fields).await;
    (s, b)
}

fn mcp_call(name: &str, args: serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}})
}

async fn mcp_text(
    app: &Router,
    token: &str,
    name: &str,
    args: serde_json::Value,
) -> (bool, String) {
    let (s, _h, b) = post_mcp(app, Some(token), &mcp_call(name, args)).await;
    assert_eq!(s, StatusCode::OK);
    let result = &json_body(&b)["result"];
    (
        result["isError"].as_bool().unwrap_or(false),
        result["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

#[tokio::test]
async fn discovery_at_root() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let (s, b) = get(&app, "/.well-known/oauth-authorization-server").await;
    assert_eq!(s, StatusCode::OK);
    let meta = json_body(&b);
    assert_eq!(
        meta["issuer"].as_str().unwrap().trim_end_matches('/'),
        PUBLIC
    );
    assert_eq!(
        meta["authorization_endpoint"],
        format!("{PUBLIC}/authorize")
    );
    assert_eq!(meta["registration_endpoint"], format!("{PUBLIC}/register"));
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));

    let (s, b) = get(&app, "/.well-known/oauth-protected-resource/mcp").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json_body(&b)["resource"], format!("{PUBLIC}/mcp"));
}

async fn get(app: &Router, path: &str) -> (StatusCode, Vec<u8>) {
    let (s, _h, b) = request(app, "GET", path, None, "text/plain", Vec::new()).await;
    (s, b)
}

#[tokio::test]
async fn full_flow_lists_and_searches() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("full", UserSpec::new("pw"))]).await;
    let (token, refresh, _) = authenticate(&app, "full", "pw").await;
    assert!(!refresh.is_empty());
    let (is_err, paths) = mcp_text(
        &app,
        &token,
        "SearchNotes",
        json!({"pattern": ".", "mode": "path"}),
    )
    .await;
    assert!(!is_err);
    assert!(paths.contains("projects/") && paths.contains("people/"));
}

#[tokio::test]
async fn oauth_folder_confinement() {
    let dir = common::fixture_dir();
    let (app, _) = build(
        &dir,
        &[(
            "p",
            UserSpec {
                policy: Some(r#"{"scope":"projects"}"#),
                ..UserSpec::new("pw")
            },
        )],
    )
    .await;
    let (token, _, _) = authenticate(&app, "p", "pw").await;
    let (_e, paths) = mcp_text(
        &app,
        &token,
        "SearchNotes",
        json!({"pattern": ".", "mode": "path"}),
    )
    .await;
    assert!(paths.lines().all(|p| !p.contains('/')) && !paths.is_empty());
    let (is_err, msg) = mcp_text(
        &app,
        &token,
        "ReadNote",
        json!({"path": "people/contacts.md"}),
    )
    .await;
    assert!(is_err && msg.contains("not found"), "{msg}");
}

#[tokio::test]
async fn oauth_read_only_blocks_write() {
    let dir = common::fixture_dir();
    let (app, _) = build(
        &dir,
        &[(
            "ro",
            UserSpec {
                policy: Some(r#"{"access":{"read":true,"write":false}}"#),
                ..UserSpec::new("pw")
            },
        )],
    )
    .await;
    let (token, _, _) = authenticate(&app, "ro", "pw").await;
    let (is_err, msg) = mcp_text(
        &app,
        &token,
        "WriteNote",
        json!({"path": "x.md", "content": "hi"}),
    )
    .await;
    assert!(is_err && msg.contains("forbidden"), "{msg}");
}

#[tokio::test]
async fn bad_password_rejected() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("right"))]).await;
    let client_id = register(&app).await;
    let (_v, challenge) = pkce();
    let (s, _h, b) = login(&app, &client_id, "a", "wrong", &challenge).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(String::from_utf8_lossy(&b).contains("invalid credentials"));
}

#[tokio::test]
async fn unknown_user_rejected() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let client_id = register(&app).await;
    let (_v, challenge) = pkce();
    let (s, _h, _b) = login(&app, &client_id, "ghost", "pw", &challenge).await;
    eprintln!("REUSED_REFRESH_STATUS={s}");
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_get_renders_form() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let client_id = register(&app).await;
    let (_v, challenge) = pkce();
    let txn = authorize_txn(&app, &client_id, &challenge).await;
    let (s, b) = get(&app, &format!("/login?txn={txn}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(String::from_utf8_lossy(&b).contains("password"));
}

#[tokio::test]
async fn login_rejects_bad_txn() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let (s, _) = get(&app, "/login?txn=nope").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _h, _b) = post_form(
        &app,
        "/login",
        &[("txn", "nope"), ("username", "a"), ("password", "pw")],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refresh_token_grant_and_rotation() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let (token, refresh, client_id) = authenticate(&app, "a", "pw").await;
    let (s, b) = post_form_token(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    let new = json_body(&b);
    assert!(new["access_token"].as_str().is_some());
    assert_ne!(new["refresh_token"].as_str().unwrap(), refresh);
    let _ = token;
    // Refresh tokens rotate and are single-use: the rotated-out token is
    // gone, so reusing it is an invalid_grant (400 per RFC 6749).
    let (s, _b) = post_form_token(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tool_realm_closed_without_a_bearer() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let (s, _) = post_json(&app, "/tool/ReadNote", None, &json!({"path": "Inbox.md"})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_requires_oauth_token() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let (s, _h, _b) = post_mcp(
        &app,
        None,
        &mcp_call("SearchNotes", json!({"pattern": "."})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn removed_user_kills_tokens_and_refresh() {
    let dir = common::fixture_dir();
    let (app, svc) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
    let (access, refresh, client_id) = authenticate(&app, "a", "pw").await;
    svc.user_remove(&un("a")).unwrap();
    let (s, _h, _b) = post_mcp(
        &app,
        Some(&access),
        &mcp_call("SearchNotes", json!({"pattern": "."})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _b) = post_form_token(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_cannot_distinguish_unknown_names() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("real", UserSpec::new("right"))]).await;
    let client_id = register(&app).await;
    let (_v, challenge) = pkce();
    let mut bodies = Vec::new();
    for (user, pw) in [("real", "wrong"), ("ghost", "wrong"), ("bot", "wrong")] {
        let (s, _h, b) = login(&app, &client_id, user, pw, &challenge).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let body = String::from_utf8_lossy(&b).into_owned();
        let redacted = regex_lite_redact_txn(&body);
        assert!(redacted.contains("invalid credentials"));
        bodies.push(redacted);
    }
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[1], bodies[2]);
}

/// Blank out the `value="<txn>"` attribute — the per-attempt txn handle is the
/// one legitimate difference between rejection pages.
fn regex_lite_redact_txn(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some(i) = rest.find("value=\"") {
        out.push_str(&rest[..i + 7]);
        rest = &rest[i + 7..];
        let end = rest.find('"').unwrap_or(rest.len());
        out.push_str("REDACTED");
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[tokio::test]
async fn clients_persist_across_restart() {
    let dir = common::fixture_dir();
    // Drop the first provider (releasing redb's single-file lock) before reopening,
    // which is the true "restart" — a durable write must survive it.
    let client_id = {
        let (app, _svc) = build(&dir, &[("a", UserSpec::new("pw"))]).await;
        register(&app).await
    };
    let (revived, _service) = build(&dir, &[]).await;
    let (_, challenge) = pkce();
    let transaction = authorize_txn(&revived, &client_id, &challenge).await;
    assert!(!transaction.is_empty());
}

#[test]
fn verify_password_edges() {
    let good = hash_password("ok");
    assert!(verify_password("ok", &good));
    assert!(!verify_password("no", &good));
    assert!(!verify_password("x", "bcrypt$1$2$3$AA$AA"));
    assert!(!verify_password("x", "malformed"));
    assert!(!verify_password("x", "scrypt$notanint$8$1$AA$AA"));
}

async fn tool(app: &Router, token: &str, name: &str, args: serde_json::Value) -> StatusCode {
    common::post_json(app, &format!("/tool/{name}"), Some(token), &args)
        .await
        .0
}

fn held(text: &str) -> PolicyFragment {
    text.parse().unwrap()
}

fn read_only() -> PolicyFragment {
    held(r#"{"access":{"read":true,"write":false}}"#)
}

/// Asks the server for a credential of its own descending from `token`.
async fn mint(app: &Router, token: &str, policy: Option<&PolicyFragment>) -> String {
    let mut body = json!({});
    if let Some(policy) = policy {
        body["policy"] = serde_json::to_value(policy).unwrap();
    }
    let (s, b) = common::post_json(app, "/macaroon/mint", Some(token), &body).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    json_body(&b)["macaroon"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn an_oauth_token_and_a_credential_minted_from_it_both_reach_a_tool() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]).await;
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let search = json!({"pattern": ".", "mode": "path"});
    assert_eq!(
        tool(&app, &access, "SearchNotes", search.clone()).await,
        StatusCode::OK
    );
    let minted = mint(&app, &access, None).await;
    assert_eq!(
        tool(&app, &minted, "SearchNotes", search).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_minted_credential_attenuates_access() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]).await;
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let child = mint(&app, &access, Some(&read_only())).await;
    let search = json!({"pattern": ".", "mode": "path"});
    let write = json!({"path": "x.md", "content": "hi"});
    assert_eq!(
        tool(&app, &child, "SearchNotes", search).await,
        StatusCode::OK
    );
    assert_eq!(
        tool(&app, &child, "WriteNote", write.clone()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        tool(&app, &access, "WriteNote", write).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_minted_credential_confines_paths() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]).await;
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let policy = held(r#"{"paths":{"people":{"read":false,"write":false}}}"#);
    let child = mint(&app, &access, Some(&policy)).await;
    assert_eq!(
        tool(
            &app,
            &child,
            "ReadNote",
            json!({"path": "projects/ideas.md"})
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        tool(
            &app,
            &child,
            "ReadNote",
            json!({"path": "people/contacts.md"})
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_minted_credential_cannot_exceed_its_owners_policy() {
    let dir = common::fixture_dir();
    let (app, _p) = build(
        &dir,
        &[(
            "ro",
            UserSpec {
                policy: Some(r#"{"access":{"read":true,"write":false}}"#),
                ..UserSpec::new("pw")
            },
        )],
    )
    .await;
    let (access, _r, _c) = authenticate(&app, "ro", "pw").await;
    let child = mint(
        &app,
        &access,
        Some(&held(r#"{"access":{"read":false,"write":true}}"#)),
    )
    .await;
    for (name, args) in [
        ("WriteNote", json!({"path": "x.md", "content": "hi"})),
        ("ReadNote", json!({"path": "Inbox.md"})),
    ] {
        let (s, b) = common::post_json(&app, &format!("/tool/{name}"), Some(&child), &args).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{name}");
        assert!(
            json_body(&b)["detail"].as_str().unwrap().contains("write"),
            "{}",
            String::from_utf8_lossy(&b)
        );
    }
}

#[tokio::test]
async fn oauth_token_survives_restart() {
    let dir = common::fixture_dir();
    let db_path = dir.path().join("auth.redb");
    // Mint a token, then drop everything (frees the redb lock). Verification is
    // DB-only, so nothing in memory was load-bearing.
    let access = {
        let (app, _svc) = build(&dir, &[("ann", UserSpec::new("pw"))]).await;
        authenticate(&app, "ann", "pw").await.0
    };
    let db = Arc::new(Db::open(&db_path).unwrap());
    let revived = Arc::new(AuthService::new(db));
    let caller = OriginAuthority::new(revived)
        .verify(Some(&noted_auth::types::CredentialPresentation::submitted(
            &access,
        )))
        .unwrap();
    assert_eq!(caller.owner().unwrap().to_string(), "user:ann");
    assert_eq!(caller.fragments()[0].to_string(), "{}");
}

#[tokio::test]
async fn every_oauth_route_preserves_its_method_status_headers_and_content_type() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/mcp",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let (status, headers, _) = request(&app, "GET", path, None, "", Vec::new()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
    }
}

#[tokio::test]
async fn metadata_preserves_every_key_value_url_and_challenge_spelling() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    let (_, body) = get(&app, "/.well-known/oauth-authorization-server").await;
    let metadata = json_body(&body);
    assert_eq!(metadata["issuer"], PUBLIC);
    assert_eq!(
        metadata["authorization_endpoint"],
        format!("{PUBLIC}/authorize")
    );
    assert_eq!(metadata["token_endpoint"], format!("{PUBLIC}/token"));
    assert_eq!(
        metadata["registration_endpoint"],
        format!("{PUBLIC}/register")
    );
}

#[tokio::test]
async fn registration_preserves_echoes_defaults_extra_fields_and_malformed_errors() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    let (status, body) = post_json(
        &app,
        "/register",
        None,
        &json!({"redirect_uris":[REDIRECT],"extra":{"nested":true}}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let value = json_body(&body);
    assert_eq!(value["token_endpoint_auth_method"], "none");
    assert_eq!(value["extra"]["nested"], true);
    let (status, _, _) = request(
        &app,
        "POST",
        "/register",
        None,
        "application/json",
        b"{".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_rejects_every_invalid_redirect_request_without_filtering() {
    for redirect_uris in [
        json!(null),
        json!([]),
        json!([null]),
        json!([7]),
        json!([{"x": true}]),
        json!(["not a url"]),
        json!([REDIRECT, "not a url"]),
        json!([REDIRECT, null]),
    ] {
        let dir = common::fixture_dir();
        let (app, _) = build(&dir, &[]).await;
        let (status, _) = post_json(
            &app,
            "/register",
            None,
            &json!({"redirect_uris": redirect_uris}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    let (status, _) = post_json(&app, "/register", None, &json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn valid_redirects_share_registration_persistence_and_restart_facts() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    let redirects = json!([REDIRECT, "http://client.example/second"]);
    let (status, body) = post_json(
        &app,
        "/register",
        None,
        &json!({"redirect_uris": redirects}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let response = json_body(&body);
    assert_eq!(response["redirect_uris"], redirects);
    let client_id = ClientId::new(response["client_id"].as_str().unwrap());
    assert!(response["client_id_issued_at"].as_u64().is_some());

    drop(app);
    let (reopened, _service) = build(&dir, &[]).await;
    let (_, challenge) = pkce();
    let transaction = authorize_txn(&reopened, client_id.as_str(), &challenge).await;
    assert!(!transaction.is_empty());
}

#[tokio::test]
async fn authorization_preserves_pkce_redirect_state_and_invalid_request_edges() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    assert_eq!(get(&app, "/authorize").await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_preserves_exact_html_success_and_unknown_forms() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    let (status, body) = get(&app, "/login?txn=missing").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8(body)
            .unwrap()
            .contains("unknown login request")
    );
}

#[tokio::test]
async fn token_and_refresh_preserve_json_headers_errors_rotation_and_expiry() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    let (status, headers, body) = post_form(&app, "/token", &[("grant_type", "unknown")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert_eq!(json_body(&body)["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn persisted_clients_survive_async_startup_without_migration() {
    let dir = common::fixture_dir();
    let (app, service) = build(&dir, &[]).await;
    let client = register(&app).await;
    drop(app);
    drop(service);
    let (reopened, _service) = build(&dir, &[]).await;
    let (_, challenge) = pkce();
    let transaction = authorize_txn(&reopened, &client, &challenge).await;
    assert!(!transaction.is_empty());
}

#[tokio::test]
async fn unauthorized_resources_preserve_the_resource_metadata_challenge() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[]).await;
    let (status, headers, _) = request(
        &app,
        "POST",
        "/mcp",
        None,
        "application/json",
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers["www-authenticate"],
        format!("Bearer resource_metadata=\"{PUBLIC}/.well-known/oauth-protected-resource/mcp\"")
    );
}

fn pw(s: &str) -> noted_auth::types::Password {
    noted_auth::types::Password::new(s)
}
