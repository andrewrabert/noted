mod common;

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::Router;
use base64::Engine;
use noted::http::build_app;
use noted::mcp::context;
use noted::oauth::service::ScopeEdit;
use noted::oauth::{AuthService, OAuthProvider};
use noted::password::{hash_password, verify_password};
use noted::scope::StoredScope;
use serde_json::json;
use sha2::{Digest, Sha256};

use common::{json_body, post_form, post_json, post_mcp, request};

const PUBLIC: &str = "http://localhost";
const REDIRECT: &str = "http://client.example/callback";

struct UserSpec {
    password: &'static str,
    tools: Option<Vec<&'static str>>,
    paths: Option<Vec<&'static str>>,
}

impl UserSpec {
    fn new(password: &'static str) -> UserSpec {
        UserSpec {
            password,
            tools: None,
            paths: None,
        }
    }
}

fn build(dir: &tempfile::TempDir, users: &[(&str, UserSpec)]) -> (Router, Arc<AuthService>) {
    let svc = common::auth_service(dir);
    for (name, spec) in users {
        svc.user_add(&un(name), &pw(spec.password)).unwrap();
        if spec.tools.is_some() || spec.paths.is_some() {
            let to_vec = |o: &Option<Vec<&str>>| {
                o.as_ref()
                    .map(|v| v.iter().map(|s| s.to_string()).collect())
            };
            svc.user_grant(
                &un(name),
                ScopeEdit::Append(vec![RuleSpec {
                    tools: to_vec(&spec.tools),
                    paths: to_vec(&spec.paths),
                }]),
            )
            .unwrap();
        }
    }
    let provider = Arc::new(OAuthProvider::new(PUBLIC, svc.clone()).unwrap());
    let (notes, tasks) = common::cores(dir);
    let app = build_app(context(notes, tasks), Some(svc.clone()), Some(provider));
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
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
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
    let (app, _) = build(&dir, &[("full", UserSpec::new("pw"))]);
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
                paths: Some(vec!["projects"]),
                ..UserSpec::new("pw")
            },
        )],
    );
    let (token, _, _) = authenticate(&app, "p", "pw").await;
    let (_e, paths) = mcp_text(
        &app,
        &token,
        "SearchNotes",
        json!({"pattern": ".", "mode": "path"}),
    )
    .await;
    assert!(paths.lines().all(|p| p.starts_with("projects/")) && !paths.is_empty());
    let (is_err, msg) = mcp_text(
        &app,
        &token,
        "ReadNote",
        json!({"path": "people/contacts.md"}),
    )
    .await;
    assert!(is_err && msg.contains("allowed folders"));
}

#[tokio::test]
async fn oauth_read_only_blocks_write() {
    let dir = common::fixture_dir();
    let (app, _) = build(
        &dir,
        &[(
            "ro",
            UserSpec {
                tools: Some(vec!["SearchNotes", "ReadNote"]),
                ..UserSpec::new("pw")
            },
        )],
    );
    let (token, _, _) = authenticate(&app, "ro", "pw").await;
    let (is_err, msg) = mcp_text(
        &app,
        &token,
        "WriteNote",
        json!({"path": "x.md", "content": "hi"}),
    )
    .await;
    assert!(is_err && msg.contains("not permitted"));
}

#[tokio::test]
async fn bad_password_rejected() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("right"))]);
    let client_id = register(&app).await;
    let (_v, challenge) = pkce();
    let (s, _h, b) = login(&app, &client_id, "a", "wrong", &challenge).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(String::from_utf8_lossy(&b).contains("invalid credentials"));
}

#[tokio::test]
async fn unknown_user_rejected() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
    let client_id = register(&app).await;
    let (_v, challenge) = pkce();
    let (s, _h, _b) = login(&app, &client_id, "ghost", "pw", &challenge).await;
    eprintln!("REUSED_REFRESH_STATUS={s}");
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_get_renders_form() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
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
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
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
async fn login_rate_limited() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
    let client_id = register(&app).await;
    let (_v, challenge) = pkce();
    let mut statuses = Vec::new();
    for _ in 0..7 {
        let (s, _h, _b) = login(&app, &client_id, "a", "bad", &challenge).await;
        statuses.push(s);
    }
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test]
async fn refresh_token_grant_and_rotation() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
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
    assert_ne!(new["access_token"].as_str().unwrap(), token);
    // oxide-auth rotates the refresh token (single-use): the rotated-out token is
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
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
    let (s, _) = post_json(&app, "/tool/ReadNote", None, &json!({"path": "Inbox.md"})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tool_realm_accepts_an_api_key() {
    let dir = common::fixture_dir();
    let (app, svc) = build(&dir, &[("a", UserSpec::new("pw"))]);
    let key = common::mint_key(&svc, "bot", StoredScope::Unrestricted);
    let (s, _) = post_json(&app, "/tool/ReadNote", None, &json!({"path": "Inbox.md"})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = post_json(
        &app,
        "/tool/ReadNote",
        Some(&key),
        &json!({"path": "Inbox.md"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn mcp_requires_oauth_token() {
    let dir = common::fixture_dir();
    let (app, _) = build(&dir, &[("a", UserSpec::new("pw"))]);
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
    let (app, svc) = build(&dir, &[("a", UserSpec::new("pw"))]);
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
async fn login_cannot_distinguish_unknown_names_or_key_labels() {
    let dir = common::fixture_dir();
    let (app, svc) = build(&dir, &[("real", UserSpec::new("right"))]);
    // an API key label is not a username — keys are not in the user table
    common::mint_key(&svc, "bot", StoredScope::Unrestricted);
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
        let (app, _svc) = build(&dir, &[("a", UserSpec::new("pw"))]);
        register(&app).await
    };
    let db = Arc::new(noted::oauth::Db::open(&dir.path().join("auth.redb")).unwrap());
    let svc = Arc::new(AuthService::new(db, noted::types::Ttl::from_secs(3600)));
    let revived = OAuthProvider::new(PUBLIC, svc).unwrap();
    assert!(revived.has_client(&client_id));
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

use noted::oauth::macaroon::attenuate;
use noted::scope::RuleSpec;

async fn root_macaroon(app: &Router, token: &str) -> String {
    let (s, b) = common::post_json(app, "/macaroon/root", Some(token), &json!({})).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    json_body(&b)["macaroon"].as_str().unwrap().to_string()
}

async fn tool(app: &Router, token: &str, name: &str, args: serde_json::Value) -> StatusCode {
    common::post_json(app, &format!("/tool/{name}"), Some(token), &args)
        .await
        .0
}

fn tools_rule(tools: &[&str]) -> Vec<RuleSpec> {
    vec![RuleSpec {
        tools: Some(tools.iter().map(|s| s.to_string()).collect()),
        paths: None,
    }]
}

#[tokio::test]
async fn oauth_token_and_root_macaroon_work_on_tool() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let search = json!({"pattern": ".", "mode": "path"});
    assert_eq!(
        tool(&app, &access, "SearchNotes", search.clone()).await,
        StatusCode::OK
    );
    let root = root_macaroon(&app, &access).await;
    assert_eq!(
        tool(&app, &root, "SearchNotes", search).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn macaroon_child_attenuates_tools() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let root = root_macaroon(&app, &access).await;
    let (child, _exp) = attenuate(
        &root,
        Some(&tools_rule(&["SearchNotes"])),
        noted::types::Ttl::from_secs(3600),
        "id-1",
        None,
    )
    .unwrap();
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
async fn macaroon_child_confines_paths() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let root = root_macaroon(&app, &access).await;
    let policy = vec![RuleSpec {
        tools: None,
        paths: Some(vec!["projects".into()]),
    }];
    let (child, _exp) = attenuate(
        &root,
        Some(&policy),
        noted::types::Ttl::from_secs(3600),
        "id-2",
        None,
    )
    .unwrap();
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
async fn macaroon_child_cannot_exceed_parent() {
    let dir = common::fixture_dir();
    let (app, _p) = build(
        &dir,
        &[(
            "ro",
            UserSpec {
                tools: Some(vec!["SearchNotes", "ReadNote"]),
                ..UserSpec::new("pw")
            },
        )],
    );
    let (access, _r, _c) = authenticate(&app, "ro", "pw").await;
    let root = root_macaroon(&app, &access).await;
    let (child, _exp) = attenuate(
        &root,
        Some(&tools_rule(&["WriteNote"])),
        noted::types::Ttl::from_secs(3600),
        "id-3",
        None,
    )
    .unwrap();
    assert_eq!(
        tool(
            &app,
            &child,
            "WriteNote",
            json!({"path": "x.md", "content": "hi"})
        )
        .await,
        StatusCode::FORBIDDEN
    );
    // effective = {Search,Read} ∩ {Write} = ∅: even SearchNotes is denied
    assert_eq!(
        tool(
            &app,
            &child,
            "SearchNotes",
            json!({"pattern": ".", "mode": "path"})
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn macaroon_expiry_rejects() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let root = root_macaroon(&app, &access).await;
    let (child, _exp) =
        attenuate(&root, None, noted::types::Ttl::from_secs(0), "id-4", None).unwrap();
    assert_eq!(
        tool(&app, &child, "SearchNotes", json!({"pattern": "."})).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn macaroon_revoke_by_id_and_session() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let root = root_macaroon(&app, &access).await;
    let search = json!({"pattern": ".", "mode": "path"});

    let (doomed, _) = attenuate(
        &root,
        Some(&tools_rule(&["SearchNotes"])),
        noted::types::Ttl::from_secs(3600),
        "kill",
        Some("run-1"),
    )
    .unwrap();
    let (sibling, _) = attenuate(
        &root,
        Some(&tools_rule(&["SearchNotes"])),
        noted::types::Ttl::from_secs(3600),
        "keep",
        Some("run-2"),
    )
    .unwrap();
    assert_eq!(
        tool(&app, &doomed, "SearchNotes", search.clone()).await,
        StatusCode::OK
    );

    let (s, _) = common::post_json(
        &app,
        "/macaroon/revoke",
        Some(&access),
        &json!({"id": "kill"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        tool(&app, &doomed, "SearchNotes", search.clone()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        tool(&app, &sibling, "SearchNotes", search.clone()).await,
        StatusCode::OK
    );

    let (s, _) = common::post_json(
        &app,
        "/macaroon/revoke",
        Some(&access),
        &json!({"session": "run-2"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        tool(&app, &sibling, "SearchNotes", search).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn macaroon_revoke_all_bumps_epoch() {
    let dir = common::fixture_dir();
    let (app, _p) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    let root = root_macaroon(&app, &access).await;
    let search = json!({"pattern": ".", "mode": "path"});
    let (child, _) = attenuate(
        &root,
        Some(&tools_rule(&["SearchNotes"])),
        noted::types::Ttl::from_secs(3600),
        "id-5",
        None,
    )
    .unwrap();
    assert_eq!(
        tool(&app, &child, "SearchNotes", search.clone()).await,
        StatusCode::OK
    );
    let (s, _) = common::post_json(
        &app,
        "/macaroon/revoke",
        Some(&access),
        &json!({"all": true}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        tool(&app, &child, "SearchNotes", search).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn oauth_token_survives_restart() {
    let dir = common::fixture_dir();
    let db_path = dir.path().join("auth.redb");
    // Mint a token, then drop everything (frees the redb lock). Validation is
    // DB-only, so nothing in memory was load-bearing.
    let access = {
        let (app, _svc) = build(&dir, &[("ann", UserSpec::new("pw"))]);
        authenticate(&app, "ann", "pw").await.0
    };
    let db = Arc::new(noted::oauth::Db::open(&db_path).unwrap());
    let revived = AuthService::new(db, noted::types::Ttl::from_secs(3600));
    let (owner, scope) = revived.resolve_bearer(&access).unwrap().unwrap();
    assert_eq!(owner, "user:ann");
    assert!(scope.allows("SearchNotes"));
}

#[tokio::test]
async fn access_tokens_live_one_hour() {
    let dir = common::fixture_dir();
    let (app, svc) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let (access, _r, _c) = authenticate(&app, "ann", "pw").await;
    assert!(access.starts_with("noted_acc_"));
    let (_name, _client, expires_at) = svc.access_owner(&access).unwrap().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ttl = expires_at as i64 - now as i64;
    assert!((ttl - 3600).abs() <= 5, "access ttl was {ttl}");
}

#[tokio::test]
async fn macaroon_parent_can_be_an_api_key_and_shrinks_live() {
    let dir = common::fixture_dir();
    let (app, svc) = build(&dir, &[("ann", UserSpec::new("pw"))]);
    let key = common::mint_key(&svc, "agent", StoredScope::Unrestricted);

    let root = root_macaroon(&app, &key).await;
    let (child, _exp) = attenuate(
        &root,
        Some(&tools_rule(&["SearchNotes", "ReadNote"])),
        noted::types::Ttl::from_secs(3600),
        "kid-1",
        None,
    )
    .unwrap();
    let search = json!({"pattern": ".", "mode": "path"});
    assert_eq!(
        tool(&app, &child, "SearchNotes", search.clone()).await,
        StatusCode::OK
    );
    assert_eq!(
        tool(
            &app,
            &child,
            "WriteNote",
            json!({"path": "x.md", "content": "y"})
        )
        .await,
        StatusCode::FORBIDDEN
    );

    // appending the first grant flips the unrestricted key to ReadNote-only,
    // so the child's SearchNotes dies with it
    svc.key_grant(
        Some(&lb("agent")),
        None,
        ScopeEdit::Append(tools_rule(&["ReadNote"])),
    )
    .unwrap();
    assert_eq!(
        tool(&app, &child, "SearchNotes", search.clone()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        tool(&app, &child, "ReadNote", json!({"path": "Inbox.md"})).await,
        StatusCode::OK
    );

    svc.key_revoke(&noted::oauth::service::RevokeBy::Label(lb("agent")))
        .unwrap();
    assert_eq!(
        tool(&app, &child, "ReadNote", json!({"path": "Inbox.md"})).await,
        StatusCode::UNAUTHORIZED
    );
}

#[allow(dead_code)]
fn un(s: impl AsRef<str>) -> noted::oauth::types::Username {
    s.as_ref().parse().unwrap()
}
#[allow(dead_code)]
fn pw(s: impl AsRef<str>) -> noted::oauth::types::Password {
    noted::oauth::types::Password::new(s.as_ref())
}
#[allow(dead_code)]
fn lb(s: impl AsRef<str>) -> noted::oauth::types::Label {
    noted::oauth::types::Label::new(s.as_ref()).unwrap()
}
#[allow(dead_code)]
fn ci(s: impl AsRef<str>) -> noted::oauth::types::CredentialId {
    noted::oauth::types::CredentialId::new(s.as_ref()).expect("valid credential id in test")
}
