mod common;

use axum::http::StatusCode;
use noted::Authority;
use noted_server::http::build_app;
use serde_json::json;

use common::{json_body, post_json, post_mcp};

fn keyed_app(dir: &tempfile::TempDir, policy: Authority) -> (axum::Router, String) {
    let svc = common::auth_service(dir);
    let token = common::mint_key(&svc, "t", policy);
    (
        build_app(common::backend(dir), Some(svc), None),
        token,
    )
}

fn held(text: &str) -> Authority {
    text.parse().unwrap()
}

fn mcp_call(name: &str, args: serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}})
}

#[tokio::test]
async fn tool_search_fixed_glob_and_hidden_flags() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(&dir, Authority::default());

    let (s, b) = post_json(
        &app,
        "/tool/SearchNotes",
        Some(&t),
        &json!({"pattern": "XYZZY", "mode": "file", "glob": ["projects"]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        json_body(&b)["ok"]["data"]
            .as_str()
            .unwrap()
            .contains("projects/ideas.md")
    );

    // case/word/type are absent from the MCP schema yet must still deserialize
    let (s, _) = post_json(
        &app,
        "/tool/SearchNotes",
        Some(&t),
        &json!({"pattern": "a.b", "mode": "file", "fixed": true, "case": "insensitive", "type": ["md"]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[test]
fn search_schema_is_lean_and_surface_clean() {
    let dir = common::fixture_dir();
    let backend = common::backend(&dir);
    let defs = backend.with_authority(None).unwrap().tools();
    let search = defs.iter().find(|d| d.name == "SearchNotes").unwrap();
    let props = search.input_schema["properties"].as_object().unwrap();
    for expected in ["pattern", "mode", "context", "fixed", "glob"] {
        assert!(props.contains_key(expected), "schema missing {expected}");
    }
    for hidden in ["case", "word", "multiline", "type", "prefix", "trash"] {
        assert!(!props.contains_key(hidden), "schema exposes {hidden}");
    }
    let blob = serde_json::to_string(&search.input_schema).unwrap() + &search.description;
    for banned in ["ripgrep", "trash"] {
        assert!(
            !blob.contains(banned),
            "SearchNotes surface leaks '{banned}'"
        );
    }
}

#[tokio::test]
async fn a_read_only_policy_refuses_the_mutators() {
    let dir = common::fixture_dir();
    let (app, ro) = keyed_app(&dir, held(r#"{"access":{"read":true,"write":false}}"#));
    let (s, _) = post_json(
        &app,
        "/tool/ReadNote",
        Some(&ro),
        &json!({"path": "Inbox.md"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = post_json(
        &app,
        "/tool/WriteNote",
        Some(&ro),
        &json!({"path": "x.md", "content": "y"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_denied_folder_confines_paths() {
    let dir = common::fixture_dir();
    let (app, f) = keyed_app(
        &dir,
        held(r#"{"paths":{"people":{"read":false,"write":false}}}"#),
    );
    let (s, _) = post_json(
        &app,
        "/tool/ReadNote",
        Some(&f),
        &json!({"path": "projects/ideas.md"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, b) = post_json(
        &app,
        "/tool/ReadNote",
        Some(&f),
        &json!({"path": "people/contacts.md"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(
        json_body(&b)["detail"]
            .as_str()
            .unwrap()
            .contains("forbidden")
    );
}

#[tokio::test]
async fn a_log_only_policy_reaches_nothing_else() {
    let dir = common::fixture_dir();
    let (app, l) = keyed_app(
        &dir,
        held(
            r#"{"access":{"read":false,"write":false},"paths":{"Log":{"read":true,"write":true}}}"#,
        ),
    );
    let (s, _) = post_json(
        &app,
        "/tool/LogNote",
        Some(&l),
        &json!({"body": "hi\n-- t · s"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = post_json(
        &app,
        "/tool/ReadNote",
        Some(&l),
        &json!({"path": "Inbox.md"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_policy_confines_search() {
    let dir = common::fixture_dir();
    let (app, f) = keyed_app(&dir, held(r#"{"scope":"projects"}"#));
    let (s, _h, b) = post_mcp(
        &app,
        Some(&f),
        &mcp_call("SearchNotes", json!({"pattern": ".", "mode": "path"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let text = json_body(&b)["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!text.is_empty());
    assert!(text.lines().all(|l| !l.contains('/')), "{text}");
}

#[tokio::test]
async fn mcp_refuses_a_write_the_policy_denies() {
    let dir = common::fixture_dir();
    let (app, ro) = keyed_app(&dir, held(r#"{"access":{"read":true,"write":false}}"#));
    let (s, _h, b) = post_mcp(
        &app,
        Some(&ro),
        &mcp_call("WriteNote", json!({"path": "x.md", "content": "y"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK); // JSON-RPC ok envelope...
    let result = &json_body(&b)["result"];
    assert_eq!(result["isError"], true); // ...carrying a tool error
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("forbidden")
    );
}

#[tokio::test]
async fn resolver_rejects_everything_but_a_live_prefixed_bearer() {
    let dir = common::fixture_dir();
    let svc = common::auth_service(&dir);
    let live = common::mint_key(&svc, "live", Authority::default());
    let pending = svc
        .key_create(&lb("pending"), Authority::default(), None)
        .unwrap()
        .token
        .expose()
        .to_string();
    let revoked = common::mint_key(&svc, "dead", Authority::default());
    svc.key_revoke(&noted_auth::oauth::service::RevokeBy::Label(lb("dead")))
        .unwrap();
    let app = build_app(common::backend(&dir), Some(svc), None);

    let probe = |tok: Option<String>| {
        let app = app.clone();
        async move {
            let (s, _) = post_json(
                &app,
                "/tool/ReadNote",
                tok.as_deref(),
                &json!({"path": "Inbox.md"}),
            )
            .await;
            s
        }
    };

    assert_eq!(probe(Some(live)).await, StatusCode::OK);
    assert_eq!(probe(None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        probe(Some("ghp_notours".into())).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        probe(Some("random-old-style-token".into())).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        probe(Some("noted_ref_whatever".into())).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        probe(Some("noted_key_wrong".into())).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(probe(Some(pending)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(probe(Some(revoked)).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_read_only_task_region_lists_but_never_writes() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(
        &dir,
        held(r#"{"paths":{"Tasks":{"read":true,"write":false}}}"#),
    );
    common::root(&dir)
        .task_create(
            &"seed".parse().unwrap(),
            &"dev".parse().unwrap(),
            &"".into(),
        )
        .unwrap();

    let (s, _) = post_json(&app, "/tool/GetTasks", Some(&t), &json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = post_json(&app, "/tool/CreateTask", Some(&t), &json!({"task": "x"})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = post_json(
        &app,
        "/tool/MoveTask",
        Some(&t),
        &json!({"path": "dev/task_0001"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_write_only_folder_leaves_the_task_region_open() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(
        &dir,
        held(
            r#"{"access":{"read":false,"write":false},"paths":{"Tasks":{"read":true,"write":true},"projects":{"read":false,"write":true}}}"#,
        ),
    );

    let (s, _) = post_json(
        &app,
        "/tool/WriteNote",
        Some(&t),
        &json!({"path": "projects/n.md", "content": "x"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, b) = post_json(
        &app,
        "/tool/WriteNote",
        Some(&t),
        &json!({"path": "people/n.md", "content": "x"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(
        json_body(&b)["detail"]
            .as_str()
            .unwrap()
            .contains("forbidden")
    );
    let (s, _) = post_json(
        &app,
        "/tool/CreateTask",
        Some(&t),
        &json!({"task": "y", "group": "ops"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = post_json(
        &app,
        "/tool/ReadNote",
        Some(&t),
        &json!({"path": "projects/n.md"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_live_policy_edit_is_visible_to_the_next_request() {
    let dir = common::fixture_dir();
    let svc = common::auth_service(&dir);
    let token = common::mint_key(
        &svc,
        "agent",
        held(r#"{"access":{"read":false,"write":false}}"#),
    );
    let app = build_app(common::backend(&dir), Some(svc.clone()), None);

    let (s, _) = post_json(
        &app,
        "/tool/SearchNotes",
        Some(&token),
        &json!({"pattern": "."}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    svc.key_set_policy(
        Some(&lb("agent")),
        None,
        r#"{"access":{"read":true,"write":false}}"#.parse::<Authority>().unwrap(),
    )
    .unwrap();
    let (s, _) = post_json(
        &app,
        "/tool/SearchNotes",
        Some(&token),
        &json!({"pattern": "XYZZY"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn mcp_initialize_returns_server_info() {
    let dir = common::fixture_dir();
    let app = build_app(common::backend(&dir), None, None);
    let (s, _headers, b) = post_mcp(
        &app,
        None,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}}}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json_body(&b)["result"]["serverInfo"]["name"], "noted");
}

#[tokio::test]
async fn mcp_stateless_needs_no_session() {
    let dir = common::fixture_dir();
    let app = build_app(common::backend(&dir), None, None);
    let (s, _h, b) = post_mcp(
        &app,
        None,
        &mcp_call("SearchNotes", json!({"pattern": "XYZZY", "mode": "line"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        json_body(&b)["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("projects/ideas.md")
    );
}

#[tokio::test]
async fn conditional_write_over_http() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(&dir, Authority::default());

    let (s, _) = post_json(
        &app,
        "/tool/WriteNote",
        Some(&t),
        &json!({"path": "http_cw.md", "content": "a", "when": "missing"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = post_json(
        &app,
        "/tool/WriteNote",
        Some(&t),
        &json!({"path": "http_cw.md", "content": "b", "when": "missing"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // An unknown word is a domain rejection (400), not a serde 422.
    let (s, _) = post_json(
        &app,
        "/tool/WriteNote",
        Some(&t),
        &json!({"path": "http_cw.md", "content": "b", "when": "whenever"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn write_schema_hides_when_via_mcp() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(&dir, Authority::default());
    let (s, _h, b) = post_mcp(
        &app,
        Some(&t),
        &json!({"jsonrpc": "2.0", "id": 1,
        "method": "tools/list", "params": {}}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let tools = json_body(&b)["result"]["tools"].as_array().unwrap().clone();
    let write = tools
        .iter()
        .find(|t| t["name"] == "WriteNote")
        .expect("WriteNote listed");
    let props = &write["inputSchema"]["properties"];
    assert!(props.get("content").is_some());
    assert!(props.get("when").is_none(), "when leaked into MCP schema");
}

#[allow(dead_code)]
fn un(s: impl AsRef<str>) -> noted_auth::oauth::types::Username {
    s.as_ref().parse().unwrap()
}
#[allow(dead_code)]
fn pw(s: impl AsRef<str>) -> noted_auth::oauth::types::Password {
    noted_auth::oauth::types::Password::new(s.as_ref())
}
#[allow(dead_code)]
fn lb(s: impl AsRef<str>) -> noted_auth::oauth::types::Label {
    noted_auth::oauth::types::Label::new(s.as_ref()).unwrap()
}
#[allow(dead_code)]
fn ci(s: impl AsRef<str>) -> noted_auth::oauth::types::CredentialId {
    noted_auth::oauth::types::CredentialId::new(s.as_ref()).expect("valid credential id in test")
}
