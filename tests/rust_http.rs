mod common;

use axum::http::StatusCode;
use noted::http::build_app;
use noted::mcp::context;
use noted::scope::{RuleSpec, StoredScope};
use serde_json::json;

use common::{json_body, post_json, post_mcp};

fn keyed_app(dir: &tempfile::TempDir, scope: StoredScope) -> (axum::Router, String) {
    let (notes, tasks) = common::cores(dir);
    let svc = common::auth_service(dir);
    let token = common::mint_key(&svc, "t", scope);
    (build_app(context(notes, tasks), Some(svc), None), token)
}

fn spec(tools: Option<&[&str]>, paths: Option<&[&str]>) -> RuleSpec {
    let to_vec = |o: Option<&[&str]>| o.map(|s: &[&str]| s.iter().map(|x| x.to_string()).collect());
    RuleSpec {
        tools: to_vec(tools),
        paths: to_vec(paths),
    }
}

fn mcp_call(name: &str, args: serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}})
}

#[tokio::test]
async fn tool_search_fixed_glob_and_hidden_flags() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(&dir, StoredScope::Unrestricted);

    let (s, b) = post_json(
        &app,
        "/tool/SearchNotes",
        Some(&t),
        &json!({"pattern": "XYZZY", "mode": "file", "glob": ["projects"]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(json_body(&b)["ok"]["data"]
        .as_str()
        .unwrap()
        .contains("projects/ideas.md"));

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
    let defs = noted::tools::tool_defs();
    let search = defs.iter().find(|d| d.name == "SearchNotes").unwrap();
    let props = search.input_schema["properties"].as_object().unwrap();
    for expected in ["pattern", "mode", "context", "fixed", "glob"] {
        assert!(props.contains_key(expected), "schema missing {expected}");
    }
    for hidden in [
        "case",
        "word",
        "multiline",
        "type",
        "prefix",
        "trash",
        "meta",
    ] {
        assert!(!props.contains_key(hidden), "schema exposes {hidden}");
    }
    let blob = serde_json::to_string(&search.input_schema).unwrap() + search.description;
    for banned in ["ripgrep", "trash", ".md.meta"] {
        assert!(
            !blob.contains(banned),
            "SearchNotes surface leaks '{banned}'"
        );
    }
}

#[tokio::test]
async fn tool_read_only_scope_refuses_mutators() {
    let dir = common::fixture_dir();
    let (app, ro) = keyed_app(
        &dir,
        common::grants(Some(&["SearchNotes", "ReadNote"]), None),
    );
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
async fn tool_folder_scope_confines_paths() {
    let dir = common::fixture_dir();
    let (app, f) = keyed_app(&dir, common::grants(None, Some(&["projects"])));
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
    assert!(json_body(&b)["detail"]
        .as_str()
        .unwrap()
        .contains("allowed folders"));
}

#[tokio::test]
async fn tool_log_only_scope_allows_only_lognote() {
    let dir = common::fixture_dir();
    let (app, l) = keyed_app(&dir, common::grants(Some(&["LogNote"]), None));
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
async fn mcp_scope_confines_search() {
    let dir = common::fixture_dir();
    let (app, f) = keyed_app(&dir, common::grants(None, Some(&["projects"])));
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
    assert!(text.lines().all(|l| l.starts_with("projects/")), "{text}");
}

#[tokio::test]
async fn mcp_scope_refuses_out_of_scope_tool() {
    let dir = common::fixture_dir();
    let (app, ro) = keyed_app(
        &dir,
        common::grants(Some(&["SearchNotes", "ReadNote"]), None),
    );
    let (s, _h, b) = post_mcp(
        &app,
        Some(&ro),
        &mcp_call("WriteNote", json!({"path": "x.md", "content": "y"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK); // JSON-RPC ok envelope...
    let result = &json_body(&b)["result"];
    assert_eq!(result["isError"], true); // ...carrying a tool error
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("not permitted"));
}

#[tokio::test]
async fn resolver_rejects_everything_but_a_live_prefixed_bearer() {
    let dir = common::fixture_dir();
    let (notes, tasks) = common::cores(&dir);
    let svc = common::auth_service(&dir);
    let live = common::mint_key(&svc, "live", StoredScope::Unrestricted);
    let pending = svc
        .key_create(&lb("pending"), StoredScope::Unrestricted, None)
        .unwrap()
        .token
        .expose()
        .to_string();
    let revoked = common::mint_key(&svc, "dead", StoredScope::Unrestricted);
    svc.key_revoke(&noted::oauth::service::RevokeBy::Label(lb("dead")))
        .unwrap();
    let app = build_app(context(notes, tasks), Some(svc), None);

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
async fn tool_scope_allows_update_but_not_create_or_move_task() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(
        &dir,
        StoredScope::Grants(vec![spec(Some(&["GetTasks", "UpdateTask"]), None)]),
    );

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
async fn tool_multi_grant_confines_notes_per_tool_but_not_tasks() {
    let dir = common::fixture_dir();
    let (app, t) = keyed_app(
        &dir,
        StoredScope::Grants(vec![
            spec(Some(&["WriteNote"]), Some(&["projects"])),
            spec(Some(&["CreateTask"]), None),
        ]),
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
    assert!(json_body(&b)["detail"]
        .as_str()
        .unwrap()
        .contains("allowed folders"));
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
async fn live_grant_edit_is_visible_to_the_next_request() {
    let dir = common::fixture_dir();
    let (notes, tasks) = common::cores(&dir);
    let svc = common::auth_service(&dir);
    let token = common::mint_key(&svc, "agent", common::grants(Some(&["ReadNote"]), None));
    let app = build_app(context(notes, tasks), Some(svc.clone()), None);

    let (s, _) = post_json(
        &app,
        "/tool/SearchNotes",
        Some(&token),
        &json!({"pattern": "."}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    svc.key_grant(
        Some(&lb("agent")),
        None,
        noted::oauth::service::ScopeEdit::Append(vec![spec(Some(&["SearchNotes"]), None)]),
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
    let (notes, tasks) = common::cores(&dir);
    let app = build_app(context(notes, tasks), None, None);
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
    let (notes, tasks) = common::cores(&dir);
    let app = build_app(context(notes, tasks), None, None);
    let (s, _h, b) = post_mcp(
        &app,
        None,
        &mcp_call("SearchNotes", json!({"pattern": "XYZZY", "mode": "line"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(json_body(&b)["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("projects/ideas.md"));
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
