mod common;

use std::path::{Path, PathBuf};

use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use noted::mcp::context;
use noted::notes::Notes;
use noted::search::{MatchOpts, WalkOpts};
use noted::tasks::Tasks;
use serde_json::{json, Value};
use tower::ServiceExt;

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

fn fixture_dir() -> tempfile::TempDir {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/notes");
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("notes");
    copy_tree(&src, &dst);
    tmp
}

fn cores(dir: &tempfile::TempDir) -> (Notes, Tasks) {
    let root = dir.path().join("notes");
    let notes = Notes::new(&root, Some("test".into())).unwrap();
    let tasks = Tasks::new(notes.root());
    (notes, tasks)
}

#[test]
fn read_existing_and_missing() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    assert!(notes.read(&rp("Inbox.md")).unwrap().contains("# Inbox"));
    assert!(notes.read(&rp("nope.md")).is_err());
}

#[test]
fn write_roundtrip_and_path_escape() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    notes.write(&rp("sub/new.md"), "hello").unwrap();
    assert_eq!(notes.read(&rp("sub/new.md")).unwrap(), "hello");
    assert!(notes.write(&rp("../escape.md"), "x").is_err());
    assert!(notes.read(&rp("../../etc/passwd")).is_err());
}

#[test]
fn log_is_immutable_and_recoverable_delete() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let rel = notes.create_log("entry\n-- t · s", None).unwrap();
    assert!(rel.starts_with("Log/"));
    let err = notes.write(&rp(&rel), "x").unwrap_err();
    assert!(err.to_string().contains("immutable"));
    assert!(notes.delete(&rp(&rel)).is_err());
    assert!(notes.move_note(&rp(&rel), &rp("moved.md"), false).is_err());

    let trash = notes.delete(&rp("Inbox.md")).unwrap();
    assert!(trash.starts_with(".trash/"));
    assert!(notes.read(&rp("Inbox.md")).is_err());
}

#[tokio::test]
async fn search_content_and_path_exclude_trash() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let m = MatchOpts::default();
    let w = WalkOpts::default();

    let hits = notes.grep("XYZZY", 1, &m, &w).await.unwrap();
    assert!(hits.iter().any(|h| h.rel().as_str() == "projects/ideas.md"));

    let normal = notes.match_path("idea", &m, &w).await.unwrap();
    assert!(!normal.iter().any(|p| p.starts_with(".trash/")));
    // FROBNICATE appears only in the fixture's trashed note
    let frob = notes.grep("FROBNICATE", 1, &m, &w).await.unwrap();
    assert!(frob.is_empty());
}

#[test]
fn task_lifecycle_numbering_and_states() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);

    let a = tasks.create(&tt("first"), &gp("dev/noted"), "").unwrap();
    let b = tasks.create(&tt("second"), &gp("dev/noted"), "").unwrap();
    assert_eq!(a["path"], "dev/noted/task_0001");
    assert_eq!(b["path"], "dev/noted/task_0002");
    assert_eq!(a["state"], "created");

    assert!(tasks
        .update(
            &rp("dev/noted/task_0001"),
            Some(ts("completed")),
            None,
            None
        )
        .is_err());
    let done = tasks
        .update(
            &rp("dev/noted/task_0001"),
            Some(ts("completed")),
            Some("shipped it"),
            None,
        )
        .unwrap();
    assert_eq!(done["state"], "completed");

    let open = tasks.query("dev/noted", false, false).unwrap();
    assert_eq!(open.as_array().unwrap().len(), 1);
    let all = tasks.query("dev/noted", false, true).unwrap();
    assert_eq!(all.as_array().unwrap().len(), 2);

    let exact = tasks.query("dev/noted/task_0001", true, false).unwrap();
    assert_eq!(exact.as_array().unwrap().len(), 1);
    assert!(exact[0]["body"].as_str().unwrap().contains("shipped it"));

    let moved = tasks
        .move_task(&rp("dev/noted/task_0002"), &gp("dev/other"))
        .unwrap();
    assert_eq!(moved["path"], "dev/other/task_0001");
    let gone = tasks.query("dev/noted/task_0002", false, false).unwrap();
    assert!(gone.as_array().unwrap().is_empty());
}

#[test]
fn task_name_validation_and_escape() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    assert!(tasks.create(&tt("x"), &gp("bad name"), "").is_err());
    assert!(tasks.create(&tt("x"), &gp("1leading"), "").is_err());
    assert!(tasks.create(&tt("x"), &gp("../escape"), "").is_err());
    assert!(tasks.create(&tt("x"), &gp("ok-group_2"), "").is_ok());
}

#[test]
fn write_and_edit_refused_under_tasks() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    tasks.create(&tt("t"), &gp("grp"), "").unwrap();
    assert!(notes.write(&rp("Tasks/grp/task_0001.md"), "x").is_err());
    assert!(notes.delete(&rp("Tasks/grp/task_0001.md")).is_err());
}

async fn mcp_raw(app: &axum::Router, body: &Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn mcp_post(app: &axum::Router, body: &Value) -> Value {
    let resp = mcp_raw(app, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn call(app: &axum::Router, name: &str, args: Value) -> Value {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}});
    mcp_post(app, &req).await["result"].clone()
}

fn init_msg() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "0"}}})
}

fn tool_text(result: &Value) -> String {
    result["content"][0]["text"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn mcp_initialize_list_and_call() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    let app = noted::http::build_app(context(notes, tasks), None, None);

    let init = mcp_post(&app, &init_msg()).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "noted");
    assert!(init["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("personal notes"));

    let list = mcp_post(
        &app,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for want in [
        "SearchNotes",
        "ReadNote",
        "WriteNote",
        "LogNote",
        "CreateTask",
        "MoveTask",
    ] {
        assert!(names.contains(&want), "missing {want}");
    }
    let lognote = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "LogNote")
        .unwrap();
    let props = &lognote["inputSchema"]["properties"];
    assert!(props.get("body").is_some());
    assert!(props.get("source").is_none());
    assert_eq!(lognote["inputSchema"]["required"], json!(["body"]));

    let read = call(&app, "ReadNote", json!({"path": "Inbox.md"})).await;
    assert_eq!(read["isError"], false);
    assert!(tool_text(&read).contains("# Inbox"));

    let missing = call(&app, "ReadNote", json!({"path": "nope.md"})).await;
    assert_eq!(missing["isError"], true);
    assert!(tool_text(&missing).starts_with("error:"));

    let unknown = call(&app, "Nope", json!({})).await;
    assert_eq!(unknown["isError"], true);
    assert!(tool_text(&unknown).contains("Unknown tool"));
}

#[tokio::test]
async fn mcp_read_only_hides_and_refuses_mutators() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    let mut ctx = context(notes, tasks);
    ctx.process_scope = noted::mcp::CallScope::Scoped(
        noted::scope::TokenScope::single_rule(
            Some(vec!["SearchNotes".into(), "ReadNote".into()]),
            None,
        )
        .unwrap(),
    );
    let app = noted::http::build_app(ctx, None, None);

    let list = mcp_post(
        &app,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["SearchNotes", "ReadNote"]);

    let write = call(&app, "WriteNote", json!({"path": "x.md", "content": "y"})).await;
    assert_eq!(write["isError"], true);
    assert!(tool_text(&write).contains("not permitted"));
}

#[tokio::test]
async fn mcp_notification_has_no_response() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    let app = noted::http::build_app(context(notes, tasks), None, None);
    let resp = mcp_raw(
        &app,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn http_tool_route_and_errors() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    let app = noted::http::build_app(context(notes, tasks), None, None);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tool/ReadNote")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({"path": "Inbox.md"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_json(resp).await;
    assert!(value["ok"]["data"].as_str().unwrap().contains("# Inbox"));

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tool/ReadNote")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({"path": "nope.md"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn http_bearer_auth_gates_requests() {
    let dir = fixture_dir();
    let (app, token) = common::app_with_key(&dir);

    let unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tool/ReadNote")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({"path": "Inbox.md"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    let ok = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tool/ReadNote")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(
                    json!({"path": "Inbox.md"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn http_mcp_endpoint_roundtrip() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    let app = noted::http::build_app(context(notes, tasks), None, None);

    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "SearchNotes", "arguments": {"pattern": "XYZZY", "mode": "line"}}});
    let value = mcp_post(&app, &req).await;
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("projects/ideas.md"));
}

#[allow(dead_code)]
fn rp(s: &str) -> noted::notes::RelPath {
    s.parse().unwrap()
}
#[allow(dead_code)]
fn gp(s: &str) -> noted::tasks::GroupPath {
    s.parse().unwrap()
}
#[allow(dead_code)]
fn tt(s: &str) -> noted::tasks::TaskTitle {
    s.parse().unwrap()
}
#[allow(dead_code)]
fn ts(s: &str) -> noted::tasks::TaskState {
    s.parse().unwrap()
}
