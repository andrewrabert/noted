mod common;

use std::path::{Path, PathBuf};

use common::{found, grep, note, read, rp, write};

use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use noted::NotedRoot;
use noted::tasks::{GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskState, TaskTitle};
use serde_json::{Value, json};
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

fn cores(dir: &tempfile::TempDir) -> NotedRoot {
    common::root(dir)
}

fn gp(s: &str) -> GroupPath {
    s.parse().unwrap()
}
fn tt(s: &str) -> TaskTitle {
    s.parse().unwrap()
}
fn tr(s: &str) -> TaskRef {
    s.parse().unwrap()
}
fn ts(s: &str) -> TaskState {
    s.parse().unwrap()
}

async fn create(root: &NotedRoot, task: &str, group: &str) -> noted::Result<TaskNote> {
    root.task_create(&tt(task), &gp(group), &"".into()).await
}

async fn get(root: &NotedRoot, prefix: &str, include_completed: bool) -> Vec<TaskNote> {
    root.task_get(&TaskQuery {
        prefix: tr(prefix),
        include_completed,
    })
    .await
    .unwrap()
}

async fn advance(
    root: &NotedRoot,
    reference: &str,
    state: &str,
    notes: Option<&str>,
) -> noted::Result<TaskNote> {
    root.task_update(
        &tr(reference),
        &TaskChange {
            state: Some(ts(state)),
            notes: notes.map(Into::into),
            task: None,
        },
    )
    .await
}

#[tokio::test]
async fn read_existing_and_missing() {
    let dir = fixture_dir();
    let root = cores(&dir);
    assert!(read(&root, "/Inbox.md").await.unwrap().contains("# Inbox"));
    assert!(read(&root, "/nope.md").await.is_err());
}

#[tokio::test]
async fn write_roundtrip_and_path_escape() {
    let dir = fixture_dir();
    let root = cores(&dir);
    write(&root, &note("/sub/new.md", "hello")).await.unwrap();
    assert_eq!(read(&root, "/sub/new.md").await.unwrap(), "hello");
    assert!(noted::NotePath::new("../escape.md").is_err());
    assert!(noted::NotePath::new("/../../etc/passwd").is_err());
}

#[tokio::test]
async fn log_is_immutable_and_recoverable_delete() {
    let dir = fixture_dir();
    let root = cores(&dir);
    let rel = root
        .log_note(&"entry\n-- t · s".into())
        .await
        .unwrap()
        .path()
        .to_string();
    assert!(rel.starts_with("/20"), "{rel}");
    let spelled = format!("/.logs{rel}");
    assert!(
        noted::NotePath::new(&spelled).is_err(),
        "a log entry is not a note path"
    );

    let trashed = root.note_delete(&rp("/Inbox.md")).await.unwrap();
    assert_eq!(trashed.path(), &rp("/Inbox.md"));
    assert!(read(&root, "/Inbox.md").await.is_err());
}

#[tokio::test]
async fn search_content_and_path_exclude_trash() {
    let dir = fixture_dir();
    let root = cores(&dir);

    let hits = grep(&root, "XYZZY").await.unwrap();
    assert!(hits.iter().any(|h| h.path == rp("/projects/ideas.md")));

    let normal = found(&root, "idea").await.unwrap();
    assert!(!normal.iter().any(|p| p.starts_with("/.trash/")));
    // FROBNICATE appears only in the fixture's trashed note
    assert!(grep(&root, "FROBNICATE").await.unwrap().is_empty());
}

#[tokio::test]
async fn task_lifecycle_numbering_and_states() {
    let dir = fixture_dir();
    let root = cores(&dir);

    let a = create(&root, "first", "dev/noted").await.unwrap();
    let b = create(&root, "second", "dev/noted").await.unwrap();
    assert_eq!(a.path(), "dev/noted/task_0001");
    assert_eq!(b.path(), "dev/noted/task_0002");
    assert_eq!(a.front().state, TaskState::Created);

    assert!(
        advance(&root, "dev/noted/task_0001", "completed", None)
            .await
            .is_err()
    );
    let done = advance(
        &root,
        "dev/noted/task_0001",
        "completed",
        Some("shipped it"),
    )
    .await
    .unwrap();
    assert_eq!(done.front().state, TaskState::Completed);

    assert_eq!(get(&root, "dev/noted", false).await.len(), 1);
    assert_eq!(get(&root, "dev/noted", true).await.len(), 2);

    let exact = get(&root, "dev/noted/task_0001", false).await;
    assert_eq!(exact.len(), 1);
    assert!(exact[0].body().as_str().contains("shipped it"));

    let moved = root
        .task_move(&tr("dev/noted/task_0002"), &gp("dev/other"))
        .await
        .unwrap();
    assert_eq!(moved.path(), "dev/other/task_0001");
    assert!(get(&root, "dev/noted/task_0002", false).await.is_empty());
}

#[tokio::test]
async fn task_name_validation_and_escape() {
    let dir = fixture_dir();
    let root = cores(&dir);
    assert!("bad name".parse::<GroupPath>().is_err());
    assert!("1leading".parse::<GroupPath>().is_err());
    assert!("../escape".parse::<GroupPath>().is_err());
    assert!(create(&root, "x", "ok-group_2").await.is_ok());
}

#[tokio::test]
async fn write_and_edit_refused_under_tasks() {
    let dir = fixture_dir();
    let root = cores(&dir);
    create(&root, "t", "grp").await.unwrap();
    assert!(
        noted::NotePath::new("/.tasks/grp/task_0001.md").is_err(),
        "a task entry is not a note path"
    );
    assert!(read(&root, "/grp/task_0001.md").await.is_err());
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
    let app = common::open_app(&dir);

    let init = mcp_post(&app, &init_msg()).await;
    assert_eq!(init["result"]["serverInfo"]["name"], noted::APP_NAME);
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("personal notes")
    );

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

    let read = call(&app, "ReadNote", json!({"path": "/Inbox.md"})).await;
    assert_eq!(read["isError"], false);
    assert!(tool_text(&read).contains("# Inbox"));

    let missing = call(&app, "ReadNote", json!({"path": "/nope.md"})).await;
    assert_eq!(missing["isError"], true);
    assert!(tool_text(&missing).starts_with("error:"));

    let unknown = call(&app, "Nope", json!({})).await;
    assert_eq!(unknown["isError"], true);
    assert!(tool_text(&unknown).contains("not found"));
}

#[tokio::test]
async fn mcp_read_only_hides_and_refuses_mutators() {
    let dir = fixture_dir();
    let policy =
        r#"{"access":{"read":true,"write":false}}"#.parse::<noted::PolicyFragment>().unwrap();
    let app = noted_server::http::build_app(noted_server::http::Served::origin(
        common::policed_root(&dir, policy),
        noted_server::auth::AuthState::open(),
    ));

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
    assert_eq!(
        names,
        vec![
            "SearchNotes",
            "SearchLog",
            "SearchTasks",
            "ReadNote",
            "GetLog",
            "GetTasks"
        ],
        "a read-only policy lists every read tool and no writer"
    );

    let write = call(&app, "WriteNote", json!({"path": "/x.md", "content": "y"})).await;
    assert_eq!(write["isError"], true);
    assert!(tool_text(&write).contains("forbidden"));
}

#[tokio::test]
async fn mcp_notification_has_no_response() {
    let dir = fixture_dir();
    let app = common::open_app(&dir);
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
    let app = common::open_app(&dir);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tool/ReadNote")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({"path": "/Inbox.md"}).to_string(),
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
                    json!({"path": "/nope.md"}).to_string(),
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
    let (app, token) = common::app_with_key(&dir).await;

    let unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tool/ReadNote")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({"path": "/Inbox.md"}).to_string(),
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
                    json!({"path": "/Inbox.md"}).to_string(),
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
    let app = common::open_app(&dir);

    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "SearchNotes", "arguments": {"pattern": "XYZZY", "mode": "line"}}});
    let value = mcp_post(&app, &req).await;
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("projects/ideas.md"));
}
