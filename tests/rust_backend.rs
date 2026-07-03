mod common;

use noted::backend::{Backend, ToolCall, Transport};
use noted::error::NotedError;
use noted::http::build_app;
use noted::httpurl::HttpUrl;
use noted::mcp::context;
use noted::notes::Notes;
use noted::scope::StoredScope;
use noted::tasks::Tasks;
use serde_json::json;

fn open_app(dir: &tempfile::TempDir) -> axum::Router {
    let (notes, tasks) = common::cores(dir);
    build_app(context(notes, tasks), None, None)
}

fn url(s: &str) -> HttpUrl {
    s.parse().unwrap()
}

fn remote(dir: &tempfile::TempDir) -> Backend {
    Backend::http_with(&url("http://test"), None, Transport::Test(open_app(dir)))
}

fn call(name: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        args,
    }
}

#[tokio::test]
async fn http_success_roundtrip() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let out = backend
        .invoke(&call("WriteNote", json!({"path": "r.md", "content": "hi"})))
        .await
        .unwrap();
    assert_eq!(out.render(), "wrote r.md");
    assert_eq!(
        std::fs::read_to_string(common::notes_root(&dir).join("r.md")).unwrap(),
        "hi"
    );
}

#[tokio::test]
async fn http_missing_note_maps_to_not_found() {
    let dir = common::fixture_dir();
    let err = remote(&dir)
        .invoke(&call("ReadNote", json!({"path": "ghost.md"})))
        .await
        .unwrap_err();
    let NotedError::NotFound(msg) = &err else {
        panic!("expected NotFound, got {err:?}");
    };
    assert!(msg.contains("no note"));
}

#[tokio::test]
async fn http_invalid_pattern_maps_from_4xx() {
    let dir = common::fixture_dir();
    let err = remote(&dir)
        .invoke(&call(
            "SearchNotes",
            json!({"pattern": "(", "mode": "line"}),
        ))
        .await
        .unwrap_err();
    let NotedError::InvalidInput(msg) = &err else {
        panic!("expected InvalidInput, got {err:?}");
    };
    assert!(msg.contains("invalid search pattern"));
}

#[tokio::test]
async fn http_sends_and_checks_bearer_token() {
    let dir = common::fixture_dir();
    let (notes, tasks) = common::cores(&dir);
    let svc = common::auth_service(&dir);
    let token = common::mint_key(&svc, "test", StoredScope::Unrestricted);
    let authed_app = build_app(context(notes, tasks), Some(svc), None);

    let ok = Backend::http_with(
        &url("http://test"),
        Some(token),
        Transport::Test(authed_app.clone()),
    )
    .invoke(&call("ReadNote", json!({"path": "Inbox.md"})))
    .await
    .unwrap();
    assert!(ok.render().contains("# Inbox"));

    let bad = Backend::http_with(
        &url("http://test"),
        Some("noted_key_wrong".into()),
        Transport::Test(authed_app),
    );
    let err = bad
        .invoke(&call("ReadNote", json!({"path": "Inbox.md"})))
        .await
        .unwrap_err();
    assert!(matches!(err, NotedError::InvalidInput(_)), "{err:?}");
}

#[tokio::test]
async fn http_strips_cli_only_source() {
    let dir = common::fixture_dir();
    let out = remote(&dir)
        .invoke(&call(
            "LogNote",
            json!({"body": "hi\n-- t · s", "source": "dropped"}),
        ))
        .await
        .unwrap();
    assert!(out.render().starts_with("logged Log/"));
}

fn canned(status: u16, body: &'static str) -> axum::Router {
    use axum::http::StatusCode;
    use axum::routing::post;
    axum::Router::new().route(
        "/tool/{name}",
        post(move || async move { (StatusCode::from_u16(status).unwrap(), body) }),
    )
}

async fn invoke_canned(
    status: u16,
    body: &'static str,
) -> Result<noted::tools::ToolOutput, NotedError> {
    let backend = Backend::http_with(
        &url("http://x"),
        None,
        Transport::Test(canned(status, body)),
    );
    backend
        .invoke(&call("ReadNote", json!({"path": "a.md"})))
        .await
}

#[tokio::test]
async fn http_missing_ok_key_is_unavailable() {
    let err = invoke_canned(200, "{\"nope\": 1}").await.unwrap_err();
    let NotedError::Unavailable(msg) = &err else {
        panic!("expected Unavailable, got {err:?}");
    };
    assert!(msg.contains("malformed"));
}

#[tokio::test]
async fn http_non_json_body_is_json_error() {
    let err = invoke_canned(200, "not json").await.unwrap_err();
    let NotedError::Json { context, source } = &err else {
        panic!("expected Json, got {err:?}");
    };
    assert!(context.contains("malformed"));
    assert!(std::error::Error::source(&err).is_some());
    let _ = source;
}

#[tokio::test]
async fn http_4xx_without_detail_falls_back() {
    let err = invoke_canned(400, "{\"other\": 1}").await.unwrap_err();
    let NotedError::InvalidInput(msg) = &err else {
        panic!("expected InvalidInput, got {err:?}");
    };
    assert!(msg.contains("HTTP 400"));
}

#[tokio::test]
async fn http_5xx_without_detail_falls_back() {
    let err = invoke_canned(500, "{}").await.unwrap_err();
    let NotedError::Unavailable(msg) = &err else {
        panic!("expected Unavailable, got {err:?}");
    };
    assert!(msg.contains("HTTP 500"));
}

#[tokio::test]
async fn http_detail_is_surfaced() {
    let err = invoke_canned(400, "{\"detail\": \"boom detail\"}")
        .await
        .unwrap_err();
    assert!(err.message().contains("boom detail"));
}

#[test]
fn backend_selects_http_when_remote_url_set() {
    assert!(matches!(
        Backend::http(&url("http://x"), None),
        Backend::Http { .. }
    ));
}

#[test]
fn backend_selects_filesystem_locally() {
    let dir = common::fixture_dir();
    let notes = Notes::new(&common::notes_root(&dir), None).unwrap();
    let tasks = Tasks::new(notes.root());
    assert!(matches!(
        Backend::filesystem(notes, tasks),
        Backend::Filesystem { .. }
    ));
}
