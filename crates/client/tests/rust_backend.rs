mod common;

use noted::authorization::Bearer;
use noted::error::NotedError;
use noted::tools::ToolOutput;
use noted::{Backend, BackendArgs, ToolCall, Transport};
use noted_server::http::build_app;
use serde_json::json;

fn open_app(dir: &tempfile::TempDir) -> axum::Router {
    build_app(common::backend(dir), None, None)
}

fn remote(dir: &tempfile::TempDir) -> Backend {
    remote_with_token(dir, None)
}

fn remote_with_token(dir: &tempfile::TempDir, token: Option<&str>) -> Backend {
    Backend::new(BackendArgs {
        url: Some("http://test".to_string()),
        token: token.map(Bearer::new),
        transport: Some(Transport::Router(open_app(dir))),
        ..Default::default()
    })
    .unwrap()
}

async fn invoke(backend: &Backend, name: &str, args: serde_json::Value) -> noted::Result<ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    backend.with_authority(None)?.invoke(&call).await
}

#[tokio::test]
async fn http_success_roundtrip() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let out = invoke(&backend, "WriteNote", json!({"path": "r.md", "content": "hi"}))
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
    let backend = remote(&dir);
    let err = invoke(&backend, "ReadNote", json!({"path": "ghost.md"}))
        .await
        .unwrap_err();
    assert!(matches!(err, NotedError::NotFound), "{err:?}");
}

#[tokio::test]
async fn http_invalid_pattern_maps_from_4xx() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let err = invoke(
        &backend,
        "SearchNotes",
        json!({"pattern": "(", "mode": "line"}),
    )
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
    let svc = common::auth_service(&dir);
    let token = common::mint_key(&svc, "test", noted::Authority::default());
    let authed_app = build_app(common::backend(&dir), Some(svc), None);

    let ok_backend = Backend::new(BackendArgs {
        url: Some("http://test".to_string()),
        token: Some(Bearer::new(token)),
        transport: Some(Transport::Router(authed_app.clone())),
        ..Default::default()
    })
    .unwrap();
    let ok = invoke(&ok_backend, "ReadNote", json!({"path": "Inbox.md"}))
        .await
        .unwrap();
    assert!(ok.render().contains("# Inbox"));

    let bad_backend = Backend::new(BackendArgs {
        url: Some("http://test".to_string()),
        token: Some(Bearer::new("noted_key_wrong")),
        transport: Some(Transport::Router(authed_app)),
        ..Default::default()
    })
    .unwrap();
    let err = invoke(&bad_backend, "ReadNote", json!({"path": "Inbox.md"}))
        .await
        .unwrap_err();
    assert!(matches!(err, NotedError::InvalidInput(_)), "{err:?}");
}

#[tokio::test]
async fn http_log_records_the_servers_provenance() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let out = invoke(&backend, "LogNote", json!({"body": "hi\n-- t · s"}))
        .await
        .unwrap();
    let ToolOutput::Logged { path } = &out else {
        panic!("expected a log receipt, got {}", out.render());
    };
    let text = std::fs::read_to_string(common::notes_root(&dir).join("Log").join(path.to_string()))
        .unwrap();
    assert!(text.contains("source: test"), "{text}");
}

fn canned(status: u16, body: &'static str) -> axum::Router {
    use axum::http::StatusCode;
    use axum::routing::post;
    axum::Router::new().route(
        "/tool/{name}",
        post(move || async move { (StatusCode::from_u16(status).unwrap(), body) }),
    )
}

async fn invoke_canned(status: u16, body: &'static str) -> Result<ToolOutput, NotedError> {
    let backend = Backend::new(BackendArgs {
        url: Some("http://x".to_string()),
        transport: Some(Transport::Router(canned(status, body))),
        ..Default::default()
    })
    .unwrap();
    invoke(&backend, "ReadNote", json!({"path": "a.md"})).await
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

#[tokio::test]
async fn search_path_mode_lists_every_note_for_the_picker() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let out = invoke(
        &backend,
        "SearchNotes",
        json!({"mode": "path", "pattern": "."}),
    )
    .await
    .unwrap();
    let text = out.render();
    let paths: Vec<&str> = text.lines().collect();
    assert!(paths.contains(&"Inbox.md"));
    assert!(paths.contains(&"projects/ideas.md"));
    assert!(
        !paths.iter().any(|p| p.starts_with("Log/")),
        "the picker offers the open region only, never the log"
    );
}
