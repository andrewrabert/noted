mod common;

use noted::error::NotedError;
use noted::tools::ToolOutput;
use noted::{Backend, BackendArgs, Bearer, ToolCall, Transport};
use serde_json::json;

fn dialing(router: axum::Router, token: Option<&str>) -> Backend {
    Backend::new(BackendArgs::Remote {
        endpoint: "http://test".parse().unwrap(),
        bearer: token.map(Bearer::new),
        transport: Transport::Router(router),
    })
    .unwrap()
}

fn remote(dir: &tempfile::TempDir) -> Backend {
    dialing(common::open_app(dir), None)
}

async fn invoke(
    backend: &Backend,
    name: &str,
    args: serde_json::Value,
) -> noted::Result<ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    backend.invoke(&call).await
}

#[tokio::test]
async fn client_http_success_roundtrip() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let out = invoke(
        &backend,
        "WriteNote",
        json!({"path": "r.md", "content": "hi"}),
    )
    .await
    .unwrap();
    assert_eq!(out.render(), "wrote r.md");
    assert_eq!(
        std::fs::read_to_string(common::notes_root(&dir).join("r.md")).unwrap(),
        "hi"
    );
}

#[tokio::test]
async fn client_http_missing_note_maps_to_not_found() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let err = invoke(&backend, "ReadNote", json!({"path": "ghost.md"}))
        .await
        .unwrap_err();
    assert!(matches!(err, NotedError::NotFound), "{err:?}");
}

#[tokio::test]
async fn client_http_invalid_pattern_maps_from_4xx() {
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
async fn client_http_sends_and_checks_bearer_token() {
    let dir = common::fixture_dir();
    let svc = common::auth_service(&dir);
    let token = common::mint_key(&svc, noted::PolicyFragment::default());
    let authed_app = common::origin_app(common::root(&dir), &svc).await;

    let ok_backend = dialing(authed_app.clone(), Some(&token));
    let ok = invoke(&ok_backend, "ReadNote", json!({"path": "Inbox.md"}))
        .await
        .unwrap();
    assert!(ok.render().contains("# Inbox"));

    let bad_backend = dialing(authed_app, Some("noted_key_wrong"));
    let err = invoke(&bad_backend, "ReadNote", json!({"path": "Inbox.md"}))
        .await
        .unwrap_err();
    assert!(matches!(err, NotedError::InvalidInput(_)), "{err:?}");
}

#[tokio::test]
async fn client_http_log_records_the_servers_provenance() {
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

#[tokio::test]
async fn client_search_path_mode_lists_every_open_note() {
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

#[cfg(unix)]
#[test]
fn client_socket_endpoint_refuses_an_in_process_router() {
    let dir = common::fixture_dir();
    let result = Backend::new(BackendArgs::Remote {
        endpoint: "unix:///run/noted.sock".parse().unwrap(),
        bearer: None,
        transport: Transport::Router(common::open_app(&dir)),
    });
    let Err(err) = result else {
        panic!("expected a socket endpoint to refuse a router");
    };
    let NotedError::InvalidInput(msg) = &err else {
        panic!("expected InvalidInput, got {err:?}");
    };
    assert!(msg.contains("in-process router"), "{msg}");
}
