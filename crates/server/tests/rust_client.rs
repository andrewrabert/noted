mod common;

use noted::Bearer;
use noted::error::NotedError;
use noted::tools::Tools as _;
use noted_client::{Backend, BackendArgs, Transport};
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

#[tokio::test]
async fn client_http_success_roundtrip() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    backend
        .write_note(serde_json::from_value(json!({"path": "/r.md", "content": "hi"})).unwrap())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(common::notes_root(&dir).join("r.md")).unwrap(),
        "hi"
    );
}

#[tokio::test]
async fn client_http_missing_note_maps_to_not_found() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let err = backend
        .read_note(serde_json::from_value(json!({"path": "/ghost.md"})).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, NotedError::NotFound), "{err:?}");
}

#[tokio::test]
async fn client_http_invalid_pattern_maps_from_4xx() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let err = backend
        .search_notes(serde_json::from_value(json!({"pattern": "(", "mode": "line"})).unwrap())
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
    let ok = ok_backend
        .read_note(serde_json::from_value(json!({"path": "/Inbox.md"})).unwrap())
        .await
        .unwrap();
    assert!(ok.body().as_str().contains("# Inbox"));

    let bad_backend = dialing(authed_app, Some("noted_key_wrong"));
    let err = bad_backend
        .read_note(serde_json::from_value(json!({"path": "/Inbox.md"})).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, NotedError::InvalidInput(_)), "{err:?}");
}

#[tokio::test]
async fn client_http_log_records_the_servers_provenance() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let entry = backend
        .log_note(serde_json::from_value(json!({"body": "hi\n-- t · s"})).unwrap())
        .await
        .unwrap();
    let path = entry.path();
    let logs = common::notes_root(&dir).join(".logs");
    let fresh: Vec<_> = std::fs::read_dir(&logs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| !p.to_string_lossy().contains(".000000-0700"))
        .collect();
    let [entry] = fresh.as_slice() else {
        panic!("one new entry expected for {path}, found {fresh:?}");
    };
    let text = std::fs::read_to_string(entry.join(".log.md")).unwrap();
    assert!(text.contains("source: test"), "{text}");
}

#[tokio::test]
async fn client_search_path_mode_lists_every_open_note() {
    let dir = common::fixture_dir();
    let backend = remote(&dir);
    let hits = backend
        .search_notes(serde_json::from_value(json!({"mode": "path", "pattern": "."})).unwrap())
        .await
        .unwrap();
    let texts: Vec<String> = hits.iter().map(|hit| hit.path.to_string()).collect();
    let paths: Vec<&str> = texts.iter().map(String::as_str).collect();
    assert!(paths.contains(&"/Inbox.md"));
    assert!(paths.contains(&"/projects/ideas.md"));
    assert!(
        !paths.iter().any(|p| p.starts_with("/.logs/")),
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
