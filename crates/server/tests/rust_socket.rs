#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};

use noted::authorization::Bearer;
use noted::tools::ReadArgs;
use noted::{Backend, BackendArgs, PolicyFragment, ToolCall};
use noted_server::http::build_app;
use noted_server::socket::bind_unix_socket;

async fn serve(dir: &tempfile::TempDir) -> (PathBuf, String) {
    let svc = common::auth_service(dir);
    let token = common::mint_key(&svc, "test", PolicyFragment::default());
    let sock = dir.path().join("noted.sock");
    let (listener, guard) = bind_unix_socket(&sock).unwrap();
    let app = build_app(common::backend(dir), Some(svc), None);
    tokio::spawn(async move {
        let _guard = guard;
        let _ = axum::serve(listener, app).await;
    });
    (sock, token)
}

fn dialing(sock: &Path, token: &str) -> Backend {
    Backend::new(BackendArgs {
        endpoint: Some(format!("unix://{}", sock.display()).parse().unwrap()),
        token: Some(Bearer::new(token)),
        ..Default::default()
    })
    .unwrap()
}

#[tokio::test]
async fn tools_round_trip_over_a_unix_socket() {
    let dir = common::fixture_dir();
    let (sock, token) = serve(&dir).await;
    let backend = dialing(&sock, &token);
    let call = ToolCall::new(ReadArgs::new(common::rp("Inbox.md"))).unwrap();
    let out = backend
        .with_authority(None)
        .unwrap()
        .invoke(&call)
        .await
        .unwrap();
    assert!(out.render().contains("follow up with Dana"));
}

#[tokio::test]
async fn an_unknown_bearer_is_refused_over_the_socket() {
    let dir = common::fixture_dir();
    let (sock, _token) = serve(&dir).await;
    let backend = dialing(&sock, "not-a-token");
    let call = ToolCall::new(ReadArgs::new(common::rp("Inbox.md"))).unwrap();
    let err = backend
        .with_authority(None)
        .unwrap()
        .invoke(&call)
        .await
        .unwrap_err();
    assert!(err.is_rejection(), "{err}");
}

#[tokio::test]
async fn the_socket_file_is_unlinked_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    let bound = bind_unix_socket(&sock).unwrap();
    assert!(sock.exists());
    drop(bound);
    assert!(!sock.exists());
}

#[tokio::test]
async fn an_occupied_path_refuses_to_bind_and_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("occupied");
    std::fs::write(&path, b"payload").unwrap();

    let err = bind_unix_socket(&path).unwrap_err();
    assert!(err.is_rejection(), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), b"payload");
}

#[tokio::test]
async fn a_socket_left_by_an_unclean_stop_refuses_the_next_bind() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("noted.sock");
    let (dead, guard) = bind_unix_socket(&sock).unwrap();
    std::mem::forget(guard);
    drop(dead);
    assert!(sock.exists());

    let err = bind_unix_socket(&sock).unwrap_err();
    assert!(err.is_rejection(), "{err}");
}
