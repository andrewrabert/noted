use std::path::PathBuf;
use std::sync::Arc;

use noted::types::Ttl;
use noted_auth::administration::Administration;
use noted_auth::authority::OriginAuthority;
use noted_auth::{AuthService, Db};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

async fn spawn(dir: &tempfile::TempDir) -> (PathBuf, tokio::task::JoinHandle<()>) {
    let auth_db = dir.path().join("auth.redb");
    let service = Arc::new(AuthService::new(
        Arc::new(Db::open(&auth_db).unwrap()),
        Ttl::from_secs(3600),
    ));
    let authority = Arc::new(OriginAuthority::new(service.clone()));
    let path = dir.path().join("admin.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(super::serve_socket(
        listener,
        Administration::new(service, authority),
    ));
    (path, task)
}

async fn line(stream: &mut BufReader<UnixStream>, request: &str) -> String {
    stream
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .unwrap();
    stream.get_mut().write_all(b"\n").await.unwrap();
    let mut response = String::new();
    stream.read_line(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn every_operation_round_trips_with_exact_request_and_response_json() {
    let dir = tempfile::tempdir().unwrap();
    let (path, task) = spawn(&dir).await;
    let mut stream = BufReader::new(UnixStream::connect(path).await.unwrap());
    assert_eq!(
        line(
            &mut stream,
            r#"{"op":"user_add","name":"alice","password":"pw"}"#
        )
        .await,
        "{\"ok\":{}}\n"
    );
    assert!(
        line(&mut stream, r#"{"op":"user_list"}"#)
            .await
            .starts_with("{\"ok\":[{")
    );
    assert!(
        line(&mut stream, r#"{"op":"user_get","name":"alice"}"#)
            .await
            .contains("\"credentials\":[]")
    );
    assert_eq!(
        line(
            &mut stream,
            r#"{"op":"user_passwd","name":"alice","password":"new"}"#
        )
        .await,
        "{\"ok\":{}}\n"
    );
    assert_eq!(
        line(
            &mut stream,
            r#"{"op":"user_set_policy","name":"alice","policy":{}}"#
        )
        .await,
        "{\"ok\":{}}\n"
    );
    assert!(
        line(
            &mut stream,
            r#"{"op":"key_create","label":"agent","policy":{},"ttl":null}"#
        )
        .await
        .contains("noted_mac_")
    );
    assert!(
        line(&mut stream, r#"{"op":"key_list","label":null}"#)
            .await
            .starts_with("{\"ok\":[{")
    );
    assert!(
        line(&mut stream, r#"{"op":"key_revoke","by":{"Label":"agent"}}"#)
            .await
            .contains("\"revoked\":")
    );
    assert!(
        line(&mut stream, r#"{"op":"user_revoke","name":"alice"}"#)
            .await
            .contains("\"epoch\":")
    );
    assert_eq!(
        line(&mut stream, r#"{"op":"user_remove","name":"alice"}"#).await,
        "{\"ok\":{}}\n"
    );
    task.abort();
}

#[tokio::test]
async fn blank_lines_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let (path, task) = spawn(&dir).await;
    let mut stream = BufReader::new(UnixStream::connect(path).await.unwrap());
    stream
        .get_mut()
        .write_all(b"\n  \n{\"op\":\"user_list\"}\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_line(&mut response).await.unwrap();
    assert_eq!(response, "{\"ok\":[]}\n");
    task.abort();
}

#[tokio::test]
async fn sequential_requests_reuse_one_connection_and_keep_order() {
    let dir = tempfile::tempdir().unwrap();
    let (path, task) = spawn(&dir).await;
    let mut stream = BufReader::new(UnixStream::connect(path).await.unwrap());
    assert_eq!(
        line(
            &mut stream,
            r#"{"op":"user_add","name":"alice","password":"pw"}"#
        )
        .await,
        "{\"ok\":{}}\n"
    );
    assert!(
        line(&mut stream, r#"{"op":"user_list"}"#)
            .await
            .contains("alice")
    );
    task.abort();
}

#[tokio::test]
async fn domain_errors_do_not_close_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (path, task) = spawn(&dir).await;
    let mut stream = BufReader::new(UnixStream::connect(path).await.unwrap());
    assert!(
        line(&mut stream, r#"{"op":"user_remove","name":"ghost"}"#)
            .await
            .contains("\"kind\":\"rejected\"")
    );
    assert_eq!(
        line(&mut stream, r#"{"op":"user_list"}"#).await,
        "{\"ok\":[]}\n"
    );
    task.abort();
}

#[tokio::test]
async fn malformed_lines_answer_once_then_close() {
    let dir = tempfile::tempdir().unwrap();
    let (path, task) = spawn(&dir).await;
    let mut stream = BufReader::new(UnixStream::connect(path).await.unwrap());
    let response = line(&mut stream, "not-json").await;
    assert!(response.contains("malformed admin request"));
    let mut next = String::new();
    assert_eq!(stream.read_line(&mut next).await.unwrap(), 0);
    task.abort();
}

#[tokio::test]
async fn concurrent_connections_progress_independently() {
    let dir = tempfile::tempdir().unwrap();
    let (path, task) = spawn(&dir).await;
    let mut first = BufReader::new(UnixStream::connect(&path).await.unwrap());
    let mut second = BufReader::new(UnixStream::connect(&path).await.unwrap());
    let (a, b) = tokio::join!(
        line(&mut first, r#"{"op":"user_list"}"#),
        line(&mut second, r#"{"op":"user_list"}"#)
    );
    assert_eq!(a, "{\"ok\":[]}\n");
    assert_eq!(b, "{\"ok\":[]}\n");
    task.abort();
}

#[tokio::test]
async fn shutdown_cancels_connections_and_guard_cleanup_unlinks_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guarded.sock");
    let (listener, guard) = crate::socket::bind_unix_socket(&path, Some(0o600)).unwrap();
    let auth_db = dir.path().join("auth.redb");
    let service = Arc::new(AuthService::new(
        Arc::new(Db::open(&auth_db).unwrap()),
        Ttl::from_secs(3600),
    ));
    let authority = Arc::new(OriginAuthority::new(service.clone()));
    let task = tokio::spawn(super::serve_socket(
        listener,
        Administration::new(service, authority),
    ));
    let _connection = UnixStream::connect(&path).await.unwrap();
    task.abort();
    let _ = task.await;
    drop(guard);
    assert!(!path.exists());
}

#[tokio::test]
async fn error_kinds_messages_and_serialization_are_byte_compatible() {
    let dir = tempfile::tempdir().unwrap();
    let (path, task) = spawn(&dir).await;
    let mut stream = BufReader::new(UnixStream::connect(path).await.unwrap());
    assert_eq!(
        line(&mut stream, r#"{"op":"user_remove","name":"ghost"}"#).await,
        "{\"error\":{\"kind\":\"rejected\",\"message\":\"no such user: 'ghost'\"}}\n"
    );
    task.abort();
}
