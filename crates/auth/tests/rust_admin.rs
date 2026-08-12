use std::path::PathBuf;
use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::oauth::Db;
use noted_auth::oauth::admin::{self, AdminClient, AdminRequest};
use noted_auth::oauth::service::{AuthService, RevokeBy};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

async fn spawn_server(dir: &tempfile::TempDir) -> (PathBuf, Arc<AuthService>) {
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let svc = Arc::new(AuthService::new(
        db,
        noted::types::Ttl::from_secs(30 * 24 * 3600),
    ));
    let sock = dir.path().join("admin.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(admin::serve_socket(listener, svc.clone()));
    (sock, svc)
}

#[tokio::test]
async fn verbs_round_trip_and_two_phase_mint() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, svc) = spawn_server(&dir).await;
    let mut client = AdminClient::connect(&sock).await.unwrap();

    client
        .call(&AdminRequest::UserAdd {
            name: "alice".into(),
            password: "pw".into(),
        })
        .await
        .unwrap();
    let users = client.call(&AdminRequest::UserList).await.unwrap();
    assert_eq!(users.as_array().unwrap().len(), 1);

    let minted = client
        .call(&AdminRequest::KeyCreate {
            label: "agent".into(),
            policy: r#"{"access":{"read":true,"write":false}}"#.parse::<PolicyFragment>().unwrap(),
            ttl: None,
        })
        .await
        .unwrap();
    let token = minted["token"].as_str().unwrap().to_string();
    let id = minted["credential_id"].as_str().unwrap().to_string();
    assert!(svc.resolve_bearer(&token).unwrap().is_none());
    client
        .call(&AdminRequest::KeyFinalize {
            credential_id: id.clone(),
        })
        .await
        .unwrap();
    let (owner, policy) = svc.resolve_bearer(&token).unwrap().unwrap();
    assert_eq!(owner, format!("key:{id}"));
    assert_eq!(
        policy.to_string(),
        r#"{"access":{"read":true,"write":false}}"#
    );

    client
        .call(&AdminRequest::KeySetPolicy {
            label: Some("agent".into()),
            id: None,
            policy: r#"{"access":{"read":true,"write":false},"paths":{"projects":{"read":false,"write":false}}}"#.parse::<PolicyFragment>().unwrap(),
        })
        .await
        .unwrap();
    let (_, policy) = svc.resolve_bearer(&token).unwrap().unwrap();
    assert_eq!(
        policy.to_string(),
        r#"{"access":{"read":true,"write":false},"paths":{"projects":{"read":false,"write":false}}}"#
    );

    let revoked = client
        .call(&AdminRequest::KeyRevoke {
            by: RevokeBy::Label(noted_auth::oauth::types::Label::new("agent").unwrap()),
        })
        .await
        .unwrap();
    assert_eq!(revoked["revoked"], 1);
    assert!(svc.resolve_bearer(&token).unwrap().is_none());
}

#[tokio::test]
async fn domain_errors_keep_the_session_open() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _svc) = spawn_server(&dir).await;
    let mut client = AdminClient::connect(&sock).await.unwrap();

    let err = client
        .call(&AdminRequest::UserRemove {
            name: "ghost".into(),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no such user"));

    client
        .call(&AdminRequest::UserAdd {
            name: "bob".into(),
            password: "pw".into(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn malformed_line_answers_then_closes() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _svc) = spawn_server(&dir).await;
    let stream = UnixStream::connect(&sock).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    write.write_all(b"this is not json\n").await.unwrap();
    let resp = lines.next_line().await.unwrap().unwrap();
    assert!(resp.contains("\"error\"") && resp.contains("malformed"));
    assert!(lines.next_line().await.unwrap().is_none());
}

#[tokio::test]
async fn redb_lock_arbitrates_direct_access() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    let _held = Db::open(&path).unwrap();
    assert!(Db::open(&path).is_err());
}
