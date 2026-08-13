use std::path::PathBuf;
use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::Db;
use noted_auth::admin::{self, Admin, AdminClient, AdminRequest};
use noted_auth::authority::{OriginAuthority, Revoke, Verifier};
use noted_auth::service::AuthService;
use noted_auth::types::Label;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

async fn spawn_server(
    dir: &tempfile::TempDir,
) -> (PathBuf, Arc<AuthService>, Arc<OriginAuthority>) {
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let svc = Arc::new(AuthService::new(
        db,
        noted::types::Ttl::from_secs(30 * 24 * 3600),
    ));
    let authority = Arc::new(OriginAuthority::new(svc.clone()));
    let sock = dir.path().join("admin.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(admin::serve_socket(
        listener,
        Admin::new(svc.clone(), authority.clone()),
    ));
    (sock, svc, authority)
}

#[tokio::test]
async fn verbs_round_trip_and_a_key_is_minted_live() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _svc, authority) = spawn_server(&dir).await;
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
    let token = minted["macaroon"].as_str().unwrap().to_string();
    assert!(token.starts_with("noted_mac_"));

    // a key is live the moment it is minted: no second phase
    let verified = authority.verify(Some(&token)).unwrap();
    assert!(
        verified
            .fragments()
            .iter()
            .any(|f| f.to_string() == r#"{"access":{"read":true,"write":false}}"#)
    );

    let listed = client
        .call(&AdminRequest::KeyList {
            label: Some("agent".into()),
        })
        .await
        .unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);

    let revoked = client
        .call(&AdminRequest::KeyRevoke {
            by: Revoke::Label(Label::new("agent").unwrap()),
        })
        .await
        .unwrap();
    assert_eq!(
        revoked["revoked"],
        serde_json::json!([format!("token_id={}", minted["token_id"].as_str().unwrap())])
    );
    assert!(authority.verify(Some(&token)).is_err());
}

#[tokio::test]
async fn domain_errors_keep_the_session_open() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _svc, _authority) = spawn_server(&dir).await;
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
    let (sock, _svc, _authority) = spawn_server(&dir).await;
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
