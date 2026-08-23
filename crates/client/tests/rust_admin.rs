#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::administration::{AdminCommand, AdminOutcome, Administration};
use noted_auth::authority::OriginAuthority;
use noted_auth::types::{Password, Username};
use noted_auth::{AuthService, Db};
use noted_client::admin::AdminConnection;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn scripted_peer(
    dir: &tempfile::TempDir,
    exchanges: Vec<(String, String)>,
) -> (PathBuf, tokio::task::JoinHandle<()>) {
    let path = dir.path().join("admin.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        for (expected, response) in exchanges {
            assert_eq!(lines.next_line().await.unwrap().unwrap(), expected);
            write.write_all(response.as_bytes()).await.unwrap();
            write.write_all(b"\n").await.unwrap();
        }
    });
    (path, task)
}

fn add(name: &str) -> AdminCommand {
    AdminCommand::AddUser {
        username: Username::new(name).unwrap(),
        password: Password::new("pw"),
    }
}

fn every_command() -> Vec<(AdminCommand, &'static str, &'static str)> {
    vec![
        (
            add("alice"),
            r#"{"op":"user_add","name":"alice","password":"pw"}"#,
            r#"{"ok":{}}"#,
        ),
        (
            AdminCommand::ReplaceUserPassword {
                username: Username::new("alice").unwrap(),
                password: Password::new("new"),
            },
            r#"{"op":"user_passwd","name":"alice","password":"new"}"#,
            r#"{"ok":{}}"#,
        ),
        (
            AdminCommand::ReplaceUserPolicy {
                username: Username::new("alice").unwrap(),
                policy: PolicyFragment::default(),
            },
            r#"{"op":"user_set_policy","name":"alice","policy":{}}"#,
            r#"{"ok":{}}"#,
        ),
        (
            AdminCommand::ListUsers,
            r#"{"op":"user_list"}"#,
            r#"{"ok":[]}"#,
        ),
        (
            AdminCommand::GetUser {
                username: Username::new("alice").unwrap(),
            },
            r#"{"op":"user_get","name":"alice"}"#,
            r#"{"ok":{"user":{"name":"alice","policy":{},"created_at":1},"credentials":[]}}"#,
        ),
        (
            AdminCommand::RemoveUser {
                username: Username::new("alice").unwrap(),
            },
            r#"{"op":"user_remove","name":"alice"}"#,
            r#"{"ok":{}}"#,
        ),
        (
            AdminCommand::CreateKey {
                policy: PolicyFragment::default(),
            },
            r#"{"op":"key_create","policy":{}}"#,
            r#"{"error":{"kind":"rejected","message":"fixture"}}"#,
        ),
        (
            AdminCommand::ListKeys,
            r#"{"op":"key_list"}"#,
            r#"{"ok":[]}"#,
        ),
    ]
}

async fn minted_response(path: &Path) -> Value {
    let auth_db = path.join("mint.redb");
    tokio::task::spawn_blocking(move || {
        let service = Arc::new(AuthService::new(Arc::new(Db::open(&auth_db).unwrap())));
        let authority = Arc::new(OriginAuthority::new(service.clone()));
        let admin = Administration::new(service, authority);
        let AdminOutcome::Minted(minted) = admin
            .execute(AdminCommand::CreateKey {
                policy: PolicyFragment::default(),
            })
            .unwrap()
        else {
            panic!("minted outcome")
        };
        json!({
            "ok": {
                "macaroon": minted.macaroon.expose(),
                "token_id": minted.token_id,
                "fingerprint": minted.fingerprint,
            }
        })
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn every_command_has_the_exact_admin_request_json() {
    let dir = tempfile::tempdir().unwrap();
    let commands = every_command();
    let exchanges = commands
        .iter()
        .map(|(_, request, response)| ((*request).to_string(), (*response).to_string()))
        .collect();
    let (socket, peer) = scripted_peer(&dir, exchanges).await;
    let mut connection = AdminConnection::open(Some(&socket), None).await.unwrap();
    for (command, _, _) in commands {
        let _ = connection.call(command).await;
    }
    peer.await.unwrap();
}

#[tokio::test]
async fn every_admin_response_decodes_to_the_typed_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let minted = minted_response(dir.path()).await;
    let exchanges = vec![
        (
            r#"{"op":"user_add","name":"alice","password":"pw"}"#.to_string(),
            r#"{"ok":{}}"#.to_string(),
        ),
        (
            r#"{"op":"user_list"}"#.to_string(),
            r#"{"ok":[{"name":"alice","policy":{},"created_at":1}]}"#.to_string(),
        ),
        (
            r#"{"op":"user_get","name":"alice"}"#.to_string(),
            r#"{"ok":{"user":{"name":"alice","policy":{},"created_at":1},"credentials":[]}}"#
                .to_string(),
        ),
        (
            r#"{"op":"key_create","policy":{}}"#.to_string(),
            minted.to_string(),
        ),
        (
            r#"{"op":"key_list"}"#.to_string(),
            r#"{"ok":[]}"#.to_string(),
        ),
    ];
    let (socket, peer) = scripted_peer(&dir, exchanges).await;
    let mut connection = AdminConnection::open(Some(&socket), None).await.unwrap();

    assert!(matches!(
        connection.call(add("alice")).await.unwrap(),
        AdminOutcome::Completed
    ));
    let AdminOutcome::Users(users) = connection.call(AdminCommand::ListUsers).await.unwrap() else {
        panic!("users outcome")
    };
    assert_eq!(users[0].name.as_str(), "alice");
    let AdminOutcome::User(details) = connection
        .call(AdminCommand::GetUser {
            username: Username::new("alice").unwrap(),
        })
        .await
        .unwrap()
    else {
        panic!("user outcome")
    };
    assert_eq!(details.user.name.as_str(), "alice");
    let AdminOutcome::Minted(minted) = connection
        .call(AdminCommand::CreateKey {
            policy: PolicyFragment::default(),
        })
        .await
        .unwrap()
    else {
        panic!("minted outcome")
    };
    assert!(minted.macaroon.expose().starts_with("noted_mac_"));
    assert!(matches!(
        connection.call(AdminCommand::ListKeys).await.unwrap(),
        AdminOutcome::Credentials(credentials) if credentials.is_empty()
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn response_error_kinds_and_messages_are_exact() {
    let dir = tempfile::tempdir().unwrap();
    let exchanges = vec![
        (
            r#"{"op":"user_list"}"#.to_string(),
            r#"{"error":{"kind":"rejected","message":"denied exactly"}}"#.to_string(),
        ),
        (
            r#"{"op":"user_list"}"#.to_string(),
            r#"{"error":{"kind":"unavailable","message":"offline exactly"}}"#.to_string(),
        ),
    ];
    let (socket, peer) = scripted_peer(&dir, exchanges).await;
    let mut connection = AdminConnection::open(Some(&socket), None).await.unwrap();
    let rejected = connection.call(AdminCommand::ListUsers).await.unwrap_err();
    assert!(rejected.is_rejection());
    assert_eq!(rejected.message(), "denied exactly");
    let unavailable = connection.call(AdminCommand::ListUsers).await.unwrap_err();
    assert!(!unavailable.is_rejection());
    assert_eq!(unavailable.message(), "offline exactly");
    peer.await.unwrap();
}

#[tokio::test]
async fn one_socket_connection_performs_sequential_calls() {
    let dir = tempfile::tempdir().unwrap();
    let exchanges = vec![
        (
            r#"{"op":"user_add","name":"alice","password":"pw"}"#.to_string(),
            r#"{"ok":{}}"#.to_string(),
        ),
        (
            r#"{"op":"user_list"}"#.to_string(),
            r#"{"ok":[{"name":"alice","policy":{},"created_at":1}]}"#.to_string(),
        ),
    ];
    let (socket, peer) = scripted_peer(&dir, exchanges).await;
    let mut connection = AdminConnection::open(Some(&socket), None).await.unwrap();
    assert!(matches!(
        connection.call(add("alice")).await.unwrap(),
        AdminOutcome::Completed
    ));
    assert!(matches!(
        connection.call(AdminCommand::ListUsers).await.unwrap(),
        AdminOutcome::Users(users) if users.len() == 1
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn a_live_socket_is_selected_before_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let (socket, peer) = scripted_peer(&dir, Vec::new()).await;
    let connection = AdminConnection::open(Some(&socket), Some(Path::new("/")))
        .await
        .unwrap();
    drop(connection);
    peer.await.unwrap();
}

#[tokio::test]
async fn an_unreachable_socket_falls_back_to_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let auth_db = dir.path().join("auth.redb");
    let mut connection =
        AdminConnection::open(Some(&dir.path().join("missing.sock")), Some(&auth_db))
            .await
            .unwrap();
    assert!(matches!(
        connection.call(AdminCommand::ListUsers).await.unwrap(),
        AdminOutcome::Users(users) if users.is_empty()
    ));
}

#[tokio::test]
async fn an_unreachable_socket_without_a_database_keeps_the_connect_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = match AdminConnection::open(Some(&dir.path().join("missing.sock")), None).await {
        Ok(_) => panic!("expected the missing socket to fail"),
        Err(error) => error,
    };
    assert!(error.message().contains("admin socket: connect"));
}

#[tokio::test]
async fn absent_socket_and_database_keep_the_existing_requirement_error() {
    let error = match AdminConnection::open(None, None).await {
        Ok(_) => panic!("expected missing administration inputs to fail"),
        Err(error) => error,
    };
    assert_eq!(
        error.message(),
        "an admin socket or an auth database is required"
    );
}

#[tokio::test]
async fn a_missing_direct_database_parent_fails_without_creation() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("missing");
    let auth_db = parent.join("auth.redb");
    let error = match AdminConnection::open(None, Some(&auth_db)).await {
        Ok(_) => panic!("expected the missing database parent to fail"),
        Err(error) => error,
    };
    assert!(error.is_rejection());
    assert!(
        error
            .message()
            .contains("if the server is running, connect to its admin socket")
    );
    assert!(!parent.exists());
}

#[tokio::test]
async fn an_unreachable_direct_database_keeps_the_server_running_hint() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("not-a-directory");
    std::fs::write(&parent, "occupied").unwrap();
    let auth_db = parent.join("auth.redb");
    let error = match AdminConnection::open(None, Some(&auth_db)).await {
        Ok(_) => panic!("expected the unreachable database to fail"),
        Err(error) => error,
    };
    assert!(
        error
            .message()
            .contains("if the server is running, connect to its admin socket")
    );
}

#[tokio::test]
async fn a_locked_direct_database_keeps_the_server_running_hint() {
    let dir = tempfile::tempdir().unwrap();
    let auth_db = dir.path().join("auth.redb");
    let locked_path = auth_db.clone();
    let locked = tokio::task::spawn_blocking(move || Db::open(&locked_path).unwrap())
        .await
        .unwrap();
    let error = match AdminConnection::open(None, Some(&auth_db)).await {
        Ok(_) => panic!("expected the locked database to fail"),
        Err(error) => error,
    };
    assert!(
        error
            .message()
            .contains("if the server is running, connect to its admin socket")
    );
    drop(locked);
}
