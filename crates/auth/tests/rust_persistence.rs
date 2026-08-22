use std::sync::Arc;

use noted::PolicyFragment;
use noted::types::Ttl;
use noted_auth::authority::{Mint, Minter, OriginAuthority, Revoke, Verified};
use noted_auth::oauth::{
    AuthorizationRequest, BeginAuthorizationOutcome, OAuthProtocol, RegisterOAuthClient,
};
use noted_auth::types::{
    AuthorizationResponseType, ClientId, CodeChallenge, CodeChallengeMethod, Owner, Password,
    RedirectUri, SubmittedRedirectUri, Username,
};
use noted_auth::{AuthService, Db};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};

const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
const REFRESH: TableDefinition<&str, &[u8]> = TableDefinition::new("refresh");
const MINTED: TableDefinition<&str, &[u8]> = TableDefinition::new("minted");
const ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("roots");
const REVOKED: TableDefinition<&str, u64> = TableDefinition::new("revoked");
const OAUTH_CLIENTS: TableDefinition<&str, &str> = TableDefinition::new("clients");
fn open(path: &std::path::Path) -> Arc<AuthService> {
    Arc::new(AuthService::new(
        Arc::new(Db::open(path).unwrap()),
        Ttl::from_secs(3600),
    ))
}

fn registration() -> RegisterOAuthClient {
    RegisterOAuthClient::new(vec![
        RedirectUri::new("https://client.example/callback").unwrap(),
        RedirectUri::new("http://127.0.0.1:8080/return").unwrap(),
    ])
    .unwrap()
}

fn authorization_request(client_id: ClientId) -> AuthorizationRequest {
    AuthorizationRequest::new(
        Some(AuthorizationResponseType::Code),
        Some(client_id),
        Some(SubmittedRedirectUri::submitted(
            "https://client.example/callback",
        )),
        None,
        None,
        Some(CodeChallenge::submitted(
            "0123456789012345678901234567890123456789012",
        )),
        Some(CodeChallengeMethod::S256),
    )
}

fn put_raw_oauth(path: &std::path::Path, key: &str, contents: &str) {
    let database = Database::open(path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(OAUTH_CLIENTS).unwrap();
        table.insert(key, contents).unwrap();
    }
    write.commit().unwrap();
}

fn populate(service: &Arc<AuthService>) {
    let username = Username::new("alice").unwrap();
    service.user_add(&username, &Password::new("pw")).unwrap();
    service
        .issue_login(&username, &ClientId::new("login-client"))
        .unwrap();
    let authority = OriginAuthority::new(service.clone());
    authority
        .mint(
            &Verified::anonymous(),
            &Mint {
                policy: PolicyFragment::default(),
                ttl: Ttl::from_secs(3600),
            },
        )
        .unwrap();
}

#[test]
fn every_auth_table_reopens_without_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    {
        let service = open(&path);
        populate(&service);
    }
    let reopened = open(&path);
    assert_eq!(reopened.user_list().unwrap().len(), 1);
    assert_eq!(reopened.db().all_minted().unwrap().len(), 1);
}

#[test]
fn user_refresh_mint_root_and_revocation_records_keep_their_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    {
        let service = open(&path);
        populate(&service);
    }
    let database = Database::open(&path).unwrap();
    let read = database.begin_read().unwrap();
    assert_eq!(read.open_table(USERS).unwrap().len().unwrap(), 1);
    assert_eq!(read.open_table(REFRESH).unwrap().len().unwrap(), 1);
    assert_eq!(read.open_table(MINTED).unwrap().len().unwrap(), 1);
    assert!(read.open_table(ROOTS).unwrap().len().unwrap() >= 1);
    assert_eq!(read.open_table(REVOKED).unwrap().len().unwrap(), 0);
}

#[test]
fn oauth_records_are_canonical_and_restore_exact_facts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    let protocol = OAuthProtocol::open(open(&path)).unwrap();
    let client = protocol.register_client(registration()).unwrap();
    let expected_id = client.client_id().clone();
    let expected_issued_at = client.issued_at();
    let expected_redirects = client
        .redirect_uris()
        .iter()
        .map(|redirect| redirect.as_str().to_owned())
        .collect::<Vec<_>>();
    drop(protocol);

    let database = Database::open(&path).unwrap();
    let read = database.begin_read().unwrap();
    let table = read.open_table(OAUTH_CLIENTS).unwrap();
    let stored = table.get(expected_id.as_str()).unwrap().unwrap();
    let value: serde_json::Value = serde_json::from_str(stored.value()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "client_id": expected_id.as_str(),
            "redirect_uris": expected_redirects,
            "client_id_issued_at": expected_issued_at.as_secs(),
        })
    );
    drop(stored);
    drop(table);
    drop(read);
    drop(database);

    let restored = OAuthProtocol::open(open(&path)).unwrap();
    assert!(matches!(
        restored.begin_authorization(authorization_request(expected_id)),
        BeginAuthorizationOutcome::LoginRequired(_)
    ));
}

#[test]
fn authentication_open_accepts_canonical_oauth_client_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    drop(open(&path));
    put_raw_oauth(
        &path,
        "client",
        r#"{"client_id":"client","redirect_uris":["https://client.example/callback"],"client_id_issued_at":1}"#,
    );

    let database = Arc::new(Db::open(&path).unwrap());
    let protocol =
        OAuthProtocol::open(Arc::new(AuthService::new(database, Ttl::from_secs(3600)))).unwrap();
    assert!(matches!(
        protocol.begin_authorization(authorization_request(ClientId::new("client"))),
        BeginAuthorizationOutcome::LoginRequired(_)
    ));
}

#[test]
fn authentication_open_rejects_malformed_incomplete_obsolete_and_legacy_oauth_records() {
    let cases = [
        ("malformed", "{"),
        (
            "incomplete",
            r#"{"client_id":"client","redirect_uris":["https://client.example/callback"]}"#,
        ),
        (
            "identity-less",
            r#"{"redirect_uris":["https://client.example/callback"],"client_id_issued_at":1}"#,
        ),
        (
            "obsolete",
            r#"{"client_id":"client","redirect_uris":["https://client.example/callback"],"client_id_issued_at":1,"client_secret":"obsolete"}"#,
        ),
        (
            "legacy",
            r#"{"client_id":"client","redirect_uri":"https://client.example/callback","client_id_issued_at":1}"#,
        ),
        (
            "metadata-bearing",
            r#"{"client_id":"client","redirect_uris":["https://client.example/callback"],"client_id_issued_at":1,"client_name":"metadata"}"#,
        ),
    ];

    for (name, contents) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.redb");
        drop(open(&path));
        put_raw_oauth(&path, "client", contents);
        assert!(Db::open(&path).is_err(), "{name} record opened");
    }
}

#[test]
fn authentication_open_rejects_matching_empty_oauth_client_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    drop(open(&path));
    put_raw_oauth(
        &path,
        "",
        r#"{"client_id":"","redirect_uris":["https://client.example/callback"],"client_id_issued_at":1}"#,
    );

    assert!(Db::open(&path).is_err());
}

#[test]
fn authentication_open_rejects_mismatched_empty_non_string_and_invalid_redirect_records() {
    let cases = [
        (
            "mismatched",
            r#"{"client_id":"different","redirect_uris":["https://client.example/callback"],"client_id_issued_at":1}"#,
        ),
        (
            "empty",
            r#"{"client_id":"client","redirect_uris":[],"client_id_issued_at":1}"#,
        ),
        (
            "non-string",
            r#"{"client_id":"client","redirect_uris":[1],"client_id_issued_at":1}"#,
        ),
        (
            "invalid",
            r#"{"client_id":"client","redirect_uris":["not a url"],"client_id_issued_at":1}"#,
        ),
    ];

    for (name, contents) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.redb");
        drop(open(&path));
        put_raw_oauth(&path, "client", contents);
        assert!(Db::open(&path).is_err(), "{name} record opened");
    }
}

#[test]
fn every_auth_table_including_oauth_reopens_together() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    {
        let service = open(&path);
        populate(&service);
        OAuthProtocol::open(service.clone())
            .unwrap()
            .register_client(registration())
            .unwrap();
    }
    let reopened = open(&path);
    assert_eq!(reopened.user_list().unwrap().len(), 1);
    assert_eq!(reopened.db().all_minted().unwrap().len(), 1);
    assert!(OAuthProtocol::open(reopened).is_ok());
}

#[test]
fn refresh_rotation_user_removal_and_withdrawal_remain_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    let service = open(&path);
    populate(&service);
    let username = Username::new("alice").unwrap();
    let first = service
        .issue_login(&username, &ClientId::new("rotation"))
        .unwrap();
    let second = service
        .rotate_login(&first.refresh, &username, &ClientId::new("rotation"))
        .unwrap();
    assert!(service.refresh_owner(&first.refresh).unwrap().is_none());
    assert!(service.refresh_owner(&second.refresh).unwrap().is_some());
    let authority = OriginAuthority::new(service.clone());
    authority
        .revoke(
            &Verified::as_owner(Owner::User(username.clone())),
            &Revoke::All,
        )
        .unwrap();
    assert!(service.refresh_owner(&second.refresh).unwrap().is_none());
    service.user_remove(&username).unwrap();
    assert!(service.user_get(&username).unwrap().is_none());
}

#[test]
fn reopen_then_write_preserves_table_names_keys_and_value_encodings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    {
        let service = open(&path);
        populate(&service);
    }
    {
        let service = open(&path);
        service
            .user_add(&Username::new("bob").unwrap(), &Password::new("pw"))
            .unwrap();
    }
    let database = Database::open(&path).unwrap();
    let read = database.begin_read().unwrap();
    let users = read.open_table(USERS).unwrap();
    assert!(users.get("alice").unwrap().is_some());
    assert!(users.get("bob").unwrap().is_some());
}
