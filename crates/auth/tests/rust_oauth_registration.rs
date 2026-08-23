use std::sync::Arc;

use noted_auth::oauth::{OAuthProtocol, RegisterOAuthClient};
use noted_auth::types::RedirectUri;
use noted_auth::{AuthService, Db};
use redb::{Database, ReadableDatabase, TableDefinition};

const OAUTH_CLIENTS: TableDefinition<&str, &str> = TableDefinition::new("clients");

fn service(path: &std::path::Path) -> Arc<AuthService> {
    Arc::new(AuthService::new(Arc::new(Db::open(path).unwrap())))
}

fn registration() -> RegisterOAuthClient {
    RegisterOAuthClient::new(vec![
        RedirectUri::new("https://client.example/callback").unwrap(),
        RedirectUri::new("http://127.0.0.1:8080/return").unwrap(),
    ])
    .unwrap()
}

fn put_raw_client(path: &std::path::Path, key: &str, value: &str) {
    let database = Database::open(path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(OAUTH_CLIENTS).unwrap();
        table.insert(key, value).unwrap();
    }
    write.commit().unwrap();
}

#[test]
fn registration_persists_before_the_client_enters_the_live_registrar() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    let protocol = OAuthProtocol::open(service(&path)).unwrap();

    let client = protocol.register_client(registration()).unwrap();
    drop(protocol);

    let database = Database::open(&path).unwrap();
    let read = database.begin_read().unwrap();
    let table = read.open_table(OAUTH_CLIENTS).unwrap();
    let stored = table.get(client.client_id().as_str()).unwrap().unwrap();
    let record: serde_json::Value = serde_json::from_str(stored.value()).unwrap();
    assert_eq!(record["client_id"], client.client_id().as_str());
    assert_eq!(
        record["redirect_uris"],
        serde_json::json!([
            "https://client.example/callback",
            "http://127.0.0.1:8080/return"
        ])
    );
}

#[test]
fn a_protocol_restores_every_canonical_registered_client() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    {
        let protocol = OAuthProtocol::open(service(&path)).unwrap();
        protocol.register_client(registration()).unwrap();
        protocol
            .register_client(
                RegisterOAuthClient::new(vec![
                    RedirectUri::new("https://other.example/return").unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
    }

    assert!(OAuthProtocol::open(service(&path)).is_ok());
}

#[test]
fn restoration_rejects_an_invalid_canonical_client_before_protocol_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    drop(service(&path));
    put_raw_client(
        &path,
        "client",
        r#"{"client_id":"client","redirect_uris":[],"client_id_issued_at":1}"#,
    );

    assert!(Db::open(&path).is_err());
}
