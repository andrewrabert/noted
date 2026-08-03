use std::sync::Arc;

use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

use noted::HttpUrl;
use noted_auth::oauth::types::Label;
use noted_auth::oauth::{AuthService, Db, Macaroon};
use noted_auth::AuthState;
use noted_client::credentials::{Credential, CredentialStore};

fn store(dir: &tempfile::TempDir) -> CredentialStore {
    CredentialStore::open_plaintext_at(dir.path().join("hosts.yaml"))
}

fn url(s: &str) -> HttpUrl {
    s.parse().unwrap()
}

fn real_root_macaroon(dir: &tempfile::TempDir) -> Macaroon {
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let svc = Arc::new(AuthService::new(db, noted::types::Ttl::from_secs(3600)));
    let minted = svc
        .key_create(&Label::new("root").unwrap(), noted::Authority::default(), None)
        .unwrap();
    svc.key_finalize(&minted.credential_id).unwrap();
    let router = noted_auth::routes(AuthState::new(svc, None));

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/macaroon/root")
                    .header(
                        "authorization",
                        format!("Bearer {}", minted.token.expose()),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        serde_json::from_value(body["macaroon"].clone()).unwrap()
    })
}

fn cred(dir: &tempfile::TempDir) -> Credential {
    Credential {
        user: Some("ann".into()),
        client_id: "cid-123".into(),
        access_token: "acc-secret".into(),
        refresh_token: Some("ref-secret".into()),
        expires_at: Some(noted::types::UnixEpochSeconds::from_secs(9_999_999_999)),
        root_macaroon: Some(real_root_macaroon(dir)),
    }
}

#[test]
fn round_trips_a_credential() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let c = cred(&dir);
    s.set(&url("https://notes.example/"), &c).unwrap();

    // set uses a trailing slash, get doesn't: exercises URL normalization
    let got = s.get(&url("https://notes.example")).unwrap().unwrap();
    assert_eq!(got.user.as_deref(), Some("ann"));
    assert_eq!(got.client_id, "cid-123");
    assert_eq!(got.access_token.expose(), "acc-secret");
    assert_eq!(
        got.refresh_token.as_ref().map(|t| t.expose()),
        Some("ref-secret")
    );
    assert_eq!(
        got.root_macaroon.as_ref().map(Macaroon::expose),
        c.root_macaroon.as_ref().map(Macaroon::expose)
    );
}

#[test]
fn pointer_file_holds_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let c = cred(&dir);
    let root_macaroon = c.root_macaroon.as_ref().unwrap().expose().to_string();
    store(&dir).set(&url("https://notes.example"), &c).unwrap();
    let hosts = std::fs::read_to_string(dir.path().join("hosts.yaml")).unwrap();
    assert!(hosts.contains("cid-123") && hosts.contains("ann"));
    assert!(!hosts.contains("acc-secret"));
    assert!(!hosts.contains("ref-secret"));
    assert!(!hosts.contains(&root_macaroon));
}

#[test]
fn list_and_remove() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    let c = cred(&dir);
    s.set(&url("https://a.example"), &c).unwrap();
    s.set(&url("https://b.example"), &c).unwrap();
    assert_eq!(s.list().unwrap().len(), 2);

    s.remove(&url("https://a.example")).unwrap();
    let left = s.list().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].url.as_str(), "https://b.example/");
    assert!(s.get(&url("https://a.example")).unwrap().is_none());
}
