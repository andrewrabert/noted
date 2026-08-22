use noted::Bearer;
use noted::HttpUrl;
use noted::types::UnixEpochSeconds;
use noted_auth::types::{ClientId, RefreshToken};
use noted_client::credentials::{Credential, CredentialStore};

fn store(dir: &tempfile::TempDir) -> CredentialStore {
    CredentialStore::open_plaintext_at(dir.path().join("hosts.json"))
}

fn url(s: &str) -> HttpUrl {
    s.parse().unwrap()
}

fn cred() -> Credential {
    Credential {
        user: Some("ann".into()),
        client_id: ClientId::new("cid-123"),
        access_token: Bearer::new("acc-secret"),
        refresh_token: Some(RefreshToken::new("ref-secret")),
        expires_at: Some(UnixEpochSeconds::from_secs(9_999_999_999)),
    }
}

#[test]
fn round_trips_a_credential() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.set(&url("https://notes.example/"), &cred()).unwrap();

    // set uses a trailing slash, get doesn't: exercises URL normalization
    let got = s.get(&url("https://notes.example")).unwrap().unwrap();
    assert_eq!(got.user.as_deref(), Some("ann"));
    assert_eq!(got.client_id.as_str(), "cid-123");
    assert_eq!(got.access_token.expose(), "acc-secret");
    assert_eq!(
        got.refresh_token.as_ref().map(|t| t.expose()),
        Some("ref-secret")
    );
}

#[test]
fn pointer_file_holds_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    store(&dir)
        .set(&url("https://notes.example"), &cred())
        .unwrap();
    let hosts = std::fs::read_to_string(dir.path().join("hosts.json")).unwrap();
    assert!(hosts.contains("cid-123") && hosts.contains("ann"));
    assert!(!hosts.contains("acc-secret"));
    assert!(!hosts.contains("ref-secret"));
}

#[test]
fn list_and_remove() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir);
    s.set(&url("https://a.example"), &cred()).unwrap();
    s.set(&url("https://b.example"), &cred()).unwrap();
    assert_eq!(s.list().unwrap().len(), 2);

    s.remove(&url("https://a.example")).unwrap();
    let left = s.list().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].url.as_str(), "https://b.example/");
    assert!(s.get(&url("https://a.example")).unwrap().is_none());
}
