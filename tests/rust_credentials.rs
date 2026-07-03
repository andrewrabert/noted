use noted::credentials::{Credential, CredentialStore};
use noted::httpurl::HttpUrl;

fn store(dir: &tempfile::TempDir) -> CredentialStore {
    CredentialStore::open_plaintext_at(dir.path().join("hosts.yaml"))
}

fn url(s: &str) -> HttpUrl {
    s.parse().unwrap()
}

fn cred() -> Credential {
    Credential {
        user: Some("ann".into()),
        client_id: "cid-123".into(),
        access_token: "acc-secret".into(),
        refresh_token: Some("ref-secret".into()),
        expires_at: Some(noted::types::UnixEpochSeconds::from_secs(9_999_999_999)),
        root_macaroon: Some("MDA-root-macaroon".into()),
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
    assert_eq!(got.client_id, "cid-123");
    assert_eq!(got.access_token.expose(), "acc-secret");
    assert_eq!(
        got.refresh_token.as_ref().map(|t| t.expose()),
        Some("ref-secret")
    );
    assert_eq!(
        got.root_macaroon.as_ref().map(|m| m.expose()),
        Some("MDA-root-macaroon")
    );
}

#[test]
fn pointer_file_holds_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    store(&dir)
        .set(&url("https://notes.example"), &cred())
        .unwrap();
    let hosts = std::fs::read_to_string(dir.path().join("hosts.yaml")).unwrap();
    assert!(hosts.contains("cid-123") && hosts.contains("ann"));
    assert!(!hosts.contains("acc-secret"));
    assert!(!hosts.contains("ref-secret"));
    assert!(!hosts.contains("MDA-root-macaroon"));
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
