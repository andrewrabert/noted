use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::Db;
use noted_auth::authority::{Mint, Minter, OriginAuthority, Verifier};
use noted_auth::credential::Macaroon;
use noted_auth::service::{AuthService, PREFIX_MAC, PREFIX_REF, sha256_hex};
use noted_auth::types::{ClientId, CredentialPresentation, Owner};

fn held(text: &str) -> PolicyFragment {
    text.parse().unwrap()
}

fn service_at(dir: &std::path::Path) -> Arc<AuthService> {
    let db = Arc::new(Db::open(&dir.join("auth.redb")).unwrap());
    Arc::new(AuthService::new(db))
}

fn service() -> (tempfile::TempDir, Arc<AuthService>) {
    let dir = tempfile::tempdir().unwrap();
    let svc = service_at(dir.path());
    (dir, svc)
}

fn client() -> ClientId {
    ClientId::new("client-1")
}

fn policy_of(authority: &OriginAuthority, bearer: &str) -> Option<Vec<PolicyFragment>> {
    authority
        .verify(Some(&CredentialPresentation::submitted(bearer)))
        .ok()
        .map(|v| v.fragments().to_vec())
}

#[test]
fn user_add_requires_valid_name_and_password() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    assert!(svc.user_add(&un("alice"), &pw("other")).is_err()); // duplicate
    assert!(svc.user_add(&un("bob"), &pw("")).is_err()); // empty password
    for bad in ["9lives", "has space", ""] {
        assert!(bad.parse::<noted_auth::types::Username>().is_err());
    }
}

#[test]
fn a_new_user_holds_nothing_back() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let stored = svc.user_get(&un("alice")).unwrap().unwrap();
    assert_eq!(stored.policy, PolicyFragment::default());
}

#[test]
fn setting_a_user_policy_replaces_the_stored_one() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();

    svc.user_set_policy(
        &un("alice"),
        held(r#"{"paths":{"/projects":{"read":true,"write":false}}}"#),
    )
    .unwrap();
    let stored = svc.user_get(&un("alice")).unwrap().unwrap();
    assert_eq!(
        stored.policy.to_string(),
        r#"{"paths":{"/projects":{"read":true,"write":false}}}"#
    );

    svc.user_set_policy(&un("alice"), held(r#"{"scope":"/dev"}"#))
        .unwrap();
    let stored = svc.user_get(&un("alice")).unwrap().unwrap();
    assert_eq!(stored.policy.to_string(), r#"{"scope":"/dev"}"#);

    assert!(
        svc.user_set_policy(&un("bob"), PolicyFragment::default())
            .is_err()
    );
}

#[test]
fn a_login_is_a_macaroon_beside_an_opaque_refresh() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let login = svc.issue_login(&un("alice"), &client()).unwrap();
    assert!(login.access.expose().starts_with(PREFIX_MAC));
    assert!(login.refresh.expose().starts_with(PREFIX_REF));
    assert_eq!(login.access.owner().unwrap(), Owner::user("alice").unwrap());

    let authority = OriginAuthority::new(svc.clone());
    let verified = authority
        .verify(Some(&CredentialPresentation::submitted(
            login.access.expose(),
        )))
        .unwrap();
    assert_eq!(verified.owner(), Some(&Owner::user("alice").unwrap()));
}

#[test]
fn a_login_names_no_user_that_does_not_exist() {
    let (_d, svc) = service();
    assert!(svc.issue_login(&un("ghost"), &client()).is_err());
}

#[test]
fn user_remove_is_transactional_and_total() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let login = svc.issue_login(&un("alice"), &client()).unwrap();
    let authority = OriginAuthority::new(svc.clone());
    svc.user_remove(&un("alice")).unwrap();
    assert!(policy_of(&authority, login.access.expose()).is_none());
    assert!(svc.refresh_owner(&login.refresh).unwrap().is_none());
    assert!(svc.user_get(&un("alice")).unwrap().is_none());
    assert!(svc.user_remove(&un("alice")).is_err());
}

#[test]
fn changing_a_password_leaves_outstanding_sessions_alive() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let login = svc.issue_login(&un("alice"), &client()).unwrap();
    let authority = OriginAuthority::new(svc.clone());
    svc.user_passwd(&un("alice"), &pw("newpw")).unwrap();
    assert!(policy_of(&authority, login.access.expose()).is_some());
    assert!(svc.refresh_owner(&login.refresh).unwrap().is_some());
}

#[test]
fn a_refresh_token_is_no_access_credential() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let login = svc.issue_login(&un("alice"), &client()).unwrap();
    let authority = OriginAuthority::new(svc.clone());
    assert!(
        authority
            .verify(Some(&CredentialPresentation::submitted(
                login.refresh.expose()
            )))
            .is_err()
    );
    assert!(
        authority
            .verify(Some(&CredentialPresentation::submitted(
                "noted_acc_whatever"
            )))
            .is_err()
    );
    assert!(
        authority
            .verify(Some(&CredentialPresentation::submitted(
                "noted_key_whatever"
            )))
            .is_err()
    );
    assert!(
        authority
            .verify(Some(&CredentialPresentation::submitted("ghp_notours")))
            .is_err()
    );
    assert!(authority.verify(None).unwrap().owner().is_none());
}

#[test]
fn a_live_policy_change_hits_outstanding_credentials() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let login = svc.issue_login(&un("alice"), &client()).unwrap();
    let authority = OriginAuthority::new(svc.clone());
    let fragments = policy_of(&authority, login.access.expose()).unwrap();
    assert_eq!(fragments, vec![PolicyFragment::default()]);
    svc.user_set_policy(
        &un("alice"),
        held(r#"{"access":{"read":true,"write":false}}"#),
    )
    .unwrap();
    let fragments = policy_of(&authority, login.access.expose()).unwrap();
    assert_eq!(
        fragments[0].to_string(),
        r#"{"access":{"read":true,"write":false}}"#
    );
}

#[test]
fn a_forged_signature_verifies_nowhere() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let authority = OriginAuthority::new(svc.clone());
    let stranger = Macaroon::mint(
        &Owner::user("alice").unwrap(),
        &noted_auth::credential::KeyRecord::fresh(),
        &[],
    )
    .unwrap();
    assert!(
        authority
            .verify(Some(&CredentialPresentation::submitted(stranger.expose())))
            .is_err()
    );
}

#[test]
fn a_minted_credential_is_ledgered() {
    let (_d, svc) = service();
    let authority = OriginAuthority::new(svc.clone());
    let ask = Mint {
        policy: held(r#"{"scope":"/dev"}"#),
    };
    let minted = authority.mint(authority.own(), &ask).unwrap();
    assert!(minted.macaroon.expose().starts_with(PREFIX_MAC));

    let owner = authority.own().owner().unwrap().clone();
    let listed = authority.minted(&owner).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].token_id, minted.token_id);

    let fragments = policy_of(&authority, minted.macaroon.expose()).unwrap();
    assert!(
        fragments
            .iter()
            .any(|f| f.to_string() == r#"{"scope":"/dev"}"#)
    );
}

#[test]
fn no_plaintext_secret_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    let refresh_token;
    {
        let db = Arc::new(Db::open(&path).unwrap());
        let svc = Arc::new(AuthService::new(db));
        svc.user_add(&un("alice"), &pw("hunter2-password")).unwrap();
        let login = svc.issue_login(&un("alice"), &client()).unwrap();
        refresh_token = login.refresh.expose().to_string();
        assert!(sha256_hex(&refresh_token).as_str().len() == 64);
    } // drop: release the lock, flush
    let raw = std::fs::read(&path).unwrap();
    // scan for the suffix, not the whole secret: the prefix legitimately
    // appears at rest in the fingerprint
    let suffix = &refresh_token["noted_xxx_".len()..];
    assert!(
        !raw.windows(suffix.len()).any(|w| w == suffix.as_bytes()),
        "plaintext secret found at rest"
    );
    assert!(
        !raw.windows("hunter2-password".len())
            .any(|w| w == b"hunter2-password")
    );
}

fn un(s: impl AsRef<str>) -> noted_auth::types::Username {
    s.as_ref().parse().unwrap()
}
fn pw(s: impl AsRef<str>) -> noted_auth::types::Password {
    noted_auth::types::Password::new(s.as_ref())
}
