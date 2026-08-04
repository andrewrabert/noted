use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::oauth::service::{AuthService, PREFIX_ACC, PREFIX_KEY, RevokeBy, sha256_hex};
use noted_auth::oauth::{CredentialStatus, Db};

const DEFAULT_TTL: noted::types::Ttl = noted::types::Ttl::from_secs(30 * 24 * 3600);

fn held(text: &str) -> PolicyFragment {
    text.parse().unwrap()
}

fn service_at(dir: &std::path::Path) -> Arc<AuthService> {
    let db = Arc::new(Db::open(&dir.join("auth.redb")).unwrap());
    Arc::new(AuthService::new(db, DEFAULT_TTL))
}

fn service() -> (tempfile::TempDir, Arc<AuthService>) {
    let dir = tempfile::tempdir().unwrap();
    let svc = service_at(dir.path());
    (dir, svc)
}

#[test]
fn user_add_requires_valid_name_and_password() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    assert!(svc.user_add(&un("alice"), &pw("other")).is_err()); // duplicate
    assert!(svc.user_add(&un("bob"), &pw("")).is_err()); // empty password
    for bad in ["9lives", "has space", ""] {
        assert!(bad.parse::<noted_auth::oauth::types::Username>().is_err());
    }
}

#[test]
fn a_new_user_holds_nothing_back() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let stored = svc.owner_policy("user:alice").unwrap().unwrap();
    assert_eq!(stored, PolicyFragment::default());
}

#[test]
fn setting_a_user_policy_replaces_the_stored_one() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();

    svc.user_set_policy(
        &un("alice"),
        held(r#"{"paths":{"projects":{"read":true,"write":false}}}"#),
    )
    .unwrap();
    let stored = svc.owner_policy("user:alice").unwrap().unwrap();
    assert_eq!(
        stored.to_string(),
        r#"{"paths":{"projects":{"read":true,"write":false}}}"#
    );

    svc.user_set_policy(&un("alice"), held(r#"{"scope":"dev"}"#))
        .unwrap();
    let stored = svc.owner_policy("user:alice").unwrap().unwrap();
    assert_eq!(stored.to_string(), r#"{"scope":"dev"}"#);

    assert!(
        svc.user_set_policy(&un("bob"), PolicyFragment::default())
            .is_err()
    );
}

#[test]
fn user_remove_is_transactional_and_total() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let (access, refresh, _) = svc.issue_login_pair("alice", "client-1").unwrap();
    svc.user_remove(&un("alice")).unwrap();
    assert!(svc.resolve_bearer(&access).unwrap().is_none());
    assert!(svc.refresh_owner(&refresh).unwrap().is_none());
    assert!(svc.user_get(&un("alice")).unwrap().is_none());
    assert!(svc.user_remove(&un("alice")).is_err());
}

#[test]
fn user_revoke_kills_sessions_but_passwd_does_not() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let (access, _, _) = svc.issue_login_pair("alice", "c").unwrap();
    svc.user_passwd(&un("alice"), &pw("newpw")).unwrap();
    assert!(svc.resolve_bearer(&access).unwrap().is_some());
    let n = svc.user_revoke(&un("alice"), None).unwrap();
    assert!(n >= 2);
    assert!(svc.resolve_bearer(&access).unwrap().is_none());
}

#[test]
fn key_mint_is_two_phase() {
    let (_d, svc) = service();
    let minted = svc
        .key_create(&lb("backup"), PolicyFragment::default(), None)
        .unwrap();
    assert!(minted.token.expose().starts_with(PREFIX_KEY));
    assert!(minted.credential_id.as_str().starts_with("cred_"));
    assert!(minted.fingerprint.as_str().starts_with(PREFIX_KEY));

    assert!(svc.resolve_bearer(minted.token.expose()).unwrap().is_none());
    let listed = svc.key_list(Some(&lb("backup"))).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, CredentialStatus::Pending);

    svc.key_finalize(&minted.credential_id).unwrap();
    let (owner, policy) = svc.resolve_bearer(minted.token.expose()).unwrap().unwrap();
    assert_eq!(owner, format!("key:{}", minted.credential_id));
    assert_eq!(policy, PolicyFragment::default());
    assert!(svc.key_finalize(&minted.credential_id).is_err());
}

#[test]
fn a_keys_policy_rides_its_record() {
    let (_d, svc) = service();
    let minted = svc
        .key_create(
            &lb("agent"),
            held(r#"{"scope":"dev/myapp","access":{"read":true,"write":false},"paths":{"Tasks":{"read":true,"write":true}}}"#),
            None,
        )
        .unwrap();
    svc.key_finalize(&minted.credential_id).unwrap();
    let (_, policy) = svc.resolve_bearer(minted.token.expose()).unwrap().unwrap();
    assert_eq!(
        policy.to_string(),
        r#"{"scope":"dev/myapp","access":{"read":true,"write":false},"paths":{"Tasks":{"read":true,"write":true}}}"#
    );
}

#[test]
fn labels_are_group_handles() {
    let (_d, svc) = service();
    let mut tokens = Vec::new();
    for _ in 0..3 {
        let m = svc
            .key_create(&lb("claude"), PolicyFragment::default(), None)
            .unwrap();
        svc.key_finalize(&m.credential_id).unwrap();
        tokens.push(m);
    }
    let other = svc
        .key_create(&lb("backup"), PolicyFragment::default(), None)
        .unwrap();
    svc.key_finalize(&other.credential_id).unwrap();

    assert_eq!(
        svc.key_revoke(&RevokeBy::Id(tokens[0].credential_id.clone()))
            .unwrap(),
        1
    );
    assert!(
        svc.resolve_bearer(tokens[0].token.expose())
            .unwrap()
            .is_none()
    );
    assert!(
        svc.resolve_bearer(tokens[1].token.expose())
            .unwrap()
            .is_some()
    );

    assert_eq!(svc.key_revoke(&RevokeBy::Label(lb("claude"))).unwrap(), 2);
    for t in &tokens {
        assert!(svc.resolve_bearer(t.token.expose()).unwrap().is_none());
    }
    assert!(svc.resolve_bearer(other.token.expose()).unwrap().is_some());

    assert_eq!(
        svc.key_revoke(&RevokeBy::SecretHash(sha256_hex(other.token.expose())))
            .unwrap(),
        1
    );
    assert!(svc.resolve_bearer(other.token.expose()).unwrap().is_none());
    assert!(svc.key_revoke(&RevokeBy::Label(lb("claude"))).is_err());
}

#[test]
fn setting_a_key_policy_is_bulk_and_reaches_one_key_by_id() {
    let (_d, svc) = service();
    let a = svc
        .key_create(&lb("claude"), PolicyFragment::default(), None)
        .unwrap();
    let b = svc
        .key_create(&lb("claude"), PolicyFragment::default(), None)
        .unwrap();
    svc.key_finalize(&a.credential_id).unwrap();
    svc.key_finalize(&b.credential_id).unwrap();

    let n = svc
        .key_set_policy(
            Some(&lb("claude")),
            None,
            held(r#"{"access":{"read":true,"write":false}}"#),
        )
        .unwrap();
    assert_eq!(n, 2);
    for m in [&a, &b] {
        let (_, policy) = svc.resolve_bearer(m.token.expose()).unwrap().unwrap();
        assert_eq!(
            policy.to_string(),
            r#"{"access":{"read":true,"write":false}}"#
        );
    }

    svc.key_set_policy(None, Some(&a.credential_id), PolicyFragment::default())
        .unwrap();
    let (_, policy) = svc.resolve_bearer(a.token.expose()).unwrap().unwrap();
    assert_eq!(policy, PolicyFragment::default());
    let (_, policy) = svc.resolve_bearer(b.token.expose()).unwrap().unwrap();
    assert_eq!(
        policy.to_string(),
        r#"{"access":{"read":true,"write":false}}"#
    );
    assert!(
        svc.key_set_policy(Some(&lb("nope")), None, PolicyFragment::default())
            .is_err()
    );
}

#[test]
fn keys_expire_and_pending_rows_are_swept() {
    let (_d, svc) = service();
    let dead = svc
        .key_create(
            &lb("ephemeral"),
            PolicyFragment::default(),
            Some(noted::types::Ttl::from_secs(0)),
        )
        .unwrap();
    svc.key_finalize(&dead.credential_id).unwrap();
    assert!(svc.resolve_bearer(dead.token.expose()).unwrap().is_none());

    let pending = svc
        .key_create(&lb("stuck"), PolicyFragment::default(), None)
        .unwrap();
    // a sweep with the cutoff in the future treats the fresh pending row as stale
    let now = noted::types::UnixEpochSeconds::now().unwrap();
    svc.db()
        .unwrap()
        .sweep_credentials(now + noted::types::SecondsDuration::from_secs(10))
        .unwrap();
    assert!(svc.key_list(Some(&lb("stuck"))).unwrap().is_empty());
    assert!(svc.key_finalize(&pending.credential_id).is_err());
}

#[test]
fn resolve_bearer_dispatches_on_prefix_only() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let (access, refresh, _) = svc.issue_login_pair("alice", "c").unwrap();

    let (owner, _) = svc.resolve_bearer(&access).unwrap().unwrap();
    assert_eq!(owner, "user:alice");
    assert!(svc.resolve_bearer(&refresh).unwrap().is_none());
    assert!(svc.resolve_bearer("ghp_notours").unwrap().is_none());
    assert!(svc.resolve_bearer("").unwrap().is_none());
    assert!(
        svc.resolve_bearer(&format!("{PREFIX_ACC}nope"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn orphan_credentials_are_revoked_on_sight() {
    let (_d, svc) = service();
    // issue_login_pair doesn't check the owner exists, so "ghost" forges an orphan
    let (access, _, _) = svc.issue_login_pair("ghost", "c").unwrap();
    assert!(svc.resolve_bearer(&access).unwrap().is_none());
    assert!(
        svc.db()
            .unwrap()
            .get_credential(&sha256_hex(&access))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_live_policy_change_hits_outstanding_credentials() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let (access, _, _) = svc.issue_login_pair("alice", "c").unwrap();
    let (_, policy) = svc.resolve_bearer(&access).unwrap().unwrap();
    assert_eq!(policy, PolicyFragment::default());
    svc.user_set_policy(
        &un("alice"),
        held(r#"{"access":{"read":true,"write":false}}"#),
    )
    .unwrap();
    let (_, policy) = svc.resolve_bearer(&access).unwrap().unwrap();
    assert_eq!(
        policy.to_string(),
        r#"{"access":{"read":true,"write":false}}"#
    );
}

#[test]
fn no_plaintext_secret_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.redb");
    let key_token;
    let access_token;
    let refresh_token;
    {
        let db = Arc::new(Db::open(&path).unwrap());
        let svc = AuthService::new(db, DEFAULT_TTL);
        svc.user_add(&un("alice"), &pw("hunter2-password")).unwrap();
        let minted = svc
            .key_create(&lb("backup"), PolicyFragment::default(), None)
            .unwrap();
        svc.key_finalize(&minted.credential_id).unwrap();
        key_token = minted.token.expose().to_string();
        let (a, r, _) = svc.issue_login_pair("alice", "c").unwrap();
        access_token = a;
        refresh_token = r;
    } // drop: release the lock, flush
    let raw = std::fs::read(&path).unwrap();
    for secret in [&key_token, &access_token, &refresh_token] {
        // scan for the suffix, not the whole secret: the prefix legitimately
        // appears at rest in the fingerprint
        let suffix = &secret["noted_xxx_".len()..];
        assert!(
            !raw.windows(suffix.len()).any(|w| w == suffix.as_bytes()),
            "plaintext secret found at rest"
        );
    }
    assert!(
        !raw.windows("hunter2-password".len())
            .any(|w| w == b"hunter2-password")
    );
}

#[allow(dead_code)]
fn un(s: impl AsRef<str>) -> noted_auth::oauth::types::Username {
    s.as_ref().parse().unwrap()
}
#[allow(dead_code)]
fn pw(s: impl AsRef<str>) -> noted_auth::oauth::types::Password {
    noted_auth::oauth::types::Password::new(s.as_ref())
}
#[allow(dead_code)]
fn lb(s: impl AsRef<str>) -> noted_auth::oauth::types::Label {
    noted_auth::oauth::types::Label::new(s.as_ref()).unwrap()
}
#[allow(dead_code)]
fn ci(s: impl AsRef<str>) -> noted_auth::oauth::types::CredentialId {
    noted_auth::oauth::types::CredentialId::new(s.as_ref()).expect("valid credential id in test")
}
