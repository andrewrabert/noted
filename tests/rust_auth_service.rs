use std::sync::Arc;

use noted::oauth::service::{sha256_hex, AuthService, RevokeBy, ScopeEdit, PREFIX_ACC, PREFIX_KEY};
use noted::oauth::{CredentialStatus, Db};
use noted::scope::{RuleSpec, StoredScope};

const DEFAULT_TTL: noted::types::Ttl = noted::types::Ttl::from_secs(30 * 24 * 3600);

fn service_at(dir: &std::path::Path) -> Arc<AuthService> {
    let db = Arc::new(Db::open(&dir.join("auth.redb")).unwrap());
    Arc::new(AuthService::new(db, DEFAULT_TTL))
}

fn service() -> (tempfile::TempDir, Arc<AuthService>) {
    let dir = tempfile::tempdir().unwrap();
    let svc = service_at(dir.path());
    (dir, svc)
}

fn spec(tools: &[&str], paths: &[&str]) -> RuleSpec {
    RuleSpec {
        tools: (!tools.is_empty()).then(|| tools.iter().map(|s| s.to_string()).collect()),
        paths: (!paths.is_empty()).then(|| paths.iter().map(|s| s.to_string()).collect()),
    }
}

#[test]
fn user_add_requires_valid_name_and_password() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    assert!(svc.user_add(&un("alice"), &pw("other")).is_err()); // duplicate
    assert!(svc.user_add(&un("bob"), &pw("")).is_err()); // empty password
                                                         // Invalid names are now unrepresentable: rejected when the string is parsed
                                                         // into a `Username` (the CLI/HTTP boundary), so `user_add` never sees one.
    for bad in ["9lives", "has space", ""] {
        assert!(bad.parse::<noted::oauth::types::Username>().is_err());
    }
}

#[test]
fn new_user_is_unrestricted() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let scope = svc.resolve_scope("user:alice").unwrap().unwrap();
    assert!(scope.allows("WriteNote"));
    assert_eq!(scope.folders_for("WriteNote"), None);
}

#[test]
fn grants_narrow_and_never_fail_open() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();

    svc.user_grant(
        &un("alice"),
        ScopeEdit::Append(vec![spec(&["ReadNote"], &["projects"])]),
    )
    .unwrap();
    let scope = svc.resolve_scope("user:alice").unwrap().unwrap();
    assert!(scope.allows("ReadNote") && !scope.allows("WriteNote"));
    assert_eq!(
        scope.folders_for("ReadNote"),
        Some(vec!["projects".to_string()])
    );

    svc.user_ungrant(&un("alice"), 1).unwrap();
    let scope = svc.resolve_scope("user:alice").unwrap().unwrap();
    assert!(!scope.allows("ReadNote"));

    svc.user_grant(&un("alice"), ScopeEdit::All).unwrap();
    let scope = svc.resolve_scope("user:alice").unwrap().unwrap();
    assert!(scope.allows("WriteNote"));

    assert!(svc.user_ungrant(&un("alice"), 1).is_err());
    assert!(svc
        .user_grant(&un("alice"), ScopeEdit::Append(Vec::new()))
        .is_err());
    assert!(svc
        .user_grant(
            &un("alice"),
            ScopeEdit::Append(vec![spec(&["NotATool"], &[])])
        )
        .is_err());
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
        .key_create(&lb("backup"), StoredScope::Unrestricted, None)
        .unwrap();
    assert!(minted.token.expose().starts_with(PREFIX_KEY));
    assert!(minted.credential_id.as_str().starts_with("cred_"));
    assert!(minted.fingerprint.as_str().starts_with(PREFIX_KEY));

    assert!(svc.resolve_bearer(minted.token.expose()).unwrap().is_none());
    let listed = svc.key_list(Some(&lb("backup"))).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, CredentialStatus::Pending);

    svc.key_finalize(&minted.credential_id).unwrap();
    let (owner, scope) = svc.resolve_bearer(minted.token.expose()).unwrap().unwrap();
    assert_eq!(owner, format!("key:{}", minted.credential_id));
    assert!(scope.allows("WriteNote"));
    assert!(svc.key_finalize(&minted.credential_id).is_err());
}

#[test]
fn key_scope_rides_the_record() {
    let (_d, svc) = service();
    let minted = svc
        .key_create(
            &lb("agent"),
            StoredScope::Grants(vec![
                spec(&["CreateTask", "UpdateTask"], &["Tasks/myapp"]),
                spec(&["ReadNote"], &["dev/myapp-desktop", "dev/myapp-web"]),
            ]),
            None,
        )
        .unwrap();
    svc.key_finalize(&minted.credential_id).unwrap();
    let (_, scope) = svc.resolve_bearer(minted.token.expose()).unwrap().unwrap();
    assert!(scope.allows("CreateTask") && scope.allows("ReadNote"));
    assert!(!scope.allows("WriteNote"));
    assert_eq!(
        scope.folders_for("CreateTask"),
        Some(vec!["Tasks/myapp".to_string()])
    );
    assert_eq!(
        scope.folders_for("ReadNote"),
        Some(vec![
            "dev/myapp-desktop".to_string(),
            "dev/myapp-web".to_string()
        ])
    );
    assert!(svc
        .key_create(
            &lb("bad"),
            StoredScope::Grants(vec![spec(&["Nope"], &[])]),
            None
        )
        .is_err());
}

#[test]
fn labels_are_group_handles() {
    let (_d, svc) = service();
    let mut tokens = Vec::new();
    for _ in 0..3 {
        let m = svc
            .key_create(&lb("claude"), StoredScope::Unrestricted, None)
            .unwrap();
        svc.key_finalize(&m.credential_id).unwrap();
        tokens.push(m);
    }
    let other = svc
        .key_create(&lb("backup"), StoredScope::Unrestricted, None)
        .unwrap();
    svc.key_finalize(&other.credential_id).unwrap();

    assert_eq!(
        svc.key_revoke(&RevokeBy::Id(tokens[0].credential_id.clone()))
            .unwrap(),
        1
    );
    assert!(svc
        .resolve_bearer(tokens[0].token.expose())
        .unwrap()
        .is_none());
    assert!(svc
        .resolve_bearer(tokens[1].token.expose())
        .unwrap()
        .is_some());

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
fn key_grant_is_bulk_and_ungrant_demands_id_when_ambiguous() {
    let (_d, svc) = service();
    let a = svc
        .key_create(&lb("claude"), StoredScope::Unrestricted, None)
        .unwrap();
    let b = svc
        .key_create(&lb("claude"), StoredScope::Unrestricted, None)
        .unwrap();
    svc.key_finalize(&a.credential_id).unwrap();
    svc.key_finalize(&b.credential_id).unwrap();

    let n = svc
        .key_grant(
            Some(&lb("claude")),
            None,
            ScopeEdit::Append(vec![spec(&["ReadNote"], &["projects"])]),
        )
        .unwrap();
    assert_eq!(n, 2);
    for m in [&a, &b] {
        let (_, scope) = svc.resolve_bearer(m.token.expose()).unwrap().unwrap();
        assert!(scope.allows("ReadNote") && !scope.allows("WriteNote"));
    }

    assert!(svc.key_ungrant(Some(&lb("claude")), None, 1).is_err());
    svc.key_ungrant(None, Some(&a.credential_id), 1).unwrap();
    let (_, scope) = svc.resolve_bearer(a.token.expose()).unwrap().unwrap();
    assert!(!scope.allows("ReadNote"));
}

#[test]
fn keys_expire_and_pending_rows_are_swept() {
    let (_d, svc) = service();
    let dead = svc
        .key_create(
            &lb("ephemeral"),
            StoredScope::Unrestricted,
            Some(noted::types::Ttl::from_secs(0)),
        )
        .unwrap();
    svc.key_finalize(&dead.credential_id).unwrap();
    assert!(svc.resolve_bearer(dead.token.expose()).unwrap().is_none());

    let pending = svc
        .key_create(&lb("stuck"), StoredScope::Unrestricted, None)
        .unwrap();
    // a sweep with the cutoff in the future treats the fresh pending row as stale
    let now = noted::types::UnixEpochSeconds::now().unwrap();
    svc.db()
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
    assert!(svc
        .resolve_bearer(&format!("{PREFIX_ACC}nope"))
        .unwrap()
        .is_none());
}

#[test]
fn orphan_credentials_are_revoked_on_sight() {
    let (_d, svc) = service();
    // issue_login_pair doesn't check the owner exists, so "ghost" forges an orphan
    let (access, _, _) = svc.issue_login_pair("ghost", "c").unwrap();
    assert!(svc.resolve_bearer(&access).unwrap().is_none());
    assert!(svc
        .db()
        .get_credential(&sha256_hex(&access))
        .unwrap()
        .is_none());
}

#[test]
fn live_scope_edits_hit_outstanding_credentials() {
    let (_d, svc) = service();
    svc.user_add(&un("alice"), &pw("pw")).unwrap();
    let (access, _, _) = svc.issue_login_pair("alice", "c").unwrap();
    let (_, scope) = svc.resolve_bearer(&access).unwrap().unwrap();
    assert!(scope.allows("WriteNote"));
    svc.user_grant(
        &un("alice"),
        ScopeEdit::Append(vec![spec(&["ReadNote"], &["projects"])]),
    )
    .unwrap();
    let (_, scope) = svc.resolve_bearer(&access).unwrap().unwrap();
    assert!(scope.allows("ReadNote") && !scope.allows("WriteNote"));
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
            .key_create(&lb("backup"), StoredScope::Unrestricted, None)
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
    assert!(!raw
        .windows("hunter2-password".len())
        .any(|w| w == b"hunter2-password"));
}

#[allow(dead_code)]
fn un(s: impl AsRef<str>) -> noted::oauth::types::Username {
    s.as_ref().parse().unwrap()
}
#[allow(dead_code)]
fn pw(s: impl AsRef<str>) -> noted::oauth::types::Password {
    noted::oauth::types::Password::new(s.as_ref())
}
#[allow(dead_code)]
fn lb(s: impl AsRef<str>) -> noted::oauth::types::Label {
    noted::oauth::types::Label::new(s.as_ref()).unwrap()
}
#[allow(dead_code)]
fn ci(s: impl AsRef<str>) -> noted::oauth::types::CredentialId {
    noted::oauth::types::CredentialId::new(s.as_ref()).expect("valid credential id in test")
}
