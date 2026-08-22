use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use noted::types::Ttl;
use noted_auth::login::{LoginAttempt, LoginOutcome};
use noted_auth::types::{LoginName, LoginPeerIp, LoginSource, LoginSourceId, Password, Username};
use noted_auth::{AuthService, Db, LoginAuthenticator};

fn fixture() -> (tempfile::TempDir, Arc<AuthService>) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let service = Arc::new(AuthService::new(db, Ttl::from_secs(3600)));
    service
        .user_add(&Username::new("alice").unwrap(), &Password::new("correct"))
        .unwrap();
    (dir, service)
}

fn source(ip: [u8; 4]) -> LoginSource {
    LoginSource::AcceptedTcpPeer(LoginPeerIp::accepted(IpAddr::V4(Ipv4Addr::from(ip))))
}

fn non_tcp(id: &str) -> LoginSource {
    LoginSource::NonTcpAdapter(LoginSourceId::new(id))
}

fn attempt(name: &str, password: &str, source: LoginSource) -> LoginAttempt {
    LoginAttempt {
        name: LoginName::submitted(name),
        password: Password::new(password),
        source,
    }
}

#[test]
fn quota_is_keyed_by_submitted_username_and_login_source() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    for _ in 0..5 {
        assert_eq!(
            auth.authenticate(attempt("alice", "bad", source([127, 0, 0, 1])))
                .unwrap(),
            LoginOutcome::InvalidCredentials
        );
    }
    assert_eq!(
        auth.authenticate(attempt("alice", "bad", source([127, 0, 0, 1])))
            .unwrap(),
        LoginOutcome::Throttled
    );
    assert_eq!(
        auth.authenticate(attempt("Alice", "bad", source([127, 0, 0, 1])))
            .unwrap(),
        LoginOutcome::InvalidCredentials
    );
}

#[test]
fn one_username_and_source_receives_five_attempts_per_minute() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    for _ in 0..5 {
        assert_ne!(
            auth.authenticate(attempt("alice", "bad", non_tcp("adapter")))
                .unwrap(),
            LoginOutcome::Throttled
        );
    }
    assert_eq!(
        auth.authenticate(attempt("alice", "bad", non_tcp("adapter")))
            .unwrap(),
        LoginOutcome::Throttled
    );
}

#[test]
fn different_usernames_and_sources_receive_independent_quotas() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    for _ in 0..5 {
        auth.authenticate(attempt("alice", "bad", source([127, 0, 0, 1])))
            .unwrap();
    }
    assert_eq!(
        auth.authenticate(attempt("bob", "bad", source([127, 0, 0, 1])))
            .unwrap(),
        LoginOutcome::InvalidCredentials
    );
    assert_eq!(
        auth.authenticate(attempt("alice", "bad", source([127, 0, 0, 2])))
            .unwrap(),
        LoginOutcome::InvalidCredentials
    );
}

#[test]
fn accepted_peer_ports_cannot_enter_the_login_source() {
    let first = SocketAddr::from(([127, 0, 0, 1], 41000));
    let second = SocketAddr::from(([127, 0, 0, 1], 42000));
    assert_eq!(
        LoginSource::AcceptedTcpPeer(LoginPeerIp::accepted(first.ip())),
        LoginSource::AcceptedTcpPeer(LoginPeerIp::accepted(second.ip()))
    );
}

#[test]
fn malformed_unknown_and_wrong_password_names_share_the_invalid_outcome() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    for (name, password) in [("9bad", "correct"), ("ghost", "correct"), ("alice", "bad")] {
        assert_eq!(
            auth.authenticate(attempt(name, password, non_tcp("adapter")))
                .unwrap(),
            LoginOutcome::InvalidCredentials
        );
    }
}

#[test]
fn successful_and_failed_attempts_consume_at_the_existing_boundary() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    for password in ["bad", "correct", "bad", "correct", "bad"] {
        assert_ne!(
            auth.authenticate(attempt("alice", password, non_tcp("adapter")))
                .unwrap(),
            LoginOutcome::Throttled
        );
    }
    assert_eq!(
        auth.authenticate(attempt("alice", "correct", non_tcp("adapter")))
            .unwrap(),
        LoginOutcome::Throttled
    );
}

#[test]
fn a_new_authenticator_starts_with_an_empty_process_local_quota() {
    let (_dir, service) = fixture();
    let first = LoginAuthenticator::new(service.clone());
    for _ in 0..6 {
        let _ = first.authenticate(attempt("alice", "bad", non_tcp("adapter")));
    }
    let second = LoginAuthenticator::new(service);
    assert_eq!(
        second
            .authenticate(attempt("alice", "correct", non_tcp("adapter")))
            .unwrap(),
        LoginOutcome::Authenticated(Username::new("alice").unwrap())
    );
}
