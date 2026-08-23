use std::sync::Arc;

use noted_auth::login::{LoginAttempt, LoginOutcome};
use noted_auth::types::{LoginName, Password, Username};
use noted_auth::{AuthService, Db, LoginAuthenticator};

fn fixture() -> (tempfile::TempDir, Arc<AuthService>) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let service = Arc::new(AuthService::new(db));
    service
        .user_add(&Username::new("alice").unwrap(), &Password::new("correct"))
        .unwrap();
    (dir, service)
}

fn attempt(name: &str, password: &str) -> LoginAttempt {
    LoginAttempt {
        name: LoginName::submitted(name),
        password: Password::new(password),
    }
}

#[test]
fn malformed_unknown_and_wrong_password_names_share_the_invalid_outcome() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    for (name, password) in [("9bad", "correct"), ("ghost", "correct"), ("alice", "bad")] {
        assert_eq!(
            auth.authenticate(attempt(name, password)).unwrap(),
            LoginOutcome::InvalidCredentials
        );
    }
}

#[test]
fn repeated_attempts_are_never_refused_for_their_count() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    for _ in 0..50 {
        assert_eq!(
            auth.authenticate(attempt("alice", "bad")).unwrap(),
            LoginOutcome::InvalidCredentials
        );
    }
    assert_eq!(
        auth.authenticate(attempt("alice", "correct")).unwrap(),
        LoginOutcome::Authenticated(Username::new("alice").unwrap())
    );
}

#[test]
fn the_submitted_name_is_matched_exactly() {
    let (_dir, service) = fixture();
    let auth = LoginAuthenticator::new(service);
    assert_eq!(
        auth.authenticate(attempt("Alice", "correct")).unwrap(),
        LoginOutcome::InvalidCredentials
    );
}
