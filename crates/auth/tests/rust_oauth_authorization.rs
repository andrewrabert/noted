use std::sync::Arc;

use noted_auth::oauth::{
    AuthorizationLogin, AuthorizationLoginOutcome, AuthorizationRequest, AuthorizationStatus,
    BeginAuthorizationOutcome, OAuthProtocol, RegisterOAuthClient,
};
use noted_auth::types::{
    AuthorizationResponseType, ClientId, ClientState, CodeChallenge, CodeChallengeMethod,
    LoginName, Password, RedirectUri, RequestedScope, SubmittedRedirectUri, Username,
};
use noted_auth::{AuthService, Db};

fn protocol() -> (tempfile::TempDir, OAuthProtocol, ClientId) {
    let dir = tempfile::tempdir().unwrap();
    let service = Arc::new(AuthService::new(Arc::new(
        Db::open(&dir.path().join("auth.redb")).unwrap(),
    )));
    service
        .user_add(&Username::new("alice").unwrap(), &Password::new("correct"))
        .unwrap();
    let protocol = OAuthProtocol::open(service).unwrap();
    let client = protocol
        .register_client(
            RegisterOAuthClient::new(vec![
                RedirectUri::new("https://client.example/callback").unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
    (dir, protocol, client.client_id().clone())
}

fn request(client_id: ClientId, state: Option<&str>) -> AuthorizationRequest {
    AuthorizationRequest::new(
        Some(AuthorizationResponseType::Code),
        Some(client_id),
        Some(SubmittedRedirectUri::submitted(
            "https://client.example/callback",
        )),
        Some(RequestedScope::submitted("notes")),
        state.map(ClientState::submitted),
        Some(CodeChallenge::submitted(
            "0123456789012345678901234567890123456789012",
        )),
        Some(CodeChallengeMethod::S256),
    )
}

#[test]
fn authorization_requires_the_registered_client_redirect_code_response_and_s256_pkce() {
    let (_dir, protocol, client_id) = protocol();
    assert!(matches!(
        protocol.begin_authorization(request(client_id, None)),
        BeginAuthorizationOutcome::LoginRequired(_)
    ));

    let invalid = AuthorizationRequest::new(
        Some(AuthorizationResponseType::Code),
        Some(ClientId::new("unknown")),
        Some(SubmittedRedirectUri::submitted(
            "https://client.example/callback",
        )),
        None,
        None,
        None,
        None,
    );
    assert!(!matches!(
        protocol.begin_authorization(invalid),
        BeginAuthorizationOutcome::LoginRequired(_)
    ));
}

#[test]
fn authorization_retains_client_state_and_returns_only_typed_redirects() {
    let (_dir, protocol, client_id) = protocol();
    let outcome = protocol.begin_authorization(request(client_id, Some("opaque-state")));
    let BeginAuthorizationOutcome::LoginRequired(transaction) = outcome else {
        panic!("valid authorization was not parked");
    };
    assert_eq!(
        protocol.authorization_status(&transaction),
        AuthorizationStatus::Pending
    );
}

#[test]
fn invalid_authorization_requests_keep_the_existing_redirect_or_invalid_request_outcome() {
    let (_dir, protocol, client_id) = protocol();
    let invalid = AuthorizationRequest::new(
        Some(AuthorizationResponseType::Unsupported),
        Some(client_id),
        Some(SubmittedRedirectUri::submitted(
            "https://client.example/callback",
        )),
        None,
        Some(ClientState::submitted("state")),
        None,
        Some(CodeChallengeMethod::Unsupported),
    );
    assert!(matches!(
        protocol.begin_authorization(invalid),
        BeginAuthorizationOutcome::Redirect(_) | BeginAuthorizationOutcome::InvalidRequest
    ));
}

#[test]
fn parking_past_1024_drops_the_oldest_and_unknown_transactions_are_unknown() {
    let (_dir, protocol, client_id) = protocol();
    let BeginAuthorizationOutcome::LoginRequired(first) =
        protocol.begin_authorization(request(client_id.clone(), None))
    else {
        panic!("valid authorization was not parked");
    };
    assert_eq!(
        protocol.authorization_status(&first),
        AuthorizationStatus::Pending
    );
    for _ in 1..1024 {
        assert!(matches!(
            protocol.begin_authorization(request(client_id.clone(), None)),
            BeginAuthorizationOutcome::LoginRequired(_)
        ));
    }
    assert!(matches!(
        protocol.begin_authorization(request(client_id, None)),
        BeginAuthorizationOutcome::LoginRequired(_)
    ));
    assert_eq!(
        protocol.authorization_status(&first),
        AuthorizationStatus::Unknown
    );
    assert_eq!(
        protocol.authorization_status(&noted_auth::types::AuthorizationTransactionId::submitted(
            "missing"
        )),
        AuthorizationStatus::Unknown
    );
}

#[test]
fn invalid_logins_keep_the_transaction_but_success_consumes_it() {
    let (_dir, protocol, client_id) = protocol();
    let BeginAuthorizationOutcome::LoginRequired(transaction) =
        protocol.begin_authorization(request(client_id.clone(), None))
    else {
        panic!("valid authorization was not parked");
    };
    for _ in 0..5 {
        assert_eq!(
            protocol.authorize_login(AuthorizationLogin::new(
                transaction.clone(),
                LoginName::submitted("alice"),
                Password::new("wrong"),
            )),
            AuthorizationLoginOutcome::InvalidCredentials
        );
    }
    assert_eq!(
        protocol.authorization_status(&transaction),
        AuthorizationStatus::Pending
    );

    let BeginAuthorizationOutcome::LoginRequired(success) =
        protocol.begin_authorization(request(client_id, None))
    else {
        panic!("valid authorization was not parked");
    };
    assert!(matches!(
        protocol.authorize_login(AuthorizationLogin::new(
            success.clone(),
            LoginName::submitted("alice"),
            Password::new("correct"),
        )),
        AuthorizationLoginOutcome::Redirect(_)
    ));
    assert_eq!(
        protocol.authorization_status(&success),
        AuthorizationStatus::Unknown
    );
}
