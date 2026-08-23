use std::sync::Arc;

use noted_auth::oauth::{
    AuthorizationCodeExchange, AuthorizationLogin, AuthorizationLoginOutcome, AuthorizationRequest,
    BeginAuthorizationOutcome, OAuthProtocol, RefreshTokenExchange, RegisterOAuthClient,
    TokenOutcome, TokenRejection, TokenRequest,
};
use noted_auth::types::{
    AuthorizationCode, AuthorizationResponseType, ClientId, CodeChallenge, CodeChallengeMethod,
    CodeVerifier, LoginName, Password, RedirectUri, RequestedScope, SubmittedRedirectUri, Username,
};
use noted_auth::{AuthService, Db};

const REDIRECT: &str = "https://client.example/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn protocol() -> (tempfile::TempDir, Arc<AuthService>, OAuthProtocol, ClientId) {
    let dir = tempfile::tempdir().unwrap();
    let service = Arc::new(AuthService::new(Arc::new(
        Db::open(&dir.path().join("auth.redb")).unwrap(),
    )));
    service
        .user_add(&Username::new("alice").unwrap(), &Password::new("correct"))
        .unwrap();
    let protocol = OAuthProtocol::open(service.clone()).unwrap();
    let client = protocol
        .register_client(
            RegisterOAuthClient::new(vec![RedirectUri::new(REDIRECT).unwrap()]).unwrap(),
        )
        .unwrap();
    (dir, service, protocol, client.client_id().clone())
}

fn authorize(protocol: &OAuthProtocol, client_id: &ClientId) -> AuthorizationCode {
    let request = AuthorizationRequest::new(
        Some(AuthorizationResponseType::Code),
        Some(client_id.clone()),
        Some(SubmittedRedirectUri::submitted(REDIRECT)),
        None,
        None,
        Some(CodeChallenge::submitted(CHALLENGE)),
        Some(CodeChallengeMethod::S256),
    );
    let BeginAuthorizationOutcome::LoginRequired(transaction) =
        protocol.begin_authorization(request)
    else {
        panic!("authorization was not parked");
    };
    let AuthorizationLoginOutcome::Redirect(redirect) =
        protocol.authorize_login(AuthorizationLogin::new(
            transaction,
            LoginName::submitted("alice"),
            Password::new("correct"),
        ))
    else {
        panic!("login did not authorize");
    };
    let code = redirect
        .as_uri()
        .as_url()
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .expect("redirect contains code");
    AuthorizationCode::submitted(code)
}

fn exchange(
    code: Option<AuthorizationCode>,
    client_id: Option<ClientId>,
    redirect: Option<&str>,
    verifier: Option<&str>,
) -> TokenRequest {
    TokenRequest::AuthorizationCode(AuthorizationCodeExchange::new(
        code,
        redirect.map(SubmittedRedirectUri::submitted),
        client_id,
        verifier.map(CodeVerifier::submitted),
    ))
}

#[test]
fn authorization_code_exchange_returns_exact_token_facts_and_codes_are_single_use() {
    let (_dir, _service, protocol, client_id) = protocol();
    let code = authorize(&protocol, &client_id);
    let outcome = protocol.exchange_token(exchange(
        Some(code.clone()),
        Some(client_id.clone()),
        Some(REDIRECT),
        Some(VERIFIER),
    ));
    let TokenOutcome::Issued(tokens) = outcome else {
        panic!("valid code exchange did not issue tokens");
    };
    assert!(!tokens.access_token().expose().is_empty());
    assert!(!tokens.refresh_token().expose().is_empty());
    assert_eq!(
        tokens.token_type(),
        &noted_auth::types::OAuthTokenType::Bearer
    );
    assert_eq!(tokens.scope().as_str(), "notes");
    assert!(matches!(
        protocol.exchange_token(exchange(
            Some(code),
            Some(client_id),
            Some(REDIRECT),
            Some(VERIFIER)
        )),
        TokenOutcome::Rejected(TokenRejection::InvalidGrant)
    ));
}

#[test]
fn authorization_code_exchange_rejects_wrong_or_missing_original_facts() {
    let (_dir, _service, protocol, client_id) = protocol();
    for request in [
        exchange(
            Some(authorize(&protocol, &client_id)),
            Some(client_id.clone()),
            Some(REDIRECT),
            Some("wrong"),
        ),
        exchange(
            Some(authorize(&protocol, &client_id)),
            Some(client_id.clone()),
            Some("https://client.example/wrong"),
            Some(VERIFIER),
        ),
        exchange(
            Some(authorize(&protocol, &client_id)),
            Some(ClientId::new("wrong")),
            Some(REDIRECT),
            Some(VERIFIER),
        ),
        exchange(
            None,
            Some(client_id.clone()),
            Some(REDIRECT),
            Some(VERIFIER),
        ),
        exchange(
            Some(authorize(&protocol, &client_id)),
            Some(client_id.clone()),
            Some(REDIRECT),
            None,
        ),
    ] {
        assert!(matches!(
            protocol.exchange_token(request),
            TokenOutcome::Rejected(TokenRejection::InvalidGrant)
        ));
    }
}

#[test]
fn refresh_tokens_rotate_once_and_retain_the_default_notes_scope() {
    let (_dir, _service, protocol, client_id) = protocol();
    let code = authorize(&protocol, &client_id);
    let TokenOutcome::Issued(first) = protocol.exchange_token(exchange(
        Some(code),
        Some(client_id.clone()),
        Some(REDIRECT),
        Some(VERIFIER),
    )) else {
        panic!("code exchange did not issue tokens");
    };
    let old_refresh = first.refresh_token().clone();
    let TokenOutcome::Issued(rotated) = protocol.exchange_token(TokenRequest::RefreshToken(
        RefreshTokenExchange::new(Some(old_refresh.clone()), Some(client_id.clone()), None),
    )) else {
        panic!("refresh did not rotate tokens");
    };
    assert_ne!(rotated.refresh_token().expose(), old_refresh.expose());
    assert_eq!(rotated.scope().as_str(), "notes");
    assert!(matches!(
        protocol.exchange_token(TokenRequest::RefreshToken(RefreshTokenExchange::new(
            Some(old_refresh),
            Some(client_id),
            None
        ))),
        TokenOutcome::Rejected(TokenRejection::InvalidGrant)
    ));
}

#[test]
fn refresh_exchange_keeps_failures_distinct() {
    let (_dir, service, protocol, client_id) = protocol();
    let code = authorize(&protocol, &client_id);
    let TokenOutcome::Issued(tokens) = protocol.exchange_token(exchange(
        Some(code),
        Some(client_id.clone()),
        Some(REDIRECT),
        Some(VERIFIER),
    )) else {
        panic!("code exchange did not issue tokens");
    };
    let refresh = tokens.refresh_token().clone();
    match protocol.exchange_token(TokenRequest::RefreshToken(RefreshTokenExchange::new(
        Some(refresh.clone()),
        Some(ClientId::new("wrong")),
        None,
    ))) {
        TokenOutcome::Rejected(TokenRejection::InvalidGrant) => {}
        TokenOutcome::Rejected(rejection) => panic!("unexpected rejection: {rejection:?}"),
        TokenOutcome::Issued(_) => panic!("wrong client issued tokens"),
        TokenOutcome::ServerError => panic!("wrong client caused server error"),
    }
    assert!(matches!(
        protocol.exchange_token(TokenRequest::RefreshToken(RefreshTokenExchange::new(
            Some(refresh.clone()),
            Some(client_id.clone()),
            Some(RequestedScope::submitted("other"))
        ))),
        TokenOutcome::Rejected(TokenRejection::InvalidScope)
    ));
    assert!(matches!(
        protocol.exchange_token(TokenRequest::RefreshToken(RefreshTokenExchange::new(
            None,
            Some(client_id.clone()),
            None
        ))),
        TokenOutcome::Rejected(TokenRejection::InvalidRequest)
    ));
    assert!(matches!(
        protocol.exchange_token(TokenRequest::Unsupported),
        TokenOutcome::Rejected(TokenRejection::UnsupportedGrantType)
    ));
    service
        .user_remove(&Username::new("alice").unwrap())
        .unwrap();
    assert!(matches!(
        protocol.exchange_token(TokenRequest::RefreshToken(RefreshTokenExchange::new(
            Some(refresh),
            Some(client_id),
            None
        ))),
        TokenOutcome::Rejected(TokenRejection::InvalidGrant)
    ));
}
