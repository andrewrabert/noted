use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::Arc;

use oxide_auth::endpoint::{AccessTokenFlow, AuthorizationFlow, OwnerConsent};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::frontends::simple::extensions::{AddonList, Extended, Pkce};
use oxide_auth::frontends::simple::request::{
    Body as OxBody, Request as OxRequest, Response as OxResponse, Status as OxStatus,
};
use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::generator::RandomGenerator;
use oxide_auth::primitives::registrar::{Client, ClientMap, RegisteredUrl};
use oxide_auth::primitives::scope::Scope;

use super::issuer::DbIssuer;
use super::{
    AuthorizationCodeExchange, AuthorizationLogin, AuthorizationLoginOutcome,
    AuthorizationRedirect, AuthorizationRequest, AuthorizationStatus, BeginAuthorizationOutcome,
    OAuthClient, OAuthTokens, RefreshTokenExchange, RegisterOAuthClient, TokenOutcome,
    TokenRejection,
};
use crate::login::{LoginAttempt, LoginAuthenticator, LoginOutcome};
use crate::service::AuthService;
use crate::types::AuthorizationTransactionId;
use noted::error::{Result, rejected};
use noted::util::random_token;

pub(super) const MAX_TRANSACTIONS: usize = 1024;
pub(super) const DEFAULT_SCOPE: &str = "notes";

pub(super) struct ProtocolState {
    pub(super) service: Arc<AuthService>,
    pub(super) registrar: ClientMap,
    pub(super) authorizer: AuthMap<RandomGenerator>,
    pub(super) issuer: DbIssuer,
    pub(super) transactions: Transactions,
    pub(super) authenticator: LoginAuthenticator,
}

/// The pending authorizations, oldest first. Nothing here expires, so the
/// oldest is dropped to make room once `MAX_TRANSACTIONS` are parked.
#[derive(Default)]
pub(super) struct Transactions {
    requests: HashMap<AuthorizationTransactionId, AuthorizationRequest>,
    order: VecDeque<AuthorizationTransactionId>,
}

impl Transactions {
    fn park(&mut self, transaction: AuthorizationTransactionId, request: AuthorizationRequest) {
        while self.order.len() >= MAX_TRANSACTIONS {
            if let Some(oldest) = self.order.pop_front() {
                self.requests.remove(&oldest);
            }
        }
        self.order.push_back(transaction.clone());
        self.requests.insert(transaction, request);
    }

    fn get(&self, transaction: &AuthorizationTransactionId) -> Option<&AuthorizationRequest> {
        self.requests.get(transaction)
    }

    fn remove(&mut self, transaction: &AuthorizationTransactionId) {
        if self.requests.remove(transaction).is_some() {
            self.order.retain(|parked| parked != transaction);
        }
    }
}

pub(super) fn open(service: Arc<AuthService>) -> Result<ProtocolState> {
    let clients = service.oauth_clients()?;
    let mut registrar = ClientMap::new();
    for client in clients {
        register(&mut registrar, &client);
    }
    Ok(ProtocolState {
        service: service.clone(),
        registrar,
        authorizer: AuthMap::new(RandomGenerator::new(16)),
        issuer: DbIssuer::new(service.clone()),
        transactions: Transactions::default(),
        authenticator: LoginAuthenticator::new(service),
    })
}

pub(super) fn register(registrar: &mut ClientMap, client: &OAuthClient) {
    let mut redirects = client
        .redirect_uris()
        .iter()
        .map(|uri| RegisteredUrl::from(uri.as_url().clone()));
    let primary = redirects
        .next()
        .expect("OAuth client invariant requires a redirect URI");
    let scope = Scope::from_str(DEFAULT_SCOPE).expect("static scope parses");
    registrar.register_client(
        Client::public(client.client_id().as_str(), primary, scope)
            .with_additional_redirect_uris(redirects.collect()),
    );
}

pub(super) fn register_client(
    state: &mut ProtocolState,
    service: &AuthService,
    request: RegisterOAuthClient,
) -> Result<OAuthClient> {
    let client = OAuthClient::registered(request)?;
    service.register_oauth_client(&client)?;
    register(&mut state.registrar, &client);
    Ok(client)
}

fn addons() -> AddonList {
    let mut list = AddonList::new();
    list.push_authorization(Pkce::required());
    list.push_access_token(Pkce::required());
    list
}

fn authorization_query(request: &AuthorizationRequest) -> HashMap<String, String> {
    let mut query = HashMap::new();
    if let Some(response_type) = &request.response_type {
        query.insert(
            "response_type".to_owned(),
            match response_type {
                crate::types::AuthorizationResponseType::Code => "code",
                crate::types::AuthorizationResponseType::Unsupported => "unsupported",
            }
            .to_owned(),
        );
    }
    if let Some(client_id) = &request.client_id {
        query.insert("client_id".to_owned(), client_id.as_str().to_owned());
    }
    if let Some(redirect_uri) = &request.redirect_uri {
        query.insert("redirect_uri".to_owned(), redirect_uri.as_str().to_owned());
    }
    if let Some(scope) = &request.scope {
        query.insert("scope".to_owned(), scope.as_str().to_owned());
    }
    if let Some(client_state) = &request.state {
        query.insert("state".to_owned(), client_state.as_str().to_owned());
    }
    if let Some(challenge) = &request.code_challenge {
        query.insert("code_challenge".to_owned(), challenge.as_str().to_owned());
    }
    if let Some(method) = &request.code_challenge_method {
        query.insert(
            "code_challenge_method".to_owned(),
            match method {
                crate::types::CodeChallengeMethod::S256 => "S256",
                crate::types::CodeChallengeMethod::Unsupported => "unsupported",
            }
            .to_owned(),
        );
    }
    query
}

pub(super) fn begin_authorization(
    state: &mut ProtocolState,
    request: AuthorizationRequest,
) -> BeginAuthorizationOutcome {
    let transaction = AuthorizationTransactionId::submitted(random_token(24));
    state
        .transactions
        .park(transaction.clone(), request.clone());

    let login_url = match url::Url::parse(&format!(
        "https://authentication.invalid/login?txn={}",
        transaction.as_str()
    )) {
        Ok(url) => url,
        Err(_) => return BeginAuthorizationOutcome::ServerError,
    };
    let ox_request = OxRequest {
        query: authorization_query(&request),
        urlbody: HashMap::new(),
        auth: None,
    };
    let ProtocolState {
        registrar,
        authorizer,
        ..
    } = state;
    let mut solicitor = FnSolicitor(|_: &mut OxRequest, _: oxide_auth::endpoint::Solicitation| {
        OwnerConsent::InProgress(OxResponse {
            status: OxStatus::Redirect,
            location: Some(login_url.clone()),
            ..Default::default()
        })
    });
    let generic = Generic {
        registrar: &*registrar,
        authorizer,
        issuer: Vacant,
        solicitor: &mut solicitor,
        scopes: Vacant,
        response: Vacant,
    };
    let mut flow = match AuthorizationFlow::prepare(Extended::extend_with(generic, addons())) {
        Ok(flow) => flow,
        Err(_) => return BeginAuthorizationOutcome::ServerError,
    };
    match flow.execute(ox_request) {
        Ok(response) if response.location.as_ref() == Some(&login_url) => {
            BeginAuthorizationOutcome::LoginRequired(transaction)
        }
        Ok(response) => match response.location {
            Some(location) => match crate::types::RedirectUri::new(location.as_str()) {
                Ok(uri) => BeginAuthorizationOutcome::Redirect(AuthorizationRedirect(uri)),
                Err(_) => BeginAuthorizationOutcome::ServerError,
            },
            None => BeginAuthorizationOutcome::InvalidRequest,
        },
        Err(_) => BeginAuthorizationOutcome::InvalidRequest,
    }
}

fn authorization_code_body(request: &AuthorizationCodeExchange) -> HashMap<String, String> {
    let mut body = HashMap::new();
    body.insert("grant_type".to_owned(), "authorization_code".to_owned());
    if let Some(code) = &request.code {
        body.insert("code".to_owned(), code.as_str().to_owned());
    }
    if let Some(redirect_uri) = &request.redirect_uri {
        body.insert("redirect_uri".to_owned(), redirect_uri.as_str().to_owned());
    }
    if let Some(client_id) = &request.client_id {
        body.insert("client_id".to_owned(), client_id.as_str().to_owned());
    }
    if let Some(verifier) = &request.code_verifier {
        body.insert("code_verifier".to_owned(), verifier.as_str().to_owned());
    }
    body
}

fn token_outcome(response: OxResponse) -> TokenOutcome {
    let status = response.status;
    let OxBody::Json(body) = (match response.body {
        Some(body) => body,
        None => return TokenOutcome::ServerError,
    }) else {
        return TokenOutcome::ServerError;
    };
    let value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(_) => return TokenOutcome::ServerError,
    };
    if status == OxStatus::Ok {
        let Some(access_token) = value.get("access_token").and_then(|value| value.as_str()) else {
            return TokenOutcome::ServerError;
        };
        let Some(refresh_token) = value.get("refresh_token").and_then(|value| value.as_str())
        else {
            return TokenOutcome::ServerError;
        };
        let Some(scope) = value.get("scope").and_then(|value| value.as_str()) else {
            return TokenOutcome::ServerError;
        };
        if value.get("token_type").and_then(|value| value.as_str()) != Some("bearer") {
            return TokenOutcome::ServerError;
        }
        return TokenOutcome::Issued(OAuthTokens {
            access_token: crate::types::OAuthAccessToken::issued(access_token),
            refresh_token: crate::types::RefreshToken::new(refresh_token),
            token_type: crate::types::OAuthTokenType::Bearer,
            scope: crate::types::GrantedScope::new(scope),
        });
    }
    match value.get("error").and_then(|value| value.as_str()) {
        Some("invalid_request") => TokenOutcome::Rejected(TokenRejection::InvalidRequest),
        Some("invalid_client") => TokenOutcome::Rejected(TokenRejection::InvalidClient(
            super::ClientAuthenticationScheme::Basic,
        )),
        Some("unsupported_grant_type") => {
            TokenOutcome::Rejected(TokenRejection::UnsupportedGrantType)
        }
        Some("invalid_grant") => TokenOutcome::Rejected(TokenRejection::InvalidGrant),
        Some("invalid_scope") => TokenOutcome::Rejected(TokenRejection::InvalidScope),
        _ => TokenOutcome::ServerError,
    }
}

pub(super) fn exchange_authorization_code(
    state: &mut ProtocolState,
    request: AuthorizationCodeExchange,
) -> TokenOutcome {
    let ox_request = OxRequest {
        query: HashMap::new(),
        urlbody: authorization_code_body(&request),
        auth: None,
    };
    let ProtocolState {
        registrar,
        authorizer,
        issuer,
        ..
    } = state;
    let generic = Generic {
        registrar: &*registrar,
        authorizer,
        issuer,
        solicitor: Vacant,
        scopes: Vacant,
        response: Vacant,
    };
    let mut flow = match AccessTokenFlow::prepare(Extended::extend_with(generic, addons())) {
        Ok(flow) => flow,
        Err(_) => return TokenOutcome::ServerError,
    };
    match flow.execute(ox_request) {
        Ok(response) if response.status == OxStatus::Ok => token_outcome(response),
        Ok(_) | Err(_) => TokenOutcome::Rejected(TokenRejection::InvalidGrant),
    }
}

fn refresh_body(request: &RefreshTokenExchange) -> HashMap<String, String> {
    let mut body = HashMap::new();
    body.insert("grant_type".to_owned(), "refresh_token".to_owned());
    if let Some(refresh_token) = &request.refresh_token {
        body.insert(
            "refresh_token".to_owned(),
            refresh_token.expose().to_owned(),
        );
    }
    if let Some(client_id) = &request.client_id {
        body.insert("client_id".to_owned(), client_id.as_str().to_owned());
    }
    if let Some(scope) = &request.scope {
        body.insert("scope".to_owned(), scope.as_str().to_owned());
    }
    body
}

pub(super) fn exchange_refresh_token(
    state: &mut ProtocolState,
    request: RefreshTokenExchange,
) -> TokenOutcome {
    let (Some(refresh_token), Some(client_id)) = (&request.refresh_token, &request.client_id)
    else {
        return TokenOutcome::Rejected(TokenRejection::InvalidRequest);
    };
    match state.service.refresh_owner(refresh_token) {
        Ok(Some(record)) if &record.client_id == client_id => {}
        Ok(_) => return TokenOutcome::Rejected(TokenRejection::InvalidGrant),
        Err(_) => return TokenOutcome::ServerError,
    }
    let ox_request = OxRequest {
        query: HashMap::new(),
        urlbody: refresh_body(&request),
        auth: None,
    };
    let ProtocolState {
        registrar, issuer, ..
    } = state;
    let generic = Generic {
        registrar: &*registrar,
        authorizer: Vacant,
        issuer,
        solicitor: Vacant,
        scopes: Vacant,
        response: Vacant,
    };
    let mut flow = match oxide_auth::endpoint::RefreshFlow::prepare(generic) {
        Ok(flow) => flow,
        Err(_) => return TokenOutcome::ServerError,
    };
    match flow.execute(ox_request) {
        Ok(response) => match token_outcome(response) {
            TokenOutcome::Rejected(
                TokenRejection::InvalidClient(_) | TokenRejection::InvalidRequest,
            ) => TokenOutcome::Rejected(TokenRejection::InvalidGrant),
            outcome => outcome,
        },
        Err(_) => TokenOutcome::Rejected(TokenRejection::InvalidGrant),
    }
}

pub(super) fn authorization_status(
    state: &ProtocolState,
    transaction: &AuthorizationTransactionId,
) -> AuthorizationStatus {
    match state.transactions.get(transaction) {
        Some(_) => AuthorizationStatus::Pending,
        None => AuthorizationStatus::Unknown,
    }
}

pub(super) fn authorize_login(
    state: &mut ProtocolState,
    login: AuthorizationLogin,
) -> AuthorizationLoginOutcome {
    let request = match state.transactions.get(&login.transaction) {
        Some(request) => request.clone(),
        None => return AuthorizationLoginOutcome::Unknown,
    };
    let outcome = state.authenticator.authenticate(LoginAttempt {
        name: login.name,
        password: login.password,
    });
    let username = match outcome {
        Ok(LoginOutcome::Authenticated(username)) => username,
        Ok(LoginOutcome::InvalidCredentials) | Err(_) => {
            return AuthorizationLoginOutcome::InvalidCredentials;
        }
    };
    state.transactions.remove(&login.transaction);

    let ox_request = OxRequest {
        query: authorization_query(&request),
        urlbody: HashMap::new(),
        auth: None,
    };
    let ProtocolState {
        registrar,
        authorizer,
        ..
    } = state;
    let owner = username.as_str().to_owned();
    let mut solicitor = FnSolicitor(|_: &mut OxRequest, _: oxide_auth::endpoint::Solicitation| {
        OwnerConsent::Authorized(owner.clone())
    });
    let generic = Generic {
        registrar: &*registrar,
        authorizer,
        issuer: Vacant,
        solicitor: &mut solicitor,
        scopes: Vacant,
        response: Vacant,
    };
    let mut flow = match AuthorizationFlow::prepare(Extended::extend_with(generic, addons())) {
        Ok(flow) => flow,
        Err(_) => return AuthorizationLoginOutcome::ServerError,
    };
    match flow.execute(ox_request) {
        Ok(response) => match response.location {
            Some(location) => match crate::types::RedirectUri::new(location.as_str()) {
                Ok(uri) => AuthorizationLoginOutcome::Redirect(AuthorizationRedirect(uri)),
                Err(_) => AuthorizationLoginOutcome::ServerError,
            },
            None => AuthorizationLoginOutcome::InvalidRequest,
        },
        Err(_) => AuthorizationLoginOutcome::InvalidRequest,
    }
}

pub(super) fn lock_error() -> noted::error::NotedError {
    rejected("OAuth protocol state lock poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;
    use crate::oauth::{
        AuthorizationRequest, BeginAuthorizationOutcome, OAuthProtocol, RegisterOAuthClient,
    };
    use crate::service::AuthService;
    use crate::types::{
        AuthorizationResponseType, AuthorizationTransactionId, CodeChallenge, CodeChallengeMethod,
        RedirectUri, SubmittedRedirectUri,
    };

    #[test]
    fn parking_past_1024_drops_the_oldest_pending_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let service = Arc::new(AuthService::new(Arc::new(
            Db::open(&dir.path().join("auth.redb")).unwrap(),
        )));
        let protocol = OAuthProtocol::open(service).unwrap();
        let client = protocol
            .register_client(
                RegisterOAuthClient::new(vec![
                    RedirectUri::new("https://client.example/callback").unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
        let request = AuthorizationRequest::new(
            Some(AuthorizationResponseType::Code),
            Some(client.client_id().clone()),
            Some(SubmittedRedirectUri::submitted(
                "https://client.example/callback",
            )),
            None,
            None,
            Some(CodeChallenge::submitted(
                "0123456789012345678901234567890123456789012",
            )),
            Some(CodeChallengeMethod::S256),
        );
        let BeginAuthorizationOutcome::LoginRequired(first) =
            protocol.begin_authorization(request.clone())
        else {
            panic!("authorization was not parked");
        };
        for _ in 1..MAX_TRANSACTIONS {
            assert!(matches!(
                protocol.begin_authorization(request.clone()),
                BeginAuthorizationOutcome::LoginRequired(_)
            ));
        }
        assert_eq!(
            protocol.authorization_status(&first),
            AuthorizationStatus::Pending
        );

        assert!(matches!(
            protocol.begin_authorization(request),
            BeginAuthorizationOutcome::LoginRequired(_)
        ));
        assert_eq!(
            protocol.authorization_status(&first),
            AuthorizationStatus::Unknown
        );
        assert_eq!(
            protocol.authorization_status(&AuthorizationTransactionId::submitted("missing")),
            AuthorizationStatus::Unknown
        );
    }
}
