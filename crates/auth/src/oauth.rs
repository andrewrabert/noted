use crate::types::{
    AuthorizationCode, AuthorizationResponseType, AuthorizationTransactionId, ClientId,
    ClientState, CodeChallenge, CodeChallengeMethod, CodeVerifier, GrantedScope, LoginName,
    OAuthAccessToken, OAuthTokenType, Password, RedirectUri, RefreshToken,
    RequestedScope, SubmittedRedirectUri,
};
use noted::error::{Result, rejected};
use noted::types::UnixEpochSeconds;
use noted::util::random_token;

mod engine;
mod issuer;

use engine::ProtocolState;

pub struct OAuthProtocol {
    service: std::sync::Arc<crate::service::AuthService>,
    state: std::sync::Mutex<ProtocolState>,
}

impl OAuthProtocol {
    pub fn open(service: std::sync::Arc<crate::service::AuthService>) -> Result<OAuthProtocol> {
        let state = engine::open(service.clone())?;
        Ok(OAuthProtocol {
            service,
            state: std::sync::Mutex::new(state),
        })
    }

    pub fn register_client(&self, request: RegisterOAuthClient) -> Result<OAuthClient> {
        let mut state = self.state.lock().map_err(|_| engine::lock_error())?;
        engine::register_client(&mut state, &self.service, request)
    }

    pub fn begin_authorization(&self, request: AuthorizationRequest) -> BeginAuthorizationOutcome {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return BeginAuthorizationOutcome::ServerError,
        };
        engine::begin_authorization(&mut state, request)
    }

    pub fn authorization_status(
        &self,
        transaction: &AuthorizationTransactionId,
    ) -> AuthorizationStatus {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return AuthorizationStatus::Unknown,
        };
        engine::authorization_status(&state, transaction)
    }

    pub fn authorize_login(&self, login: AuthorizationLogin) -> AuthorizationLoginOutcome {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return AuthorizationLoginOutcome::ServerError,
        };
        engine::authorize_login(&mut state, login)
    }

    pub fn exchange_token(&self, request: TokenRequest) -> TokenOutcome {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return TokenOutcome::ServerError,
        };
        match request {
            TokenRequest::AuthorizationCode(exchange) => {
                engine::exchange_authorization_code(&mut state, exchange)
            }
            TokenRequest::RefreshToken(exchange) => {
                engine::exchange_refresh_token(&mut state, exchange)
            }
            TokenRequest::Unsupported => {
                TokenOutcome::Rejected(TokenRejection::UnsupportedGrantType)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterOAuthClient {
    redirect_uris: Vec<RedirectUri>,
}

impl RegisterOAuthClient {
    pub fn new(redirect_uris: Vec<RedirectUri>) -> Result<RegisterOAuthClient> {
        if redirect_uris.is_empty() {
            return Err(rejected("OAuth client requires at least one redirect URI"));
        }
        Ok(RegisterOAuthClient { redirect_uris })
    }

    pub fn redirect_uris(&self) -> &[RedirectUri] {
        &self.redirect_uris
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthClient {
    client_id: ClientId,
    redirect_uris: Vec<RedirectUri>,
    issued_at: UnixEpochSeconds,
}

impl OAuthClient {
    pub fn registered(request: RegisterOAuthClient) -> Result<OAuthClient> {
        Ok(OAuthClient {
            client_id: ClientId::new(random_token(24)),
            redirect_uris: request.redirect_uris,
            issued_at: UnixEpochSeconds::now()?,
        })
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn redirect_uris(&self) -> &[RedirectUri] {
        &self.redirect_uris
    }

    pub fn issued_at(&self) -> UnixEpochSeconds {
        self.issued_at
    }

    pub(crate) fn from_persisted(
        client_id: ClientId,
        issued_at: UnixEpochSeconds,
        request: RegisterOAuthClient,
    ) -> Result<OAuthClient> {
        if client_id.as_str().is_empty() {
            return Err(rejected("OAuth client requires a client id"));
        }
        Ok(OAuthClient {
            client_id,
            redirect_uris: request.redirect_uris,
            issued_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    response_type: Option<AuthorizationResponseType>,
    client_id: Option<ClientId>,
    redirect_uri: Option<SubmittedRedirectUri>,
    scope: Option<RequestedScope>,
    state: Option<ClientState>,
    code_challenge: Option<CodeChallenge>,
    code_challenge_method: Option<CodeChallengeMethod>,
}

impl AuthorizationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        response_type: Option<AuthorizationResponseType>,
        client_id: Option<ClientId>,
        redirect_uri: Option<SubmittedRedirectUri>,
        scope: Option<RequestedScope>,
        state: Option<ClientState>,
        code_challenge: Option<CodeChallenge>,
        code_challenge_method: Option<CodeChallengeMethod>,
    ) -> AuthorizationRequest {
        AuthorizationRequest {
            response_type,
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationLogin {
    transaction: AuthorizationTransactionId,
    name: LoginName,
    password: Password,
}

impl AuthorizationLogin {
    pub fn new(
        transaction: AuthorizationTransactionId,
        name: LoginName,
        password: Password,
    ) -> AuthorizationLogin {
        AuthorizationLogin {
            transaction,
            name,
            password,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationCodeExchange {
    code: Option<AuthorizationCode>,
    redirect_uri: Option<SubmittedRedirectUri>,
    client_id: Option<ClientId>,
    code_verifier: Option<CodeVerifier>,
}

impl AuthorizationCodeExchange {
    pub fn new(
        code: Option<AuthorizationCode>,
        redirect_uri: Option<SubmittedRedirectUri>,
        client_id: Option<ClientId>,
        code_verifier: Option<CodeVerifier>,
    ) -> AuthorizationCodeExchange {
        AuthorizationCodeExchange {
            code,
            redirect_uri,
            client_id,
            code_verifier,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenExchange {
    refresh_token: Option<RefreshToken>,
    client_id: Option<ClientId>,
    scope: Option<RequestedScope>,
}

impl RefreshTokenExchange {
    pub fn new(
        refresh_token: Option<RefreshToken>,
        client_id: Option<ClientId>,
        scope: Option<RequestedScope>,
    ) -> RefreshTokenExchange {
        RefreshTokenExchange {
            refresh_token,
            client_id,
            scope,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenRequest {
    AuthorizationCode(AuthorizationCodeExchange),
    RefreshToken(RefreshTokenExchange),
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRedirect(RedirectUri);
impl AuthorizationRedirect {
    pub fn as_uri(&self) -> &RedirectUri {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeginAuthorizationOutcome {
    LoginRequired(AuthorizationTransactionId),
    Redirect(AuthorizationRedirect),
    InvalidRequest,
    ServerError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationStatus {
    Pending,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationLoginOutcome {
    Redirect(AuthorizationRedirect),
    Unknown,
    InvalidCredentials,
    InvalidRequest,
    ServerError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientAuthenticationScheme {
    Basic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenRejection {
    InvalidRequest,
    InvalidClient(ClientAuthenticationScheme),
    UnsupportedGrantType,
    InvalidGrant,
    InvalidScope,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OAuthTokens {
    access_token: OAuthAccessToken,
    refresh_token: RefreshToken,
    token_type: OAuthTokenType,
    scope: GrantedScope,
}

impl OAuthTokens {
    pub fn access_token(&self) -> &OAuthAccessToken {
        &self.access_token
    }
    pub fn refresh_token(&self) -> &RefreshToken {
        &self.refresh_token
    }
    pub fn token_type(&self) -> &OAuthTokenType {
        &self.token_type
    }
    pub fn scope(&self) -> &GrantedScope {
        &self.scope
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum TokenOutcome {
    Issued(OAuthTokens),
    Rejected(TokenRejection),
    ServerError,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn poisoned_protocol_state_maps_token_exchange_to_server_error() {
        let directory = tempfile::tempdir().unwrap();
        let service = Arc::new(crate::service::AuthService::new(Arc::new(
            crate::db::Db::open(&directory.path().join("auth.redb")).unwrap(),
        )));
        let protocol = Arc::new(OAuthProtocol::open(service).unwrap());
        let poisoner = Arc::clone(&protocol);

        let panic = std::thread::spawn(move || {
            let _guard = poisoner.state.lock().unwrap();
            panic!("intentional protocol-state mutex poison");
        });

        assert!(panic.join().is_err());
        assert!(matches!(
            protocol.exchange_token(TokenRequest::Unsupported),
            TokenOutcome::ServerError
        ));
    }
}
