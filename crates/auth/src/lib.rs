use std::sync::Arc;

use axum::Router;

pub mod admin;
pub mod authority;
pub mod credential;
pub mod db;
pub mod oauth;
pub mod password;
pub mod routes;
pub mod service;
pub mod types;

pub use authority::{
    Denial, Minter, OpenAuthority, OriginAuthority, RelayCredential, Verified, Verifier, Withdrawn,
};
pub use credential::Macaroon;
pub use db::Db;
pub use oauth::OAuthProvider;
pub use service::AuthService;

/// Who a server admits and what it hands out, decided once at startup.
#[derive(Clone)]
pub struct AuthState {
    verifier: Arc<dyn Verifier>,
    minter: Option<Arc<dyn Minter>>,
    oauth: Option<Arc<OAuthProvider>>,
}

impl AuthState {
    pub fn origin(service: Arc<AuthService>, oauth: Option<Arc<OAuthProvider>>) -> AuthState {
        let authority = Arc::new(OriginAuthority::new(service));
        AuthState {
            verifier: authority.clone(),
            minter: Some(authority),
            oauth,
        }
    }

    pub fn open() -> AuthState {
        AuthState {
            verifier: Arc::new(OpenAuthority),
            minter: None,
            oauth: None,
        }
    }

    pub fn relay(credential: Arc<RelayCredential>) -> AuthState {
        AuthState {
            verifier: credential.clone(),
            minter: Some(credential),
            oauth: None,
        }
    }

    pub fn verifier(&self) -> &Arc<dyn Verifier> {
        &self.verifier
    }

    pub fn minter(&self) -> Option<&Arc<dyn Minter>> {
        self.minter.as_ref()
    }

    pub fn oauth(&self) -> Option<&Arc<OAuthProvider>> {
        self.oauth.as_ref()
    }
}

pub fn routes(state: AuthState) -> Router {
    let mut router = Router::new();
    if state.oauth().is_some() {
        router = oauth::mount_routes(router);
    }
    routes::mount_routes(router).with_state(state)
}
