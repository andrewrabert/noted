use std::sync::Arc;

use axum::Router;

pub mod oauth;
pub mod password;

pub use oauth::{AuthService, OAuthProvider};

#[derive(Clone)]
pub struct AuthState {
    auth: Arc<AuthService>,
    oauth: Option<Arc<OAuthProvider>>,
}

impl AuthState {
    pub fn new(auth: Arc<AuthService>, oauth: Option<Arc<OAuthProvider>>) -> AuthState {
        AuthState { auth, oauth }
    }

    pub fn auth(&self) -> &Arc<AuthService> {
        &self.auth
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
    oauth::macaroon::mount_routes(router).with_state(state)
}
