use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use noted::PolicyFragment;
use noted_auth::authority::{
    Denial, Mint, Minted, Minter, OpenAuthority, OriginAuthority, Verified, Verifier,
};
use serde_json::{Value, json};

pub(crate) async fn run_blocking<F, T>(operation: F) -> noted::error::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            noted::error::unavailable(format!("blocking authentication task failed: {error}"))
        })
}

#[derive(Clone)]
pub struct AuthState {
    verifier: Arc<dyn Verifier>,
    minter: Option<Arc<dyn Minter>>,
    oauth: Option<Arc<crate::oauth::OAuthProvider>>,
    relay: Option<Arc<crate::relay::Relay>>,
}

impl AuthState {
    pub async fn origin(
        service: Arc<noted_auth::AuthService>,
        oauth: Option<Arc<crate::oauth::OAuthProvider>>,
    ) -> noted::error::Result<AuthState> {
        let authority = run_blocking(move || Arc::new(OriginAuthority::new(service))).await?;
        Ok(AuthState {
            verifier: authority.clone(),
            minter: Some(authority),
            oauth,
            relay: None,
        })
    }

    pub fn open() -> AuthState {
        AuthState {
            verifier: Arc::new(OpenAuthority),
            minter: None,
            oauth: None,
            relay: None,
        }
    }

    pub(crate) fn relay(relay: Arc<crate::relay::Relay>) -> AuthState {
        AuthState {
            verifier: Arc::new(OpenAuthority),
            minter: None,
            oauth: None,
            relay: Some(relay),
        }
    }

    pub(crate) fn relay_self_error(
        &self,
        error: noted::error::NotedError,
    ) -> noted::error::NotedError {
        match &self.relay {
            Some(relay) => relay.self_error(error),
            None => error,
        }
    }

    pub fn verifier(&self) -> &Arc<dyn Verifier> {
        &self.verifier
    }

    pub fn minter(&self) -> Option<&Arc<dyn Minter>> {
        self.minter.as_ref()
    }

    pub fn oauth(&self) -> Option<&Arc<crate::oauth::OAuthProvider>> {
        self.oauth.as_ref()
    }
}

pub(crate) fn routes(state: AuthState) -> Router {
    let mut router = Router::new();
    if state.oauth().is_some() {
        router = crate::oauth::mount_routes(router);
    }
    router.route("/macaroon/mint", post(mint)).with_state(state)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn detail(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "detail": message }))).into_response()
}

fn denied(denial: &Denial) -> Response {
    match denial {
        Denial::Malformed(message) => detail(StatusCode::BAD_REQUEST, message),
        Denial::Unauthorized(_) => detail(StatusCode::UNAUTHORIZED, "unauthorized"),
        Denial::Forbidden(message) => detail(StatusCode::FORBIDDEN, message),
    }
}

async fn caller(state: &AuthState, headers: &HeaderMap) -> Result<Verified, Box<Response>> {
    let credential = bearer(headers).map(noted_auth::types::CredentialPresentation::submitted);
    let verifier = state.verifier().clone();
    match run_blocking(move || verifier.verify(credential.as_ref())).await {
        Ok(Ok(verified)) => Ok(verified),
        Ok(Err(denial)) => Err(Box::new(denied(&denial))),
        Err(error) => Err(Box::new(detail(
            StatusCode::SERVICE_UNAVAILABLE,
            &state.relay_self_error(error).to_string(),
        ))),
    }
}

fn minter(state: &AuthState) -> Result<Arc<dyn Minter>, Box<Response>> {
    state
        .minter()
        .cloned()
        .ok_or_else(|| Box::new(StatusCode::NOT_FOUND.into_response()))
}

fn operation_error(state: &AuthState, error: noted::error::NotedError) -> Response {
    let error = state.relay_self_error(error);
    let status = if error.is_rejection() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    detail(status, &error.to_string())
}

async fn mint(State(state): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    let minter = match minter(&state) {
        Ok(minter) => minter,
        Err(response) => return *response,
    };
    let caller = match caller(&state, &headers).await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    let asked: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let policy = match asked.get("policy") {
        Some(value) => match serde_json::from_value::<PolicyFragment>(value.clone()) {
            Ok(policy) => policy,
            Err(error) => return detail(StatusCode::BAD_REQUEST, &error.to_string()),
        },
        None => PolicyFragment::default(),
    };
    let ask = Mint { policy };
    match run_blocking(move || minter.mint(&caller, &ask)).await {
        Ok(Ok(Minted {
            macaroon,
            token_id,
            fingerprint,
        })) => Json(json!({
            "macaroon": macaroon.expose(),
            "token_id": token_id,
            "fingerprint": fingerprint,
        }))
        .into_response(),
        Ok(Err(error)) => operation_error(&state, error),
        Err(error) => detail(
            StatusCode::SERVICE_UNAVAILABLE,
            &state.relay_self_error(error).to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noted::Transport;

    async fn relay_state() -> (crate::serve::Bound, AuthState) {
        let bound = crate::serve::Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .bind()
        .await
        .unwrap();
        let relay = Arc::new(
            crate::relay::Relay::open(
                None,
                noted::PolicyFragment::default(),
                "http://upstream.test/internal".parse().unwrap(),
                &bound,
                Transport::Router(axum::Router::new()),
            )
            .unwrap(),
        );
        (bound, AuthState::relay(relay))
    }

    async fn blocking_error() -> noted::error::NotedError {
        run_blocking(|| panic!("authentication task failed"))
            .await
            .unwrap_err()
    }

    #[tokio::test]
    async fn relay_caller_blocking_failure_names_the_relays_listener_endpoint() {
        let (bound, state) = relay_state().await;
        let error = state.relay_self_error(blocking_error().await);
        assert!(
            error
                .to_string()
                .starts_with(&format!("{}: ", bound.endpoint()))
        );
        assert!(
            error
                .to_string()
                .contains("blocking authentication task failed")
        );
    }

    #[tokio::test]
    async fn relay_mint_blocking_failure_names_the_relays_listener_endpoint() {
        let (bound, state) = relay_state().await;
        let error = state.relay_self_error(blocking_error().await);
        assert!(
            error
                .to_string()
                .starts_with(&format!("{}: ", bound.endpoint()))
        );
        assert!(
            error
                .to_string()
                .contains("blocking authentication task failed")
        );
    }

    #[tokio::test]
    async fn relay_mint_domain_failure_keeps_its_class_detail_and_listener_endpoint() {
        let (bound, state) = relay_state().await;
        let response = operation_error(&state, noted::error::rejected("mint refused"));

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["detail"],
            format!("{}: mint refused", bound.endpoint())
        );
    }
}
