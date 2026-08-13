use noted::error::{Result, rejected};
use noted::{Bearer, Endpoint, PolicyFragment};
use noted_auth::credential::{Caveat, Macaroon};
use noted_client::authclient::Session;
use noted_client::credentials::CredentialStore;

/// The credential this invocation holds: `NOTED_TOKEN`, else the stored login
/// of an http(s) endpoint. A token that is not a macaroon is refused, naming
/// the endpoint.
pub async fn held(
    endpoint: &Endpoint,
    token: Option<&str>,
    store: &CredentialStore,
) -> Result<Option<Macaroon>> {
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        return Macaroon::from_encoded(token.to_string())
            .map(Some)
            .map_err(|_| {
                rejected(format!(
                    "{endpoint}: that credential is not a macaroon; log in again"
                ))
            });
    }
    match endpoint.tcp() {
        Some(url) => Session::open(url, None, store.clone()).credential().await,
        None => Ok(None),
    }
}

/// The bearer this invocation carries: the credential it holds, extended by a
/// `policy=` caveat where the fragment asks for one; a fresh root nothing
/// keeps where it holds none and the fragment asks; no bearer otherwise.
pub async fn client_bearer(
    endpoint: &Endpoint,
    token: Option<&str>,
    policy: &PolicyFragment,
    store: &CredentialStore,
) -> Result<Option<Bearer>> {
    let held = held(endpoint, token, store).await?;
    let confines = *policy != PolicyFragment::default();
    let credential = match (held, confines) {
        (Some(held), false) => held,
        (Some(held), true) => held.extended(&[Caveat::Policy(policy.clone())])?,
        (None, true) => Macaroon::ephemeral()?.extended(&[Caveat::Policy(policy.clone())])?,
        (None, false) => return Ok(None),
    };
    Ok(Some(Bearer::new(credential.expose())))
}
