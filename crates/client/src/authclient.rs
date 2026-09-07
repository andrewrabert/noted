use std::collections::HashMap;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::credentials::{Credential, CredentialStore};
use crate::{Transport, Upstream};
use noted::error::{Result, io_error, rejected, unavailable};
use noted::util::random_token;
use noted::{Bearer, HttpUrl, PolicyFragment};
use noted_auth::credential::{Macaroon, MacaroonId};
use noted_auth::types::{ClientId, Fingerprint, RefreshToken};

pub async fn login(url: &HttpUrl) -> Result<Credential> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| io_error("cannot bind loopback listener", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| io_error("loopback addr", e))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let upstream = Upstream::open(url.as_str().parse()?, Transport::Real)?;
    let client_id = upstream.register_client(&redirect_uri).await?;
    let verifier = random_token(48);
    let state = random_token(24);
    let authorize = crate::oauth::authorize_url(
        url,
        &client_id,
        &redirect_uri,
        &crate::oauth::code_challenge(&verifier),
        &state,
    );

    eprintln!("Opening your browser to log in. If it does not open, visit:\n  {authorize}");
    let _ = open::that(authorize.as_str());

    let params = wait_for_code(&listener).await?;
    if params.get("state").map(String::as_str) != Some(state.as_str()) {
        return Err(rejected("login failed: state mismatch"));
    }
    let code = params
        .get("code")
        .ok_or_else(|| rejected("login failed: no code returned"))?;
    let tokens = upstream
        .exchange_code(&client_id, code, &verifier, &redirect_uri)
        .await?;

    let access_token = tokens.access.expose().to_string();
    let user = Macaroon::from_encoded(access_token.clone())
        .and_then(|access| access.owner())
        .map(|owner| owner.to_string())
        .ok();

    Ok(Credential {
        user,
        client_id: ClientId::new(client_id),
        access_token: Bearer::new(access_token),
        refresh_token: tokens.refresh.map(RefreshToken::new),
    })
}

/// What a caller asks a server to mint for it.
pub struct Ask {
    pub policy: PolicyFragment,
}

/// What the server minted in answer.
#[derive(serde::Deserialize)]
pub struct Granted {
    pub macaroon: Macaroon,
    pub token_id: MacaroonId,
    pub fingerprint: Fingerprint,
}

pub struct Session {
    url: HttpUrl,
    token_override: Option<String>,
    store: CredentialStore,
}

impl Session {
    pub fn open(url: &HttpUrl, token_override: Option<&str>, store: CredentialStore) -> Session {
        Session {
            url: url.clone(),
            token_override: token_override.filter(|s| !s.is_empty()).map(str::to_string),
            store,
        }
    }

    /// The stored login's access macaroon.
    pub async fn credential(&self) -> Result<Option<Macaroon>> {
        if let Some(token) = &self.token_override {
            return self.as_macaroon(token).map(Some);
        }
        let Some(cred) = self.store.get(&self.url)? else {
            return Ok(None);
        };
        self.as_macaroon(cred.access_token.expose()).map(Some)
    }

    fn as_macaroon(&self, token: &str) -> Result<Macaroon> {
        Macaroon::from_encoded(token.to_string()).map_err(|_| {
            rejected(format!(
                "{}: that credential is not a macaroon; log in again",
                self.url
            ))
        })
    }

    pub async fn mint(&self, ask: &Ask) -> Result<Granted> {
        let credential = self
            .credential()
            .await?
            .ok_or_else(|| rejected("not logged in; run `noted auth login`"))?;
        let endpoint = self.url.join("macaroon/mint");
        let body = serde_json::to_vec(&json!({ "policy": ask.policy })).unwrap_or_default();
        let credential = Bearer::new(credential.expose().to_string());
        let reply = Upstream::open(self.url.as_str().parse()?, Transport::Real)?
            .post("macaroon/mint", &[], Some(&credential), None, body)
            .await?;
        if reply.status >= 400 {
            let detail = reply
                .detail()
                .unwrap_or_else(|| format!("HTTP {}", reply.status));
            return Err(rejected(format!("{endpoint}: {detail}")));
        }
        let answer: Value = serde_json::from_slice(&reply.body)
            .map_err(|e| unavailable(format!("{endpoint}: unreadable answer: {e}")))?;
        serde_json::from_value(answer)
            .map_err(|e| unavailable(format!("{endpoint}: unreadable answer: {e}")))
    }
}

async fn wait_for_code(listener: &TcpListener) -> Result<HashMap<String, String>> {
    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| io_error("loopback accept", e))?;
    let mut buf = [0u8; 8192];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| io_error("loopback read", e))?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let target = req
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let params: HashMap<String, String> = reqwest::Url::parse(&format!("http://callback/?{query}"))
        .map(|parsed| parsed.query_pairs().into_owned().collect())
        .unwrap_or_default();
    let page = "<!doctype html><html><body><h2>noted</h2><p>Login complete — you can close this tab.</p></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        page.len(),
        page
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    Ok(params)
}
