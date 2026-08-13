use std::collections::HashMap;

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::credentials::{Credential, CredentialStore};
use noted::HttpUrl;
use noted::error::{Result, http_error, io_error, rejected, unavailable};
use noted::types::{Ttl, UnixEpochSeconds};
use noted::util::random_token;
use noted::{Bearer, PolicyFragment};
use noted_auth::authority::Revoke;
use noted_auth::credential::{Macaroon, MacaroonId};
use noted_auth::types::{ClientId, Fingerprint, RefreshToken, SessionId};

async fn get_json(client: &reqwest::Client, url: &HttpUrl) -> Result<Value> {
    let resp = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|e| http_error(format!("cannot reach {url}"), e))?;
    if !resp.status().is_success() {
        return Err(unavailable(format!("{url}: HTTP {}", resp.status())));
    }
    resp.json()
        .await
        .map_err(|e| http_error(format!("{url}"), e))
}

async fn post_form(
    client: &reqwest::Client,
    url: &HttpUrl,
    form: &[(&str, &str)],
) -> Result<Value> {
    let resp = client
        .post(url.as_str())
        .form(form)
        .send()
        .await
        .map_err(|e| http_error(format!("cannot reach {url}"), e))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(rejected(format!("{url}: {detail}")));
    }
    Ok(body)
}

fn pkce() -> (String, String) {
    let verifier = random_token(48);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    (verifier, challenge)
}

pub async fn login(url: &HttpUrl) -> Result<Credential> {
    let client = reqwest::Client::new();

    let meta = get_json(&client, &url.join(".well-known/oauth-authorization-server")).await?;
    let auth_ep = endpoint(&meta, "authorization_endpoint")?;
    let token_ep = endpoint(&meta, "token_endpoint")?;
    let reg_ep = endpoint(&meta, "registration_endpoint")?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| io_error("cannot bind loopback listener", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| io_error("loopback addr", e))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let reg: Value = client
        .post(reg_ep.as_str())
        .json(&json!({ "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none" }))
        .send()
        .await
        .map_err(|e| http_error(format!("cannot reach {reg_ep}"), e))?
        .json()
        .await
        .map_err(|e| http_error(format!("{reg_ep}"), e))?;
    let client_id = reg
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("registration returned no client_id"))?
        .to_string();

    let (verifier, challenge) = pkce();
    let state = random_token(24);
    let mut authorize = auth_ep.as_url().clone();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state);

    eprintln!("Opening your browser to log in. If it does not open, visit:\n  {authorize}");
    let _ = open::that(authorize.as_str());

    let params = wait_for_code(&listener).await?;
    if params.get("state").map(String::as_str) != Some(state.as_str()) {
        return Err(rejected("login failed: state mismatch"));
    }
    let code = params
        .get("code")
        .ok_or_else(|| rejected("login failed: no code returned"))?;

    let tokens = post_form(
        &client,
        &token_ep,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", &verifier),
            ("client_id", &client_id),
            ("redirect_uri", &redirect_uri),
        ],
    )
    .await?;

    let access_token = tokens
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("token endpoint returned no access_token"))?
        .to_string();
    let refresh_token = tokens
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::to_string);
    let now = UnixEpochSeconds::now()?;
    let expires_at = tokens
        .get("expires_in")
        .and_then(Value::as_u64)
        .map(|s| now + Ttl::from_secs(s));

    let user = Macaroon::from_encoded(access_token.clone())
        .and_then(|access| access.owner())
        .map(|owner| owner.to_string())
        .ok();

    Ok(Credential {
        user,
        client_id: ClientId::new(client_id),
        access_token: Bearer::new(access_token),
        refresh_token: refresh_token.map(RefreshToken::new),
        expires_at,
    })
}

/// What a caller asks a server to mint for it.
pub struct Ask {
    pub policy: PolicyFragment,
    pub ttl: Ttl,
    pub session: Option<SessionId>,
}

/// What the server minted in answer.
#[derive(serde::Deserialize)]
pub struct Granted {
    pub macaroon: Macaroon,
    pub token_id: MacaroonId,
    pub fingerprint: Fingerprint,
    pub expires_at: UnixEpochSeconds,
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

    /// The stored login's access macaroon, refreshed when it has expired.
    pub async fn credential(&self) -> Result<Option<Macaroon>> {
        if let Some(token) = &self.token_override {
            return self.as_macaroon(token).map(Some);
        }
        let Some(cred) = self.store.get(&self.url)? else {
            return Ok(None);
        };
        let now = UnixEpochSeconds::now()?;
        let expired = cred.expires_at.map(|e| now >= e).unwrap_or(false);
        if !expired {
            return self.as_macaroon(cred.access_token.expose()).map(Some);
        }
        let Some(rt) = cred.refresh_token.clone() else {
            return Err(rejected("session expired; run `noted auth login` again"));
        };
        match refresh(&self.url, cred.client_id.as_str(), rt.expose()).await {
            Ok((access, refresh_token, expires_at)) => {
                let updated = Credential {
                    access_token: Bearer::new(access.clone()),
                    refresh_token: refresh_token.map(RefreshToken::new),
                    expires_at,
                    ..cred
                };
                self.store.set(&self.url, &updated)?;
                self.as_macaroon(&access).map(Some)
            }
            Err(_) => Err(rejected("session expired; run `noted auth login` again")),
        }
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
        let body = json!({
            "policy": ask.policy,
            "ttl": ask.ttl.as_secs(),
            "session": ask.session.as_ref().map(|s| s.as_str()),
        });
        let answer = post_json(&endpoint, credential.expose(), &body).await?;
        serde_json::from_value(answer)
            .map_err(|e| unavailable(format!("{endpoint}: unreadable answer: {e}")))
    }

    pub async fn revoke(&self, selector: Revoke) -> Result<usize> {
        let credential = self
            .credential()
            .await?
            .ok_or_else(|| rejected("not logged in; run `noted auth login`"))?;
        let body = match &selector {
            Revoke::All => json!({ "all": true }),
            Revoke::Session(s) => json!({ "session": s.as_str() }),
            Revoke::Token(id) => json!({ "id": id.as_str() }),
            Revoke::Label(_) => {
                return Err(rejected(
                    "a label names a credential only to its own server",
                ));
            }
        };
        let endpoint = self.url.join("macaroon/revoke");
        let answer = post_json(&endpoint, credential.expose(), &body).await?;
        Ok(answer
            .get("revoked")
            .and_then(Value::as_u64)
            .unwrap_or_default() as usize)
    }
}

async fn post_json(endpoint: &HttpUrl, bearer: &str, body: &Value) -> Result<Value> {
    let resp = reqwest::Client::new()
        .post(endpoint.as_str())
        .bearer_auth(bearer)
        .json(body)
        .send()
        .await
        .map_err(|e| http_error(format!("cannot reach {endpoint}"), e))?;
    let status = resp.status();
    let answer: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = answer
            .get("detail")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(rejected(format!("{endpoint}: {detail}")));
    }
    Ok(answer)
}

pub async fn refresh(
    url: &HttpUrl,
    client_id: &str,
    refresh_token: &str,
) -> Result<(String, Option<String>, Option<UnixEpochSeconds>)> {
    let client = reqwest::Client::new();
    let meta = get_json(&client, &url.join(".well-known/oauth-authorization-server")).await?;
    let token_ep = endpoint(&meta, "token_endpoint")?;
    let tokens = post_form(
        &client,
        &token_ep,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ],
    )
    .await?;
    let access = tokens
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("refresh returned no access_token"))?
        .to_string();
    let new_refresh = tokens
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| Some(refresh_token.to_string()));
    let now = UnixEpochSeconds::now()?;
    let expires_at = tokens
        .get("expires_in")
        .and_then(Value::as_u64)
        .map(|s| now + Ttl::from_secs(s));
    Ok((access, new_refresh, expires_at))
}

fn endpoint(meta: &Value, key: &str) -> Result<HttpUrl> {
    let raw = meta
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable(format!("discovery document missing {key}")))?;
    raw.parse()
        .map_err(|e| unavailable(format!("discovery {key} is not a valid URL: {e}")))
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
