//! The client half of the OAuth protocol: the authorize URL a caller
//! navigates to, the form POST that answers a redirect, and the code
//! exchange. Every request goes out through the upstream's own transport.

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Reply, Upstream};
use noted::error::{NotedError, Result, rejected, unavailable};
use noted::httpurl::HttpUrl;
use noted::types::Bearer;

/// The built-in public client every noted server knows.
pub use noted::oauth::WEB_CLIENT_ID;

pub struct Tokens {
    pub access: Bearer,
    pub refresh: Option<String>,
}

/// base64url(sha-256(verifier)) without padding.
pub fn code_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The built-in client's redirect URI: the base with exactly one trailing
/// slash.
pub fn web_redirect_uri(base: &HttpUrl) -> String {
    format!("{}/", base.as_str().trim_end_matches('/'))
}

/// `<base>/authorize?response_type=code&client_id=&redirect_uri=
/// &code_challenge=&code_challenge_method=S256&state=`
pub fn authorize_url(
    base: &HttpUrl,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> HttpUrl {
    base.join_query(
        "authorize",
        &[
            ("response_type", "code".to_string()),
            ("client_id", client_id.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("code_challenge", challenge.to_string()),
            ("code_challenge_method", "S256".to_string()),
            ("state", state.to_string()),
        ],
    )
}

impl Upstream {
    /// POST /register for one public client with `token_endpoint_auth_method:
    /// none`; answers its client id.
    pub async fn register_client(&self, redirect_uri: &str) -> Result<String> {
        let body = serde_json::to_vec(
            &json!({ "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none" }),
        )
        .unwrap_or_default();
        let reply = self.post("register", &[], None, None, body).await?;
        if reply.status >= 400 {
            return Err(rejected(format!(
                "{}: {}",
                self.base().join("register"),
                failure(&reply)
            )));
        }
        answer(&reply)?
            .get("client_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| unavailable("registration returned no client_id"))
    }

    /// POST /login as a form; 200 answers the redirect the server named.
    pub async fn submit_txn(&self, txn: &str, username: &str, password: &str) -> Result<String> {
        let target = self.base().join("login");
        let reply = post_form(
            self,
            "login",
            &[("txn", txn), ("username", username), ("password", password)],
        )
        .await?;
        let body = answer(&reply).unwrap_or(Value::Null);
        let code = body.get("error").and_then(Value::as_str);
        let redirect = body
            .get("redirect")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match (reply.status, code) {
            (200, _) => Ok(redirect),
            (401, Some("invalid_credentials")) => Err(NotedError::InvalidCredentials),
            (400, Some("unknown_txn")) => Err(NotedError::UnknownTxn),
            _ => Err(rejected(format!("{target}: {}", failure(&reply)))),
        }
    }

    /// POST /token as `client_id` with the verifier; the id must be the one
    /// that authorized.
    pub async fn exchange_code(
        &self,
        client_id: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<Tokens> {
        let target = self.base().join("token");
        let reply = post_form(
            self,
            "token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", verifier),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
            ],
        )
        .await?;
        if reply.status >= 400 {
            return Err(rejected(format!("{target}: {}", failure(&reply))));
        }
        let body = answer(&reply)?;
        let access = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| unavailable("token endpoint returned no access_token"))?
            .to_string();
        Ok(Tokens {
            access: Bearer::new(access),
            refresh: body
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

async fn post_form(upstream: &Upstream, path: &str, form: &[(&str, &str)]) -> Result<Reply> {
    let target = upstream.base().join(path);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().copied())
        .finish()
        .into_bytes();
    upstream
        .send(
            &target,
            &[("content-type", "application/x-www-form-urlencoded")],
            body,
        )
        .await
}

fn answer(reply: &Reply) -> Result<Value> {
    serde_json::from_slice(&reply.body).map_err(|e| unavailable(format!("unreadable answer: {e}")))
}

/// The `error_description`, else the `error`, of an OAuth error body; else
/// `HTTP <status>`.
fn failure(reply: &Reply) -> String {
    answer(reply)
        .ok()
        .and_then(|body| {
            body.get("error_description")
                .or_else(|| body.get("error"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("HTTP {}", reply.status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_s256_challenge_matches_the_rfc_7636_appendix_b_vector() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_authorize_url_carries_the_client_redirect_challenge_method_and_state() {
        let base: HttpUrl = "https://notes.example".parse().unwrap();
        let url = authorize_url(&base, WEB_CLIENT_ID, "https://notes.example/", "chal", "st");
        let query: std::collections::HashMap<String, String> = url
            .as_url()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(url.as_url().path(), "/authorize");
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], WEB_CLIENT_ID);
        assert_eq!(query["redirect_uri"], "https://notes.example/");
        assert_eq!(query["code_challenge"], "chal");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["state"], "st");
    }

    #[test]
    fn the_web_redirect_uri_is_the_base_with_one_trailing_slash() {
        let bare: HttpUrl = "https://notes.example".parse().unwrap();
        let slashed: HttpUrl = "https://notes.example/".parse().unwrap();
        assert_eq!(web_redirect_uri(&bare), "https://notes.example/");
        assert_eq!(web_redirect_uri(&slashed), "https://notes.example/");
    }
}
