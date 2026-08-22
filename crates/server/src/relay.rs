use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, http::HeaderValue};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use noted::error::{NotedError, Result, io_error};
use noted::{Bearer, Endpoint, Transport, Upstream};
use noted_auth::authority::{Minter, RelayCredential, Verified};

use crate::auth::run_blocking;
use crate::serve::{Bound, ListenerEndpoint};

/// The MCP endpoint every relayed JSON-RPC message is posted to.
const MCP_PATH: &str = "mcp";

/// rmcp answers a stateless call only when both content types are acceptable.
const MCP_ACCEPT: &str = "application/json, text/event-stream";

/// A domain-blind pipe: it re-mints the caller's credential from its own and
/// copies bodies through.
pub struct Relay {
    credential: Arc<RelayCredential>,
    upstream: Upstream,
    listener_endpoint: Option<Arc<ListenerEndpoint>>,
}

impl Relay {
    pub fn open(
        credential: Arc<RelayCredential>,
        upstream_endpoint: Endpoint,
        bound: &Bound,
        transport: Transport,
    ) -> Result<Relay> {
        Ok(Relay {
            credential,
            upstream: Upstream::open(upstream_endpoint, transport)?,
            listener_endpoint: Some(bound.endpoint().clone()),
        })
    }

    pub fn open_stdio(
        credential: Arc<RelayCredential>,
        upstream_endpoint: Endpoint,
        transport: Transport,
    ) -> Result<Relay> {
        Ok(Relay {
            credential,
            upstream: Upstream::open(upstream_endpoint, transport)?,
            listener_endpoint: None,
        })
    }

    pub fn credential(&self) -> &Arc<RelayCredential> {
        &self.credential
    }

    pub(crate) fn listener_endpoint(&self) -> Option<&ListenerEndpoint> {
        self.listener_endpoint.as_deref()
    }

    pub(crate) fn self_error(&self, error: NotedError) -> NotedError {
        match self.listener_endpoint() {
            Some(endpoint) => crate::serve::listener_endpoint_error(endpoint, error),
            None => error,
        }
    }

    fn remint_result<T>(&self, result: Result<T>) -> Result<T> {
        result.map_err(|error| self.self_error(error))
    }

    /// POSTs `body` byte for byte to `path` upstream under a credential minted
    /// for `caller`, answering with the upstream's status and body untouched.
    pub async fn forward(
        &self,
        path: &str,
        accept: Option<&str>,
        caller: &Verified,
        body: Bytes,
    ) -> Response {
        let credential = self.credential.clone();
        let caller = caller.clone();
        let reminted = self
            .remint_result(run_blocking(move || credential.remint(&caller)).await)
            .and_then(|result| self.remint_result(result));
        let bearer = match reminted {
            Ok(minted) => Bearer::new(minted.macaroon.expose()),
            Err(error) => {
                return refused(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
            }
        };
        match self
            .upstream
            .post(
                path.trim_start_matches('/'),
                Some(&bearer),
                accept,
                body.to_vec(),
            )
            .await
        {
            Ok(reply) => {
                let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::BAD_GATEWAY);
                let mut response = (status, reply.body).into_response();
                if let Some(content_type) = reply.content_type
                    && let Ok(value) = HeaderValue::from_str(&content_type)
                {
                    response.headers_mut().insert(header::CONTENT_TYPE, value);
                }
                response
            }
            Err(e) => refused(StatusCode::SERVICE_UNAVAILABLE, e.message().into_owned()),
        }
    }

    /// One JSON-RPC message per line from stdin to the upstream `/mcp`, each
    /// reply written back as one line.
    pub async fn pipe_stdio(&self) -> Result<()> {
        let caller = self.credential.own().clone();
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut out = tokio::io::stdout();
        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| io_error("mcp stdio", e))?
        {
            if line.trim().is_empty() {
                continue;
            }
            let credential = self.credential.clone();
            let caller = caller.clone();
            let reminted =
                self.remint_result(run_blocking(move || credential.remint(&caller)).await)?;
            let minted = self.remint_result(reminted)?;
            let bearer = Bearer::new(minted.macaroon.expose());
            let reply = self
                .upstream
                .post(MCP_PATH, Some(&bearer), Some(MCP_ACCEPT), line.into_bytes())
                .await?;
            if reply.body.is_empty() {
                continue;
            }
            out.write_all(&reply.body)
                .await
                .map_err(|e| io_error("mcp stdio", e))?;
            out.write_all(b"\n")
                .await
                .map_err(|e| io_error("mcp stdio", e))?;
            out.flush().await.map_err(|e| io_error("mcp stdio", e))?;
        }
        Ok(())
    }
}

fn refused(status: StatusCode, detail: String) -> Response {
    (status, Json(json!({ "detail": detail }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocking_remint_errors_name_the_relays_listener_endpoint() {
        let bound = crate::serve::Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .bind()
        .await
        .unwrap();
        let relay = Relay::open(
            Arc::new(RelayCredential::open(None, noted::PolicyFragment::default(), None).unwrap()),
            "http://upstream.test/internal".parse().unwrap(),
            &bound,
            Transport::Router(axum::Router::new()),
        )
        .unwrap();
        let error = noted::error::rejected("remint failed");

        let error = relay.remint_result::<()>(Err(error)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("{}: remint failed", bound.endpoint())
        );
    }

    #[test]
    fn stdio_remint_errors_claim_no_listener_endpoint() {
        let relay = Relay::open_stdio(
            Arc::new(RelayCredential::open(None, noted::PolicyFragment::default(), None).unwrap()),
            "http://upstream.test/internal".parse().unwrap(),
            Transport::Router(axum::Router::new()),
        )
        .unwrap();
        let error = noted::error::rejected("remint failed");

        let error = relay.remint_result::<()>(Err(error)).unwrap_err();
        assert_eq!(error.to_string(), "remint failed");
    }
}
