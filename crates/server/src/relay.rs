use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, http::HeaderValue};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use noted::error::{NotedError, Result, io_error};
use noted::{Bearer, Endpoint, PolicyFragment, Transport, Upstream};

use crate::serve::{Bound, ListenerEndpoint};

/// The MCP endpoint every relayed JSON-RPC message is posted to.
const MCP_PATH: &str = "mcp";

/// rmcp answers a stateless call only when both content types are acceptable.
const MCP_ACCEPT: &str = "application/json, text/event-stream";

/// A domain-blind pipe: it carries the credential it was configured with,
/// imposes its own confinement as a `policy=` query, and copies bodies through.
pub struct Relay {
    bearer: Option<Bearer>,
    policy: PolicyFragment,
    upstream: Upstream,
    listener_endpoint: Option<Arc<ListenerEndpoint>>,
}

impl Relay {
    pub fn open(
        bearer: Option<Bearer>,
        policy: PolicyFragment,
        upstream_endpoint: Endpoint,
        bound: &Bound,
        transport: Transport,
    ) -> Result<Relay> {
        Ok(Relay {
            bearer,
            policy,
            upstream: Upstream::open(upstream_endpoint, transport)?,
            listener_endpoint: Some(bound.endpoint().clone()),
        })
    }

    pub fn open_stdio(
        bearer: Option<Bearer>,
        policy: PolicyFragment,
        upstream_endpoint: Endpoint,
        transport: Transport,
    ) -> Result<Relay> {
        Ok(Relay {
            bearer,
            policy,
            upstream: Upstream::open(upstream_endpoint, transport)?,
            listener_endpoint: None,
        })
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

    /// The confinement every proxied call is held to: this relay's own, then
    /// whatever the caller asked to be narrowed to.
    fn query(&self, asked: &[PolicyFragment]) -> Vec<(&'static str, String)> {
        std::iter::once(&self.policy)
            .chain(asked)
            .filter(|fragment| **fragment != PolicyFragment::default())
            .map(|fragment| ("policy", fragment.to_string()))
            .collect()
    }

    /// POSTs `body` byte for byte to `path` upstream under the credential this
    /// relay holds, answering with the upstream's status and body untouched.
    pub async fn forward(
        &self,
        path: &str,
        accept: Option<&str>,
        asked: &[PolicyFragment],
        body: Bytes,
    ) -> Response {
        match self
            .upstream
            .post(
                path.trim_start_matches('/'),
                &self.query(asked),
                self.bearer.as_ref(),
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
            let reply = self
                .upstream
                .post(
                    MCP_PATH,
                    &self.query(&[]),
                    self.bearer.as_ref(),
                    Some(MCP_ACCEPT),
                    line.into_bytes(),
                )
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

    fn fragment(text: &str) -> PolicyFragment {
        text.parse().unwrap()
    }

    #[tokio::test]
    async fn relay_errors_name_the_relays_listener_endpoint() {
        let bound = crate::serve::Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .bind()
        .await
        .unwrap();
        let relay = Relay::open(
            None,
            PolicyFragment::default(),
            "http://upstream.test/internal".parse().unwrap(),
            &bound,
            Transport::Router(axum::Router::new()),
        )
        .unwrap();

        let error = relay.self_error(noted::error::rejected("forward failed"));
        assert_eq!(
            error.to_string(),
            format!("{}: forward failed", bound.endpoint())
        );
    }

    #[test]
    fn stdio_relay_errors_claim_no_listener_endpoint() {
        let relay = Relay::open_stdio(
            None,
            PolicyFragment::default(),
            "http://upstream.test/internal".parse().unwrap(),
            Transport::Router(axum::Router::new()),
        )
        .unwrap();

        let error = relay.self_error(noted::error::rejected("forward failed"));
        assert_eq!(error.to_string(), "forward failed");
    }

    #[test]
    fn a_query_carries_the_relays_confinement_ahead_of_the_callers() {
        let relay = Relay::open_stdio(
            None,
            fragment(r#"{"scope":"a"}"#),
            "http://upstream.test".parse().unwrap(),
            Transport::Router(axum::Router::new()),
        )
        .unwrap();

        assert_eq!(
            relay.query(&[fragment(r#"{"scope":"b"}"#)]),
            vec![
                ("policy", r#"{"scope":"a"}"#.to_string()),
                ("policy", r#"{"scope":"b"}"#.to_string()),
            ]
        );
    }

    #[test]
    fn a_query_that_narrows_nothing_is_left_off_entirely() {
        let relay = Relay::open_stdio(
            None,
            PolicyFragment::default(),
            "http://upstream.test".parse().unwrap(),
            Transport::Router(axum::Router::new()),
        )
        .unwrap();

        assert!(relay.query(&[PolicyFragment::default()]).is_empty());
    }
}
