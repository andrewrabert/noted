use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, http::HeaderValue};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use noted::error::{Result, io_error};
use noted::{Bearer, Endpoint, Transport, Upstream};
use noted_auth::authority::{Minter, RelayCredential, Verified};

/// The MCP endpoint every relayed JSON-RPC message is posted to.
const MCP_PATH: &str = "mcp";

/// rmcp answers a stateless call only when both content types are acceptable.
const MCP_ACCEPT: &str = "application/json, text/event-stream";

/// A domain-blind pipe: it re-mints the caller's credential from its own and
/// copies bodies through.
pub struct Relay {
    credential: Arc<RelayCredential>,
    upstream: Upstream,
}

impl Relay {
    pub fn open(
        credential: Arc<RelayCredential>,
        endpoint: Endpoint,
        transport: Transport,
    ) -> Result<Relay> {
        Ok(Relay {
            credential,
            upstream: Upstream::open(endpoint, transport)?,
        })
    }

    pub fn credential(&self) -> &Arc<RelayCredential> {
        &self.credential
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
        let bearer = match self.credential.remint(caller) {
            Ok(minted) => Bearer::new(minted.macaroon.expose()),
            Err(e) => {
                return refused(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}: {}", self.credential.at(), e.message()),
                );
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
            let minted = self.credential.remint(&caller)?;
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
