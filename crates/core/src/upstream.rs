use serde_json::Value;

use crate::endpoint::Endpoint;
use crate::error::{Result, unavailable};
use crate::httpurl::HttpUrl;
use crate::platform::Router;
use crate::types::Bearer;

/// How an upstream reaches the far side: a real client, or a router served in
/// this very process.
#[derive(Clone)]
pub enum Transport {
    Real,
    Router(Router),
}

/// One way to reach another server, real or in-process.
pub struct Upstream {
    endpoint: Endpoint,
    base: HttpUrl,
    transport: Transport,
    client: reqwest::Client,
}

/// What the far side answered.
pub struct Reply {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn detail(&self) -> Option<String> {
        let value: Value = serde_json::from_slice(&self.body).ok()?;
        match value.get("detail")? {
            Value::Null => None,
            Value::String(s) => Some(s.clone()),
            other => Some(other.to_string()),
        }
    }
}

impl Upstream {
    pub fn open(endpoint: Endpoint, transport: Transport) -> Result<Upstream> {
        #[cfg(unix)]
        if matches!(endpoint, Endpoint::Unix(_)) && matches!(transport, Transport::Router(_)) {
            return Err(crate::error::rejected(
                "a socket is dialed by a real client: it takes no in-process router",
            ));
        }
        let client = match &endpoint {
            Endpoint::Tcp(_) => reqwest::Client::builder(),
            #[cfg(unix)]
            Endpoint::Unix(path) => reqwest::Client::builder().unix_socket(path.clone()),
        }
        .build()
        .map_err(|e| unavailable(format!("cannot build an HTTP client: {e}")))?;
        Ok(Upstream {
            base: endpoint.base_url()?,
            endpoint,
            transport,
            client,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub async fn post(
        &self,
        path: &str,
        bearer: Option<&Bearer>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Reply> {
        let target = self.base.join(path);
        let authorization = bearer.map(|b| format!("Bearer {}", b.expose()));
        let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        if let Some(authorization) = &authorization {
            headers.push(("authorization", authorization));
        }
        if let Some(accept) = accept {
            headers.push(("accept", accept));
        }
        let sent = match &self.transport {
            Transport::Real => send_reqwest(&self.client, &target, &headers, body).await,
            Transport::Router(router) => {
                crate::platform::route(router, &target, &headers, body).await
            }
        };
        match sent {
            Ok((status, content_type, body)) => Ok(Reply {
                status,
                content_type,
                body,
            }),
            Err(e) => Err(unavailable(format!("cannot reach {}: {e}", self.endpoint))),
        }
    }
}

async fn send_reqwest(
    client: &reqwest::Client,
    target: &HttpUrl,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> std::result::Result<(u16, Option<String>, Vec<u8>), String> {
    let mut req = client.post(target.as_str()).body(body);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    Ok((status, content_type, bytes.to_vec()))
}
