use serde_json::Value;

use crate::platform::Router;
use noted::Endpoint;
use noted::error::{Result, unavailable};
use noted::httpurl::HttpUrl;
use noted::types::Bearer;

pub mod oauth;

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

fn refuses(status: u16) -> bool {
    reqwest::StatusCode::from_u16(status).map_or(true, |code| {
        code.is_client_error() || code.is_server_error()
    })
}

impl Reply {
    pub fn is_refusal(&self) -> bool {
        refuses(self.status)
    }

    pub fn detail(&self) -> String {
        let status = format!("HTTP {}", self.status);
        if self.body.is_empty() {
            return format!("{status}, with no body");
        }
        let Ok(text) = std::str::from_utf8(&self.body) else {
            return format!(
                "{status}, with a {}-byte body that is not utf-8",
                self.body.len()
            );
        };
        match serde_json::from_str::<Value>(text) {
            Ok(value) => match value.get("detail") {
                Some(Value::String(detail)) => detail.clone(),
                Some(Value::Null) | None => format!("{status}: {text}"),
                Some(other) => other.to_string(),
            },
            Err(_) => format!("{status}: {text}"),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub struct Streamed {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: ByteStream,
}

#[cfg(not(target_arch = "wasm32"))]
pub type ByteStream = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static>,
>;

#[cfg(not(target_arch = "wasm32"))]
impl Streamed {
    pub fn is_refusal(&self) -> bool {
        refuses(self.status)
    }

    pub async fn collect(self) -> Result<Reply> {
        use futures_util::TryStreamExt;
        let body: Vec<u8> = self
            .body
            .try_fold(Vec::new(), |mut all, chunk| async move {
                all.extend_from_slice(&chunk);
                Ok(all)
            })
            .await
            .map_err(|e| unavailable(format!("cannot read the reply: {e}")))?;
        Ok(Reply {
            status: self.status,
            content_type: self.content_type,
            body,
        })
    }
}

impl Upstream {
    pub fn open(endpoint: Endpoint, transport: Transport) -> Result<Upstream> {
        #[cfg(unix)]
        if endpoint.unix_path().is_some() && matches!(transport, Transport::Router(_)) {
            return Err(noted::error::rejected(
                "a socket is dialed by a real client: it takes no in-process router",
            ));
        }
        let builder = reqwest::Client::builder().user_agent(format!(
            "{}/{}",
            noted::APP_NAME,
            noted::APP_VERSION
        ));
        // rustls-platform-verifier needs a JVM on Android, which a CLI does not have.
        #[cfg(target_os = "android")]
        let builder = builder.tls_certs_only(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|der| reqwest::Certificate::from_der(der))
                .collect::<reqwest::Result<Vec<_>>>()
                .map_err(|e| unavailable(format!("cannot load TLS root certificates: {e}")))?,
        );
        #[cfg(unix)]
        let builder = match endpoint.tcp() {
            Some(_) => builder,
            None => {
                let Some(path) = endpoint.unix_path() else {
                    return Err(noted::error::rejected("endpoint has no dialable transport"));
                };
                builder.unix_socket(path.to_path_buf())
            }
        };
        #[cfg(not(unix))]
        let builder = {
            let _ = endpoint.tcp();
            builder
        };
        let client = builder
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
        query: &[(&str, String)],
        bearer: Option<&Bearer>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Reply> {
        let target = self.base.join_query(path, query);
        let authorization = bearer.map(|b| format!("Bearer {}", b.expose()));
        let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        if let Some(authorization) = &authorization {
            headers.push(("authorization", authorization));
        }
        if let Some(accept) = accept {
            headers.push(("accept", accept));
        }
        self.send(&target, &headers, body).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn post_stream(
        &self,
        path: &str,
        query: &[(&str, String)],
        bearer: Option<&Bearer>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Streamed> {
        let target = self.base.join_query(path, query);
        let authorization = bearer.map(|b| format!("Bearer {}", b.expose()));
        let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        if let Some(authorization) = &authorization {
            headers.push(("authorization", authorization));
        }
        if let Some(accept) = accept {
            headers.push(("accept", accept));
        }
        let sent = match &self.transport {
            Transport::Real => stream_reqwest(&self.client, &target, &headers, body).await,
            Transport::Router(router) => {
                crate::platform::route_stream(router, &target, &headers, body).await
            }
        };
        sent.map_err(|e| unavailable(format!("cannot reach {}: {e}", self.endpoint)))
    }

    async fn send(
        &self,
        target: &HttpUrl,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<Reply> {
        let sent = match &self.transport {
            Transport::Real => send_reqwest(&self.client, target, headers, body).await,
            Transport::Router(router) => {
                crate::platform::route(router, target, headers, body).await
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

    pub(crate) fn base(&self) -> &HttpUrl {
        &self.base
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
        .map(|v| v.to_str().map(str::to_string))
        .transpose()
        .map_err(|e| format!("invalid content type: {e}"))?;
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    Ok((status, content_type, bytes.to_vec()))
}

#[cfg(not(target_arch = "wasm32"))]
async fn stream_reqwest(
    client: &reqwest::Client,
    target: &HttpUrl,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> std::result::Result<Streamed, String> {
    use futures_util::TryStreamExt;
    let mut req = client.post(target.as_str()).body(body);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().map(str::to_string))
        .transpose()
        .map_err(|e| format!("invalid content type: {e}"))?;
    Ok(Streamed {
        status,
        content_type,
        body: Box::pin(resp.bytes_stream().map_err(std::io::Error::other)),
    })
}
