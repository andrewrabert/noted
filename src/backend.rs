use serde_json::Value;

use crate::error::{forbidden, json_error, not_found, rejected, unavailable, Result};
use crate::httpurl::HttpUrl;
use crate::notes::Notes;
use crate::tasks::Tasks;
use crate::tools::{run_tool, ToolOutput, CLI_ONLY_FIELDS};

pub struct ToolCall {
    pub name: String,
    pub args: Value,
}

pub enum Transport {
    Real,
    #[cfg(feature = "test-util")]
    Test(axum::Router),
}

pub enum Backend {
    Filesystem {
        notes: Notes,
        tasks: Tasks,
    },
    Http {
        url: HttpUrl,
        token: Option<String>,
        transport: Transport,
    },
}

impl Backend {
    pub fn filesystem(notes: Notes, tasks: Tasks) -> Backend {
        Backend::Filesystem { notes, tasks }
    }

    pub fn http(url: &HttpUrl, token: Option<String>) -> Backend {
        Backend::Http {
            url: url.clone(),
            token,
            transport: Transport::Real,
        }
    }

    #[cfg(feature = "test-util")]
    pub fn http_with(url: &HttpUrl, token: Option<String>, transport: Transport) -> Backend {
        Backend::Http {
            url: url.clone(),
            token,
            transport,
        }
    }

    pub async fn invoke(&self, call: &ToolCall) -> Result<ToolOutput> {
        match self {
            Backend::Filesystem { notes, tasks } => {
                run_tool(&call.name, &call.args, notes, tasks).await
            }
            Backend::Http {
                url,
                token,
                transport,
            } => roundtrip(url, token.as_deref(), transport, &call.name, &call.args).await,
        }
    }
}

async fn roundtrip(
    url: &HttpUrl,
    token: Option<&str>,
    transport: &Transport,
    name: &str,
    args: &Value,
) -> Result<ToolOutput> {
    let payload = strip_cli_only(args);
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    let target = url.join(&format!("tool/{name}"));
    let (status, resp_body) = match send(transport, target.as_str(), token, body).await {
        Ok(pair) => pair,
        Err(e) => return Err(unavailable(format!("cannot reach {url}: {e}"))),
    };
    if status >= 500 {
        return Err(unavailable(
            detail(&resp_body).unwrap_or_else(|| format!("{url}: HTTP {status}")),
        ));
    }
    if status >= 400 {
        let msg = detail(&resp_body).unwrap_or_else(|| format!("HTTP {status}"));
        return Err(match status {
            404 => not_found(msg),
            403 => forbidden(msg),
            _ => rejected(msg),
        });
    }
    let parsed: Value = serde_json::from_slice(&resp_body)
        .map_err(|e| json_error(format!("{url}: malformed response"), e))?;
    match parsed.get("ok") {
        Some(ok) => serde_json::from_value::<ToolOutput>(ok.clone())
            .map_err(|e| json_error(format!("{url}: malformed response"), e)),
        None => Err(unavailable(format!("{url}: malformed response"))),
    }
}

fn strip_cli_only(args: &Value) -> Value {
    let mut out = args.clone();
    if let Value::Object(map) = &mut out {
        for field in CLI_ONLY_FIELDS {
            map.remove(field);
        }
    }
    out
}

fn detail(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value.get("detail")? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

async fn send(
    transport: &Transport,
    target: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> std::result::Result<(u16, Vec<u8>), String> {
    match transport {
        Transport::Real => send_reqwest(target, token, body).await,
        #[cfg(feature = "test-util")]
        Transport::Test(router) => send_router(router.clone(), target, token, body).await,
    }
}

async fn send_reqwest(
    target: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> std::result::Result<(u16, Vec<u8>), String> {
    let client = reqwest::Client::new();
    let mut req = client
        .post(target)
        .header("content-type", "application/json")
        .body(body);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    Ok((status, bytes.to_vec()))
}

#[cfg(feature = "test-util")]
async fn send_router(
    router: axum::Router,
    target: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> std::result::Result<(u16, Vec<u8>), String> {
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let path = target
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/').map(|(_, p)| format!("/{p}")))
        .unwrap_or_else(|| target.to_string());
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(axum::body::Body::from(body))
        .map_err(|e| e.to_string())?;
    let resp = router.oneshot(request).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, bytes.to_vec()))
}
