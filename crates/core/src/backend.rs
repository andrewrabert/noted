use serde_json::Value;

use crate::endpoint::Endpoint;
use crate::error::{NotedError, Result, json_error, rejected, unavailable};
use crate::platform::{BoxFuture, Threadsafe};
use crate::policyargs::PolicyArgs;
use crate::root::NotedRoot;
use crate::store::NotedDir;
use crate::tools::{ToolArgs, ToolOutput, is_tool};
use crate::types::{Bearer, Source};
use crate::upstream::{Transport, Upstream};

/// What a client invokes against: a notes tree on this host, or another
/// server reached over an upstream.
pub enum BackendArgs {
    Local {
        dir: NotedDir,
        source: Option<Source>,
        policy: PolicyArgs,
    },
    Remote {
        endpoint: Endpoint,
        bearer: Option<Bearer>,
        transport: Transport,
    },
}

pub struct ToolCall {
    name: String,
    args: Value,
}

impl ToolCall {
    pub fn new<A: ToolArgs>(args: A) -> Result<ToolCall> {
        Ok(ToolCall {
            name: A::TOOL.to_string(),
            args: serde_json::to_value(args).map_err(|e| json_error("tool arguments", e))?,
        })
    }

    pub fn raw(name: &str, args: Value) -> Result<ToolCall> {
        if !is_tool(name) {
            return Err(NotedError::NotFound);
        }
        Ok(ToolCall {
            name: name.to_string(),
            args,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn args(&self) -> &Value {
        &self.args
    }
}

pub struct ToolListing {
    pub name: &'static str,
    pub title: &'static str,
    pub description: String,
    pub input_schema: Value,
}

pub struct Backend {
    inner: Box<dyn BackendImpl>,
}

impl Backend {
    pub fn new(args: BackendArgs) -> Result<Backend> {
        match args {
            BackendArgs::Remote {
                endpoint,
                bearer,
                transport,
            } => Ok(Backend {
                inner: Box::new(RemoteBackend {
                    upstream: Upstream::open(endpoint, transport)?,
                    bearer,
                }),
            }),
            BackendArgs::Local {
                dir,
                source,
                policy,
            } => {
                let root = NotedRoot::open(dir, source)?.with_authority(&policy.fragments()?)?;
                Ok(Backend {
                    inner: Box::new(LocalBackend { root }),
                })
            }
        }
    }

    pub async fn invoke(&self, call: &ToolCall) -> Result<ToolOutput> {
        self.inner.invoke(call).await
    }

    pub async fn submit_txn(&self, txn: &str, username: &str, password: &str) -> Result<String> {
        self.inner.submit_txn(txn, username, password).await
    }

    pub async fn exchange_code(
        &self,
        client_id: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<crate::oauth::Tokens> {
        self.inner
            .exchange_code(client_id, code, verifier, redirect_uri)
            .await
    }
}

trait BackendImpl: Threadsafe {
    fn invoke<'a>(&'a self, call: &'a ToolCall) -> BoxFuture<'a, Result<ToolOutput>>;

    /// A notes tree on this host has no login.
    fn submit_txn<'a>(
        &'a self,
        txn: &'a str,
        username: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        let _ = (txn, username, password);
        Box::pin(async move { Err(rejected("a local notes tree has no login")) })
    }

    fn exchange_code<'a>(
        &'a self,
        client_id: &'a str,
        code: &'a str,
        verifier: &'a str,
        redirect_uri: &'a str,
    ) -> BoxFuture<'a, Result<crate::oauth::Tokens>> {
        let _ = (client_id, code, verifier, redirect_uri);
        Box::pin(async move { Err(rejected("a local notes tree has no login")) })
    }
}

struct LocalBackend {
    root: NotedRoot,
}

impl BackendImpl for LocalBackend {
    fn invoke<'a>(&'a self, call: &'a ToolCall) -> BoxFuture<'a, Result<ToolOutput>> {
        Box::pin(async move { self.root.invoke(call).await })
    }
}

struct RemoteBackend {
    upstream: Upstream,
    bearer: Option<Bearer>,
}

impl BackendImpl for RemoteBackend {
    fn invoke<'a>(&'a self, call: &'a ToolCall) -> BoxFuture<'a, Result<ToolOutput>> {
        Box::pin(async move { self.roundtrip(&call.name, &call.args).await })
    }

    fn submit_txn<'a>(
        &'a self,
        txn: &'a str,
        username: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { self.upstream.submit_txn(txn, username, password).await })
    }

    fn exchange_code<'a>(
        &'a self,
        client_id: &'a str,
        code: &'a str,
        verifier: &'a str,
        redirect_uri: &'a str,
    ) -> BoxFuture<'a, Result<crate::oauth::Tokens>> {
        Box::pin(async move {
            self.upstream
                .exchange_code(client_id, code, verifier, redirect_uri)
                .await
        })
    }
}

impl RemoteBackend {
    async fn roundtrip(&self, name: &str, args: &Value) -> Result<ToolOutput> {
        let at = self.upstream.endpoint();
        let body = serde_json::to_vec(args).unwrap_or_default();
        let reply = self
            .upstream
            .post(
                &format!("tool/{name}"),
                &[],
                self.bearer.as_ref(),
                None,
                body,
            )
            .await?;
        if reply.status >= 500 {
            return Err(unavailable(
                reply
                    .detail()
                    .unwrap_or_else(|| format!("{at}: HTTP {}", reply.status)),
            ));
        }
        if reply.status >= 400 {
            let msg = reply
                .detail()
                .unwrap_or_else(|| format!("HTTP {}", reply.status));
            return Err(match reply.status {
                404 => NotedError::NotFound,
                403 => NotedError::Forbidden,
                401 => NotedError::Unauthorized,
                409 => NotedError::Conflict,
                _ => rejected(msg),
            });
        }
        let parsed: Value = serde_json::from_slice(&reply.body)
            .map_err(|e| json_error(format!("{at}: malformed response"), e))?;
        match parsed.get("ok") {
            Some(ok) => serde_json::from_value::<ToolOutput>(ok.clone())
                .map_err(|e| json_error(format!("{at}: malformed response"), e)),
            None => Err(unavailable(format!("{at}: malformed response"))),
        }
    }
}
