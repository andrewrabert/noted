use serde_json::Value;

use crate::authorization::{Authorization, Bearer};
use crate::endpoint::Endpoint;
use crate::error::{NotedError, Result, json_error, rejected, unavailable};
use crate::fragment::PolicyFragment;
use crate::httpurl::HttpUrl;
use crate::platform::{BoxFuture, Router, Threadsafe};
use crate::policy::RegionPolicy;
use crate::policyargs::PolicyArgs;
use crate::regions::{RegionDir, folded};
use crate::root::NotedRoot;
use crate::store::NotedDir;
use crate::tools::{ToolArgs, ToolOutput, is_tool, permitted, run_tool, tool_defs};
use crate::types::Source;

const INSTRUCTIONS: &str = "This is the user's personal notes — the canonical place where they keep and organize their own notes, ideas, todos, and log entries as a nested tree of Markdown (.md) files. Whenever the user refers to 'my notes', asks to look something up, record or jot something down, or check what they've written before, use these tools instead of guessing or answering from memory. Search, read, write, edit, move, and delete notes by relative path (e.g. 'proj/ideas.md'). The tree has three regions and each has its own search tool: SearchNotes covers ordinary notes, SearchLog covers Log/, and SearchTasks covers Tasks/ — none of them reaches into another's region. Use LogNote to quickly capture an immutable, timestamped log entry (its metadata is auto-generated and it cannot be edited or deleted), then GetLog to list entries newest first or SearchLog to match their text. Track units of work with the task tools: CreateTask opens a task (optionally in a nested 'group' under Tasks/, e.g. group='dev/noted'); GetTasks reads them (by group prefix, or an exact task path with body=true); UpdateTask advances one (state=created/started/blocked/completed/rejected/invalid); MoveTask changes a task's group. A task is identified by its Tasks-relative path minus '.md' (e.g. 'dev/noted/task_0001'); tasks are managed only through these tools — WriteNote/EditNote are refused under Tasks/.";

#[derive(Default)]
pub struct BackendArgs {
    pub dir: Option<String>,
    pub endpoint: Option<Endpoint>,
    pub token: Option<Bearer>,
    pub source: Option<String>,
    pub policy: PolicyArgs,
    pub transport: Option<Transport>,
}

#[derive(Clone)]
pub enum Transport {
    Real,
    Router(Router),
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
        let BackendArgs {
            dir,
            endpoint,
            token,
            source,
            policy,
            transport,
        } = args;
        match endpoint {
            Some(endpoint) => {
                if policy != PolicyArgs::default() {
                    return Err(rejected(
                        "a remote server holds its own policy: a policy cannot be set here",
                    ));
                }
                #[cfg(unix)]
                if matches!(endpoint, Endpoint::Unix(_))
                    && matches!(transport, Some(Transport::Router(_)))
                {
                    return Err(rejected(
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
                Ok(Backend {
                    inner: Box::new(RemoteBackend {
                        base: endpoint.base_url()?,
                        endpoint,
                        token,
                        transport: transport.unwrap_or(Transport::Real),
                        client,
                    }),
                })
            }
            None => {
                let dir = dir
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| rejected("no notes dir set (set NOTED_DIR)"))?;
                let root = NotedRoot::open(NotedDir::new(dir), Source::from_opt(source))?
                    .with_authority(&policy.fragments()?)?;
                Ok(Backend {
                    inner: Box::new(LocalBackend { root }),
                })
            }
        }
    }

    pub fn with_authority(
        &self,
        authorization: Option<&Authorization>,
    ) -> Result<AuthorizedBackend<'_>> {
        Ok(AuthorizedBackend {
            inner: self.inner.with_authority(authorization)?,
        })
    }
}

pub struct AuthorizedBackend<'a> {
    inner: Box<dyn AuthorizedBackendImpl + 'a>,
}

impl AuthorizedBackend<'_> {
    pub async fn invoke(&self, call: &ToolCall) -> Result<ToolOutput> {
        self.inner.invoke(call).await
    }

    pub fn tools(&self) -> Vec<ToolListing> {
        let allowed = permitted(
            self.inner.policy(RegionDir::Notes),
            self.inner.policy(RegionDir::Log),
            self.inner.policy(RegionDir::Tasks),
        );
        let scope = self.inner.policy(RegionDir::Notes).scope();
        tool_defs()
            .into_iter()
            .filter(|def| allowed.contains(&def.name))
            .map(|def| ToolListing {
                name: def.name,
                title: def.title,
                description: def.described(scope),
                input_schema: def.input_schema,
            })
            .collect()
    }

    pub fn instructions(&self) -> String {
        let mut out = String::from(INSTRUCTIONS);
        match self.inner.policy(RegionDir::Notes).scope() {
            None => out.push_str(
                " Notes live at the top of the tree. Tasks are under Tasks/, log entries under Log/.",
            ),
            Some(scope) => out.push_str(&format!(
                " You are working in {scope}. Every path you write is relative to it. \
Tasks you create land in its task region; log entries you write are stamped with it."
            )),
        }
        out
    }
}

trait BackendImpl: Threadsafe {
    fn with_authority<'a>(
        &'a self,
        authorization: Option<&Authorization>,
    ) -> Result<Box<dyn AuthorizedBackendImpl + 'a>>;
}

trait AuthorizedBackendImpl: Threadsafe {
    fn invoke<'a>(&'a self, call: &'a ToolCall) -> BoxFuture<'a, Result<ToolOutput>>;

    fn policy(&self, dir: RegionDir) -> &RegionPolicy;
}

struct LocalBackend {
    root: NotedRoot,
}

impl BackendImpl for LocalBackend {
    fn with_authority<'a>(
        &'a self,
        authorization: Option<&Authorization>,
    ) -> Result<Box<dyn AuthorizedBackendImpl + 'a>> {
        let root = match authorization {
            Some(authorization) => self.root.with_authority(authorization.fragments())?,
            None => self.root.clone(),
        };
        Ok(Box::new(AuthorizedLocalBackend { root }))
    }
}

struct AuthorizedLocalBackend {
    root: NotedRoot,
}

impl AuthorizedBackendImpl for AuthorizedLocalBackend {
    fn invoke<'a>(&'a self, call: &'a ToolCall) -> BoxFuture<'a, Result<ToolOutput>> {
        Box::pin(async move { run_tool(&call.name, &call.args, &self.root).await })
    }

    fn policy(&self, dir: RegionDir) -> &RegionPolicy {
        self.root.policy(dir)
    }
}

struct RemoteBackend {
    endpoint: Endpoint,
    base: HttpUrl,
    token: Option<Bearer>,
    transport: Transport,
    client: reqwest::Client,
}

impl BackendImpl for RemoteBackend {
    fn with_authority<'a>(
        &'a self,
        authorization: Option<&Authorization>,
    ) -> Result<Box<dyn AuthorizedBackendImpl + 'a>> {
        let bearer = match authorization {
            None => self.token.clone(),
            Some(authorization) => Some(authorization.bearer().cloned().ok_or_else(|| {
                rejected("a call carried to another server needs a bearer to carry")
            })?),
        };
        let fragments: &[PolicyFragment] = match authorization {
            Some(authorization) => authorization.fragments(),
            None => &[],
        };
        Ok(Box::new(AuthorizedRemoteBackend {
            remote: self,
            bearer,
            notes: folded(RegionDir::Notes, fragments)?,
            log: folded(RegionDir::Log, fragments)?,
            tasks: folded(RegionDir::Tasks, fragments)?,
        }))
    }
}

struct AuthorizedRemoteBackend<'a> {
    remote: &'a RemoteBackend,
    bearer: Option<Bearer>,
    notes: RegionPolicy,
    log: RegionPolicy,
    tasks: RegionPolicy,
}

impl AuthorizedBackendImpl for AuthorizedRemoteBackend<'_> {
    fn invoke<'a>(&'a self, call: &'a ToolCall) -> BoxFuture<'a, Result<ToolOutput>> {
        Box::pin(async move {
            self.remote
                .roundtrip(
                    self.bearer.as_ref().map(Bearer::expose),
                    &call.name,
                    &call.args,
                )
                .await
        })
    }

    fn policy(&self, dir: RegionDir) -> &RegionPolicy {
        match dir {
            RegionDir::Notes => &self.notes,
            RegionDir::Log => &self.log,
            RegionDir::Tasks => &self.tasks,
        }
    }
}

impl RemoteBackend {
    async fn roundtrip(&self, token: Option<&str>, name: &str, args: &Value) -> Result<ToolOutput> {
        let url = &self.base;
        let body = serde_json::to_vec(args).unwrap_or_default();
        let target = url.join(&format!("tool/{name}"));
        let (status, resp_body) = match self.send(&target, token, body).await {
            Ok(pair) => pair,
            Err(e) => {
                return Err(unavailable(format!("cannot reach {}: {e}", self.endpoint)));
            }
        };
        if status >= 500 {
            return Err(unavailable(
                detail(&resp_body).unwrap_or_else(|| format!("{url}: HTTP {status}")),
            ));
        }
        if status >= 400 {
            let msg = detail(&resp_body).unwrap_or_else(|| format!("HTTP {status}"));
            return Err(match status {
                404 => NotedError::NotFound,
                403 => NotedError::Forbidden,
                409 => NotedError::Conflict,
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

    // dispatches to the real client or the in-process router
    async fn send(
        &self,
        target: &HttpUrl,
        token: Option<&str>,
        body: Vec<u8>,
    ) -> std::result::Result<(u16, Vec<u8>), String> {
        match &self.transport {
            Transport::Real => send_reqwest(&self.client, target, token, body).await,
            Transport::Router(router) => crate::platform::route(router, target, token, body).await,
        }
    }
}

fn detail(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value.get("detail")? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

async fn send_reqwest(
    client: &reqwest::Client,
    target: &HttpUrl,
    token: Option<&str>,
    body: Vec<u8>,
) -> std::result::Result<(u16, Vec<u8>), String> {
    let mut req = client
        .post(target.as_str())
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
