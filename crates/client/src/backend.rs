use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::upstream::{Transport, Upstream};
use noted::Endpoint;
use noted::NotedRoot;
use noted::PolicyArgs;
use noted::error::{NotedError, Result, json_error, rejected, unavailable};
use noted::note::{LogNote, TextNote, Trashed};
use noted::search::Hit;
use noted::store::NotedDir;
use noted::tasks::TaskNote;
use noted::tools::{
    CreateTaskArgs, DeleteArgs, EditArgs, GetLogArgs, GetTasksArgs, LogArgs, MoveArgs,
    MoveTaskArgs, ReadArgs, SearchLogArgs, SearchNotesArgs, SearchTasksArgs, Tool, Tools,
    UpdateTaskArgs, WriteArgs,
};
use noted::types::{Bearer, Source};
use noted::{LogPath, TaskPath, TextPath};

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

pub struct Backend {
    inner: Inner,
}

enum Inner {
    Local(NotedRoot),
    Remote(Box<RemoteBackend>),
}

impl Backend {
    pub fn new(args: BackendArgs) -> Result<Backend> {
        match args {
            BackendArgs::Remote {
                endpoint,
                bearer,
                transport,
            } => Ok(Backend {
                inner: Inner::Remote(Box::new(RemoteBackend {
                    upstream: Upstream::open(endpoint, transport)?,
                    bearer,
                })),
            }),
            BackendArgs::Local {
                dir,
                source,
                policy,
            } => {
                let root = NotedRoot::open(dir, source)?.with_authority(&policy.fragments()?)?;
                Ok(Backend {
                    inner: Inner::Local(root),
                })
            }
        }
    }

    pub async fn submit_txn(&self, txn: &str, username: &str, password: &str) -> Result<String> {
        match &self.inner {
            Inner::Remote(remote) => remote.upstream.submit_txn(txn, username, password).await,
            // a notes tree on this host has no login
            Inner::Local(_) => Err(rejected("a local notes tree has no login")),
        }
    }

    pub async fn exchange_code(
        &self,
        client_id: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<crate::oauth::Tokens> {
        match &self.inner {
            Inner::Remote(remote) => {
                remote
                    .upstream
                    .exchange_code(client_id, code, verifier, redirect_uri)
                    .await
            }
            Inner::Local(_) => Err(rejected("a local notes tree has no login")),
        }
    }
}

impl Tools for Backend {
    async fn search_notes(&self, args: SearchNotesArgs) -> Result<Vec<Hit<TextPath>>> {
        match &self.inner {
            Inner::Local(root) => root.search_notes(args).await,
            Inner::Remote(remote) => remote.search_notes(args).await,
        }
    }

    async fn search_log(&self, args: SearchLogArgs) -> Result<Vec<Hit<LogPath>>> {
        match &self.inner {
            Inner::Local(root) => root.search_log(args).await,
            Inner::Remote(remote) => remote.search_log(args).await,
        }
    }

    async fn search_tasks(&self, args: SearchTasksArgs) -> Result<Vec<Hit<TaskPath>>> {
        match &self.inner {
            Inner::Local(root) => root.search_tasks(args).await,
            Inner::Remote(remote) => remote.search_tasks(args).await,
        }
    }

    async fn read_note(&self, args: ReadArgs) -> Result<TextNote> {
        match &self.inner {
            Inner::Local(root) => root.read_note(args).await,
            Inner::Remote(remote) => remote.read_note(args).await,
        }
    }

    async fn write_note(&self, args: WriteArgs) -> Result<()> {
        match &self.inner {
            Inner::Local(root) => root.write_note(args).await,
            Inner::Remote(remote) => remote.write_note(args).await,
        }
    }

    async fn edit_note(&self, args: EditArgs) -> Result<TextNote> {
        match &self.inner {
            Inner::Local(root) => root.edit_note(args).await,
            Inner::Remote(remote) => remote.edit_note(args).await,
        }
    }

    async fn move_note(&self, args: MoveArgs) -> Result<()> {
        match &self.inner {
            Inner::Local(root) => root.move_note(args).await,
            Inner::Remote(remote) => remote.move_note(args).await,
        }
    }

    async fn delete_note(&self, args: DeleteArgs) -> Result<Trashed> {
        match &self.inner {
            Inner::Local(root) => root.delete_note(args).await,
            Inner::Remote(remote) => remote.delete_note(args).await,
        }
    }

    async fn log_note(&self, args: LogArgs) -> Result<LogNote> {
        match &self.inner {
            Inner::Local(root) => Tools::log_note(root, args).await,
            Inner::Remote(remote) => remote.log_note(args).await,
        }
    }

    async fn get_log(&self, args: GetLogArgs) -> Result<Vec<LogNote>> {
        match &self.inner {
            Inner::Local(root) => root.get_log(args).await,
            Inner::Remote(remote) => remote.get_log(args).await,
        }
    }

    async fn create_task(&self, args: CreateTaskArgs) -> Result<TaskNote> {
        match &self.inner {
            Inner::Local(root) => root.create_task(args).await,
            Inner::Remote(remote) => remote.create_task(args).await,
        }
    }

    async fn get_tasks(&self, args: GetTasksArgs) -> Result<Vec<TaskNote>> {
        match &self.inner {
            Inner::Local(root) => root.get_tasks(args).await,
            Inner::Remote(remote) => remote.get_tasks(args).await,
        }
    }

    async fn update_task(&self, args: UpdateTaskArgs) -> Result<TaskNote> {
        match &self.inner {
            Inner::Local(root) => root.update_task(args).await,
            Inner::Remote(remote) => remote.update_task(args).await,
        }
    }

    async fn move_task(&self, args: MoveTaskArgs) -> Result<TaskNote> {
        match &self.inner {
            Inner::Local(root) => root.move_task(args).await,
            Inner::Remote(remote) => remote.move_task(args).await,
        }
    }
}

struct RemoteBackend {
    upstream: Upstream,
    bearer: Option<Bearer>,
}

impl Tools for RemoteBackend {
    async fn search_notes(&self, args: SearchNotesArgs) -> Result<Vec<Hit<TextPath>>> {
        self.post_tool(Tool::SearchNotes(args)).await
    }

    async fn search_log(&self, args: SearchLogArgs) -> Result<Vec<Hit<LogPath>>> {
        self.post_tool(Tool::SearchLog(args)).await
    }

    async fn search_tasks(&self, args: SearchTasksArgs) -> Result<Vec<Hit<TaskPath>>> {
        self.post_tool(Tool::SearchTasks(args)).await
    }

    async fn read_note(&self, args: ReadArgs) -> Result<TextNote> {
        self.post_tool(Tool::ReadNote(args)).await
    }

    async fn write_note(&self, args: WriteArgs) -> Result<()> {
        self.post_tool(Tool::WriteNote(args)).await
    }

    async fn edit_note(&self, args: EditArgs) -> Result<TextNote> {
        self.post_tool(Tool::EditNote(args)).await
    }

    async fn move_note(&self, args: MoveArgs) -> Result<()> {
        self.post_tool(Tool::MoveNote(args)).await
    }

    async fn delete_note(&self, args: DeleteArgs) -> Result<Trashed> {
        self.post_tool(Tool::DeleteNote(args)).await
    }

    async fn log_note(&self, args: LogArgs) -> Result<LogNote> {
        self.post_tool(Tool::LogNote(args)).await
    }

    async fn get_log(&self, args: GetLogArgs) -> Result<Vec<LogNote>> {
        self.post_tool(Tool::GetLog(args)).await
    }

    async fn create_task(&self, args: CreateTaskArgs) -> Result<TaskNote> {
        self.post_tool(Tool::CreateTask(args)).await
    }

    async fn get_tasks(&self, args: GetTasksArgs) -> Result<Vec<TaskNote>> {
        self.post_tool(Tool::GetTasks(args)).await
    }

    async fn update_task(&self, args: UpdateTaskArgs) -> Result<TaskNote> {
        self.post_tool(Tool::UpdateTask(args)).await
    }

    async fn move_task(&self, args: MoveTaskArgs) -> Result<TaskNote> {
        self.post_tool(Tool::MoveTask(args)).await
    }
}

impl RemoteBackend {
    // the tool, name and args, is the whole body of `tool`
    async fn post_tool<R: DeserializeOwned>(&self, tool: Tool) -> Result<R> {
        let at = self.upstream.endpoint();
        let body = serde_json::to_vec(&tool).map_err(|e| json_error("tool arguments", e))?;
        let reply = self
            .upstream
            .post("tool", &[], self.bearer.as_ref(), None, body)
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
            Some(ok) => serde_json::from_value::<R>(ok.clone())
                .map_err(|e| json_error(format!("{at}: malformed response"), e)),
            None => Err(unavailable(format!("{at}: malformed response"))),
        }
    }
}
