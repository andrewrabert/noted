use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::upstream::{Reply, Transport, Upstream};
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
#[cfg(not(target_arch = "wasm32"))]
use noted::{NoteEvent, NoteWatch, tools::WatchArgs};

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

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn watch_note(&self, path: TextPath) -> Result<NoteChanges> {
        let inner = match &self.inner {
            Inner::Local(root) => ChangesInner::Local(root.note_watch(&path).await?),
            Inner::Remote(remote) => ChangesInner::Remote(remote.watch_note(path).await?),
        };
        Ok(NoteChanges { inner })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub struct NoteChanges {
    inner: ChangesInner,
}

#[cfg(not(target_arch = "wasm32"))]
enum ChangesInner {
    Local(NoteWatch),
    Remote(EventStream),
}

#[cfg(not(target_arch = "wasm32"))]
impl NoteChanges {
    pub async fn next(&mut self) -> Result<Option<NoteEvent>> {
        match &mut self.inner {
            ChangesInner::Local(watch) => watch.next().await.transpose(),
            ChangesInner::Remote(events) => events.next().await,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct EventStream {
    body: crate::upstream::ByteStream,
    buffer: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
impl EventStream {
    async fn next(&mut self) -> Result<Option<NoteEvent>> {
        use futures_util::StreamExt;
        loop {
            if let Some(end) = self.buffer.windows(2).position(|pair| pair == b"\n\n") {
                let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
                match parse_event(&block)? {
                    Some(event) => return Ok(Some(event)),
                    None => continue,
                }
            }
            match self.body.next().await {
                Some(Ok(chunk)) => self.buffer.extend_from_slice(&chunk),
                Some(Err(e)) => return Err(unavailable(format!("note events stopped: {e}"))),
                None => return Ok(None),
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_event(block: &[u8]) -> Result<Option<NoteEvent>> {
    let block = std::str::from_utf8(block)
        .map_err(|e| unavailable(format!("note event is not utf-8: {e}")))?;
    let mut kind = None;
    let mut data = Vec::new();
    for line in block.lines() {
        let field = |name: &str| {
            line.strip_prefix(name)
                .map(|value| value.strip_prefix(' ').unwrap_or(value))
        };
        if let Some(value) = field("data:") {
            data.push(value);
        } else if let Some(value) = field("event:") {
            kind = Some(value);
        }
    }
    if data.is_empty() {
        return Ok(None);
    }
    let data = data.join("\n");
    match kind {
        None => serde_json::from_str(&data)
            .map(Some)
            .map_err(|e| json_error("malformed note event", e)),
        Some("error") => Err(unavailable(data)),
        Some(other) => Err(unavailable(format!("unknown note event: '{other}'"))),
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
    #[cfg(not(target_arch = "wasm32"))]
    async fn watch_note(&self, path: TextPath) -> Result<EventStream> {
        let body = serde_json::to_vec(&WatchArgs::new(path))
            .map_err(|e| json_error("watch arguments", e))?;
        let streamed = self
            .upstream
            .post_stream(
                "watch",
                &[],
                self.bearer.as_ref(),
                Some("text/event-stream"),
                body,
            )
            .await?;
        if streamed.is_refusal() {
            let reply = streamed.collect().await?;
            return Err(self.refusal(&reply));
        }
        Ok(EventStream {
            body: streamed.body,
            buffer: Vec::new(),
        })
    }

    fn refusal(&self, reply: &Reply) -> NotedError {
        let at = self.upstream.endpoint();
        let Ok(status) = StatusCode::from_u16(reply.status) else {
            return unavailable(format!("{at}: {}", reply.detail()));
        };
        if status.is_server_error() {
            return unavailable(format!("{at}: {}", reply.detail()));
        }
        match status {
            StatusCode::NOT_FOUND => NotedError::NotFound,
            StatusCode::FORBIDDEN => NotedError::Forbidden,
            StatusCode::UNAUTHORIZED => NotedError::Unauthorized,
            StatusCode::CONFLICT => NotedError::Conflict,
            _ => rejected(reply.detail()),
        }
    }

    // the tool, name and args, is the whole body of `tool`
    async fn post_tool<R: DeserializeOwned>(&self, tool: Tool) -> Result<R> {
        let at = self.upstream.endpoint();
        let body = serde_json::to_vec(&tool).map_err(|e| json_error("tool arguments", e))?;
        let reply = self
            .upstream
            .post("tool", &[], self.bearer.as_ref(), None, body)
            .await?;
        if reply.is_refusal() {
            return Err(self.refusal(&reply));
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
