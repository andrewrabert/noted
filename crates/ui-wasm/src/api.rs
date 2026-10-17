use noted::error::rejected;
use noted::search::{Hit, SearchMode, SearchOrder};
use noted::tasks::{TaskDue, TaskNote, TaskState};
use noted::tools::{Tools, UpdateTaskArgs};
use noted::{LogNote, LogPath, NotePath, TaskPath, TextNote, TextPath, Trashed};
use noted_client::{Backend, BackendArgs, Transport};
use serde_json::json;

fn pattern_or_all(pattern: &str) -> String {
    if pattern.trim().is_empty() {
        ".".to_string()
    } else {
        pattern.to_string()
    }
}

pub async fn search_notes(
    backend: noted::Result<Backend>,
    pattern: String,
    mode: SearchMode,
    sort: SearchOrder,
) -> Result<Vec<Hit<TextPath>>, ApiError> {
    async move {
        let args = serde_json::from_value(json!({
            "pattern": pattern_or_all(&pattern),
            "mode": mode,
            "sort": sort,
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.search_notes(args).await
    }
    .await
    .map_err(ApiError::of)
}

/// An empty bound is omitted rather than sent: the tool reads a missing bound as
/// unbounded and an empty string as a malformed instant.
pub async fn search_log(
    backend: noted::Result<Backend>,
    pattern: String,
    since: String,
    until: String,
    limit: i64,
) -> Result<Vec<Hit<LogPath>>, ApiError> {
    async move {
        let (since, until) = (since.trim(), until.trim());
        let args = serde_json::from_value(json!({
            "pattern": pattern_or_all(&pattern),
            "mode": SearchMode::Line,
            "since": (!since.is_empty()).then_some(since),
            "until": (!until.is_empty()).then_some(until),
            "limit": limit,
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.search_log(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn search_tasks(
    backend: noted::Result<Backend>,
    pattern: String,
    prefix: String,
    include_completed: bool,
) -> Result<Vec<Hit<TaskPath>>, ApiError> {
    async move {
        let args = serde_json::from_value(json!({
            "pattern": pattern_or_all(&pattern),
            "prefix": prefix,
            "include_completed": include_completed,
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.search_tasks(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn get_log(
    backend: noted::Result<Backend>,
    since: String,
    until: String,
    limit: i64,
) -> Result<Vec<LogNote>, ApiError> {
    async move {
        let (since, until) = (since.trim(), until.trim());
        let args = serde_json::from_value(json!({
            "since": (!since.is_empty()).then_some(since),
            "until": (!until.is_empty()).then_some(until),
            "limit": limit,
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.get_log(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn read_note(
    backend: noted::Result<Backend>,
    path: String,
) -> Result<TextNote, ApiError> {
    async move {
        let args =
            serde_json::from_value(json!({ "path": path })).map_err(|e| rejected(e.to_string()))?;
        backend?.read_note(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn write_note(
    backend: noted::Result<Backend>,
    path: String,
    content: String,
) -> Result<(), ApiError> {
    async move {
        let args = serde_json::from_value(json!({ "path": path, "content": content }))
            .map_err(|e| rejected(e.to_string()))?;
        backend?.write_note(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn edit_note(
    backend: noted::Result<Backend>,
    path: String,
    old_string: String,
    new_string: String,
    replace_all: bool,
) -> Result<TextNote, ApiError> {
    async move {
        let args = serde_json::from_value(json!({
            "path": path,
            "old_string": old_string,
            "new_string": new_string,
            "replace_all": replace_all,
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.edit_note(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn move_note(
    backend: noted::Result<Backend>,
    path: String,
    dest: String,
    overwrite: bool,
) -> Result<(), ApiError> {
    async move {
        let args = serde_json::from_value(json!({
            "path": path,
            "dest": dest,
            "overwrite": overwrite,
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.move_note(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn delete_note(
    backend: noted::Result<Backend>,
    path: String,
) -> Result<Trashed, ApiError> {
    async move {
        let args =
            serde_json::from_value(json!({ "path": path })).map_err(|e| rejected(e.to_string()))?;
        backend?.delete_note(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn log_note(backend: noted::Result<Backend>, body: String) -> Result<LogNote, ApiError> {
    async move {
        let args =
            serde_json::from_value(json!({ "body": body })).map_err(|e| rejected(e.to_string()))?;
        backend?.log_note(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn create_task(
    backend: noted::Result<Backend>,
    task: String,
    dir: String,
    notes: String,
    due: String,
) -> Result<TaskNote, ApiError> {
    async move {
        let args = serde_json::from_value(json!({
            "task": task,
            "dir": dir,
            "notes": notes,
            "due": (!due.is_empty()).then_some(due),
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.create_task(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn get_tasks(
    backend: noted::Result<Backend>,
    prefix: String,
    include_completed: bool,
) -> Result<Vec<TaskNote>, ApiError> {
    async move {
        let args = serde_json::from_value(json!({
            "prefix": prefix,
            "include_completed": include_completed,
        }))
        .map_err(|e| rejected(e.to_string()))?;
        backend?.get_tasks(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn update_task(
    backend: noted::Result<Backend>,
    path: String,
    state: Option<TaskState>,
    due: Option<TaskDue>,
) -> Result<TaskNote, ApiError> {
    async move {
        let args = UpdateTaskArgs {
            path: NotePath::new(&path).and_then(TaskPath::try_from)?,
            state,
            notes: None,
            task: None,
            due,
        };
        backend?.update_task(args).await
    }
    .await
    .map_err(ApiError::of)
}

pub async fn move_task(
    backend: noted::Result<Backend>,
    path: String,
    dest: String,
) -> Result<TaskNote, ApiError> {
    async move {
        let args = serde_json::from_value(json!({ "path": path, "dest": dest }))
            .map_err(|e| rejected(e.to_string()))?;
        backend?.move_task(args).await
    }
    .await
    .map_err(ApiError::of)
}

/// The Clone-able projection a `Message` can hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    Unauthorized,
    InvalidCredentials,
    UnknownTxn,
    Failed(String),
}

impl ApiError {
    pub fn of(error: noted::NotedError) -> ApiError {
        match error {
            noted::NotedError::Unauthorized => ApiError::Unauthorized,
            noted::NotedError::InvalidCredentials => ApiError::InvalidCredentials,
            noted::NotedError::UnknownTxn => ApiError::UnknownTxn,
            other => ApiError::Failed(other.message().into_owned()),
        }
    }

    /// The sentence the status bar or the overlay shows.
    pub fn message(&self) -> String {
        match self {
            ApiError::Unauthorized => noted::NotedError::Unauthorized.message().into_owned(),
            ApiError::InvalidCredentials => {
                noted::NotedError::InvalidCredentials.message().into_owned()
            }
            ApiError::UnknownTxn => noted::NotedError::UnknownTxn.message().into_owned(),
            ApiError::Failed(message) => message.clone(),
        }
    }
}

/// The same construction whether or not a token exists yet.
pub fn remote(endpoint: String, bearer: Option<noted::Bearer>) -> noted::Result<Backend> {
    Backend::new(BackendArgs::Remote {
        endpoint: endpoint.parse()?,
        bearer,
        transport: Transport::Real,
    })
}
