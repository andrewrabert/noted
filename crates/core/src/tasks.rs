use std::str::FromStr;

use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};
use crate::front_matter::{dump_front, split_front};
use crate::newtype::{str_newtype_validated, str_surface};
use crate::note::Note;
use crate::path::RelPath;
use crate::types::{TaskBody, Timestamp};

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    #[default]
    Created,
    Started,
    Blocked,
    Completed,
    Rejected,
    Invalid,
}

impl TaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Created => "created",
            TaskState::Started => "started",
            TaskState::Blocked => "blocked",
            TaskState::Completed => "completed",
            TaskState::Rejected => "rejected",
            TaskState::Invalid => "invalid",
        }
    }

    pub fn is_closed(self) -> bool {
        matches!(
            self,
            TaskState::Completed | TaskState::Rejected | TaskState::Invalid
        )
    }

    pub fn requires_body(self) -> bool {
        matches!(
            self,
            TaskState::Blocked | TaskState::Completed | TaskState::Rejected | TaskState::Invalid
        )
    }
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TaskState {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<TaskState> {
        match s {
            "created" => Ok(TaskState::Created),
            "started" => Ok(TaskState::Started),
            "blocked" => Ok(TaskState::Blocked),
            "completed" => Ok(TaskState::Completed),
            "rejected" => Ok(TaskState::Rejected),
            "invalid" => Ok(TaskState::Invalid),
            _ => Err(rejected(format!(
                "unknown state '{s}' (created, started, blocked, completed, rejected, invalid)"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct TaskTitle(String);
str_newtype_validated!(TaskTitle, validate_task_title);

fn validate_task_title(s: &str) -> Result<()> {
    if s.trim().is_empty() {
        return Err(rejected("task is required"));
    }
    Ok(())
}

fn valid_segment(part: &str) -> bool {
    let mut chars = part.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn segments(raw: &str) -> Result<String> {
    let mut parts = Vec::new();
    for part in raw.split('/').filter(|p| !p.is_empty()) {
        if !valid_segment(part) {
            return Err(rejected(format!(
                "invalid name '{part}': must start with a letter and use \
                 only letters, digits, '-' or '_'"
            )));
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

// Tool-schema field: a rustdoc comment here ships as the wire description.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct GroupPath(String);
str_surface!(GroupPath);

impl GroupPath {
    pub fn new(s: impl Into<String>) -> Result<GroupPath> {
        Ok(GroupPath(segments(&s.into())?))
    }

    pub(crate) fn to_rel(&self, tasks: &RelPath) -> RelPath {
        tasks.joined(&self.0)
    }
}

impl FromStr for GroupPath {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<GroupPath> {
        GroupPath::new(s)
    }
}

impl TryFrom<String> for GroupPath {
    type Error = NotedError;
    fn try_from(s: String) -> Result<GroupPath> {
        GroupPath::new(s)
    }
}

// Tool-schema field: a rustdoc comment here ships as the wire description.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct TaskRef(String);
str_surface!(TaskRef);

impl TaskRef {
    pub fn new(s: impl Into<String>) -> Result<TaskRef> {
        Ok(TaskRef(segments(&s.into())?))
    }

    pub(crate) fn of_file(path: &RelPath, tasks: &RelPath) -> TaskRef {
        let text = path.as_str();
        let text = text.strip_prefix(tasks.as_str()).unwrap_or(text);
        let text = text.strip_prefix('/').unwrap_or(text);
        TaskRef(text.strip_suffix(".md").unwrap_or(text).to_string())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn to_rel(&self, tasks: &RelPath) -> RelPath {
        tasks.joined(&format!("{}.md", self.0))
    }

    pub(crate) fn stem(&self) -> &str {
        match self.0.rsplit_once('/') {
            Some((_, name)) => name,
            None => &self.0,
        }
    }
}

impl FromStr for TaskRef {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<TaskRef> {
        TaskRef::new(s)
    }
}

impl TryFrom<String> for TaskRef {
    type Error = NotedError;
    fn try_from(s: String) -> Result<TaskRef> {
        TaskRef::new(s)
    }
}

impl Ord for TaskRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_lowercase()
            .cmp(&other.0.to_lowercase())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for TaskRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub(crate) fn numbered(stem: &str) -> Option<u64> {
    let digits = stem.strip_prefix("task_")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[derive(Clone, Debug, Serialize)]
pub struct TaskFront {
    pub task: TaskTitle,
    pub state: TaskState,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Deserialize)]
struct TaskFrontWire {
    task: Option<TaskTitle>,
    #[serde(default)]
    state: TaskState,
    created_at: Option<Timestamp>,
    updated_at: Option<Timestamp>,
}

impl TaskFrontWire {
    fn into_front(self) -> Option<TaskFront> {
        let task = self.task?;
        let created_at = self.created_at?;
        let updated_at = self.updated_at.unwrap_or_else(|| created_at.clone());
        Some(TaskFront {
            task,
            state: self.state,
            created_at,
            updated_at,
        })
    }
}

pub fn parse_task_file(text: &str) -> (Option<TaskFront>, TaskBody) {
    match split_front(text) {
        Some((block, body)) => match serde_yaml::from_str::<TaskFrontWire>(block) {
            Ok(wire) => (wire.into_front(), TaskBody::new(body)),
            Err(_) => (None, TaskBody::new(text)),
        },
        None => (None, TaskBody::new(text)),
    }
}

#[derive(Default)]
pub struct TaskChange {
    pub state: Option<TaskState>,
    pub notes: Option<TaskBody>,
    pub task: Option<TaskTitle>,
}

#[derive(Default)]
pub struct TaskQuery {
    pub prefix: TaskRef,
    pub include_completed: bool,
}

#[derive(Debug)]
pub struct TaskNote {
    path: TaskRef,
    front: TaskFront,
    body: TaskBody,
}

impl TaskNote {
    pub(crate) fn new(task: TaskTitle, body: TaskBody) -> TaskNote {
        let now = Timestamp::now();
        TaskNote {
            path: TaskRef::default(),
            front: TaskFront {
                task,
                state: TaskState::Created,
                created_at: now.clone(),
                updated_at: now,
            },
            body,
        }
    }

    pub(crate) fn from_bytes(path: TaskRef, bytes: &[u8]) -> Result<TaskNote> {
        let text = std::str::from_utf8(bytes).map_err(|_| rejected("not a task"))?;
        let (front, body) = parse_task_file(text);
        let front = front.ok_or_else(|| rejected("not a task"))?;
        Ok(TaskNote { path, front, body })
    }

    pub fn path(&self) -> &TaskRef {
        &self.path
    }

    pub fn front(&self) -> &TaskFront {
        &self.front
    }

    pub fn body(&self) -> &TaskBody {
        &self.body
    }

    pub(crate) fn changed(&self, change: &TaskChange) -> Result<TaskNote> {
        let state = change.state.unwrap_or(self.front.state);
        let body = change.notes.clone().unwrap_or_else(|| self.body.clone());
        if state.requires_body() && body.is_blank() {
            return Err(rejected(format!(
                "state '{state}' requires a non-empty note body"
            )));
        }
        Ok(TaskNote {
            path: self.path.clone(),
            front: TaskFront {
                task: change
                    .task
                    .clone()
                    .unwrap_or_else(|| self.front.task.clone()),
                state,
                created_at: self.front.created_at.clone(),
                updated_at: Timestamp::now(),
            },
            body,
        })
    }

    pub(crate) fn restamped(&self) -> TaskNote {
        let mut front = self.front.clone();
        front.updated_at = Timestamp::now();
        TaskNote {
            path: self.path.clone(),
            front,
            body: self.body.clone(),
        }
    }

    pub(crate) fn with_path(mut self, path: TaskRef) -> TaskNote {
        self.path = path;
        self
    }
}

impl Note for TaskNote {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(dump_front(&self.front, self.body.as_str())?.into_bytes())
    }
}
