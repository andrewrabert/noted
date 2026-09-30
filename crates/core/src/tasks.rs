use std::str::FromStr;

use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::{DirPath, TaskPath};
use crate::error::{NotedError, Result, rejected};
use crate::front_matter::{FrontMatter, split_front};
use crate::newtype::str_newtype_validated;
use crate::note::Note;
use crate::search::SearchQuery;
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

#[derive(Clone, Debug)]
pub struct TaskFront {
    pub task: TaskTitle,
    pub state: TaskState,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl TaskFront {
    pub(crate) fn read(front: &FrontMatter) -> Result<TaskFront> {
        let created_at: Timestamp = front.field("created_at")?;
        Ok(TaskFront {
            task: front.field("task")?,
            state: front.opt_field("state")?.unwrap_or_default(),
            created_at,
            updated_at: front.opt_field("updated_at")?.unwrap_or(created_at),
        })
    }

    pub(crate) fn write(&self) -> FrontMatter {
        let mut front = FrontMatter::default();
        front.set("task", self.task.as_str());
        front.set("state", self.state.as_str());
        front.set("created_at", self.created_at.to_string());
        front.set("updated_at", self.updated_at.to_string());
        front
    }
}

pub fn parse_task_file(text: &str) -> (Option<TaskFront>, TaskBody) {
    match split_front(text) {
        Some((block, body)) => match FrontMatter::parse(block).and_then(|f| TaskFront::read(&f)) {
            Ok(front) => (Some(front), TaskBody::new(body)),
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
    pub prefix: DirPath,
    pub include_completed: bool,
}

#[derive(Default)]
pub struct TaskSearch {
    pub prefix: DirPath,
    pub include_completed: bool,
    pub query: SearchQuery,
}

#[derive(Debug)]
pub struct TaskNote {
    path: TaskPath,
    front: TaskFront,
    body: TaskBody,
}

impl TaskNote {
    pub(crate) fn new(path: TaskPath, title: TaskTitle, body: TaskBody) -> TaskNote {
        let now = Timestamp::now();
        TaskNote {
            path,
            front: TaskFront {
                task: title,
                state: TaskState::Created,
                created_at: now,
                updated_at: now,
            },
            body,
        }
    }

    pub(crate) fn from_bytes(path: TaskPath, bytes: &[u8]) -> Result<TaskNote> {
        let text = std::str::from_utf8(bytes).map_err(|_| rejected("not a task"))?;
        let (front, body) = parse_task_file(text);
        let front = front.ok_or_else(|| rejected("not a task"))?;
        Ok(TaskNote { path, front, body })
    }

    pub fn path(&self) -> &TaskPath {
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
                created_at: self.front.created_at,
                updated_at: Timestamp::now(),
            },
            body,
        })
    }
}

impl Note for TaskNote {
    fn to_bytes(&self) -> Vec<u8> {
        self.front.write().dump(self.body.as_str()).into_bytes()
    }
}
