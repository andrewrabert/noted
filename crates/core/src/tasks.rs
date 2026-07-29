use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{NotedError, Result, forbidden, io_error, not_found, rejected};
use crate::front_matter::{dump_front, split_front};
use crate::newtype::{str_newtype, str_newtype_validated};
use crate::note::{Note, RelPath};
use crate::types::Timestamp;
use crate::util::{IgnoreFilter, atomic_create, atomic_write};

const DIR: &str = "Tasks";

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

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct GroupPath(String);
str_newtype!(GroupPath);

#[derive(Clone, Serialize)]
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

fn valid_segment(part: &str) -> bool {
    let mut chars = part.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn numbered(stem: &str) -> Option<u64> {
    let digits = stem.strip_prefix("task_")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

pub fn parse_task_file(text: &str) -> (Option<TaskFront>, String) {
    match split_front(text) {
        Some((block, body)) => match serde_yaml::from_str::<TaskFrontWire>(block) {
            Ok(wire) => (wire.into_front(), body.to_string()),
            Err(_) => (None, text.to_string()),
        },
        None => (None, text.to_string()),
    }
}

/// A task as a domain object: typed frontmatter plus its markdown body. Parsing
/// (`from_bytes`) is the one fallible edge — a file under `Tasks/` that isn't a
/// well-formed task is rejected; everything downstream holds a valid `TaskNote`.
pub struct TaskNote {
    front: TaskFront,
    body: String,
}

impl TaskNote {
    fn new(task: TaskTitle, state: TaskState, body: String) -> TaskNote {
        let now = Timestamp::now();
        TaskNote {
            front: TaskFront {
                task,
                state,
                created_at: now.clone(),
                updated_at: now,
            },
            body,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<TaskNote> {
        let text = std::str::from_utf8(bytes).map_err(|_| rejected("not a task"))?;
        let (front, body) = parse_task_file(text);
        let front = front.ok_or_else(|| rejected("not a task"))?;
        Ok(TaskNote { front, body })
    }

    fn front(&self) -> &TaskFront {
        &self.front
    }

    fn body(&self) -> &str {
        &self.body
    }

    /// Apply an edit, re-validating the schema and stamping `updated_at`.
    /// `created_at` is preserved.
    fn reconciled(&self, task: &TaskTitle, state: TaskState, body: &str) -> Result<TaskNote> {
        if state.requires_body() && body.trim().is_empty() {
            return Err(rejected(format!(
                "state '{state}' requires a non-empty note body"
            )));
        }
        Ok(TaskNote {
            front: TaskFront {
                task: task.clone(),
                state,
                created_at: self.front.created_at.clone(),
                updated_at: Timestamp::now(),
            },
            body: body.to_string(),
        })
    }

    /// Restamp `updated_at` without touching the schema (used by a group move).
    fn restamped(&self) -> TaskNote {
        let mut front = self.front.clone();
        front.updated_at = Timestamp::now();
        TaskNote {
            front,
            body: self.body.clone(),
        }
    }
}

impl Note for TaskNote {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(dump_front(&self.front, &self.body)?.into_bytes())
    }
}

#[derive(Clone)]
pub struct Tasks {
    root: PathBuf,
    dir: PathBuf,
    confine: Option<Vec<String>>,
}

impl Tasks {
    pub fn new(root: &Path) -> Tasks {
        Tasks {
            root: root.to_path_buf(),
            dir: root.join(DIR),
            confine: None,
        }
    }

    pub fn confined(&self, folders: Option<Vec<String>>) -> Tasks {
        match folders {
            None => self.clone(),
            Some(folders) => Tasks {
                root: self.root.clone(),
                dir: self.dir.clone(),
                confine: Some(folders),
            },
        }
    }

    fn within_confine(&self, path: &Path) -> bool {
        match &self.confine {
            None => true,
            Some(folders) => folders.iter().any(|folder| {
                let base = crate::util::normalize(&self.dir.join(folder));
                path == base || path.starts_with(&base)
            }),
        }
    }

    fn resolve(&self, rel: &str) -> Result<PathBuf> {
        let rel = rel.trim_matches('/');
        let mut target = self.dir.clone();
        for part in rel.split('/').filter(|p| !p.is_empty()) {
            if !valid_segment(part) {
                return Err(rejected(format!(
                    "invalid name '{part}': must start with a letter and use \
                     only letters, digits, '-' or '_'"
                )));
            }
            target.push(part);
        }
        if self.confine.is_some() && !self.within_confine(&crate::util::normalize(&target)) {
            return Err(forbidden(format!(
                "task path outside allowed folders: '{rel}'"
            )));
        }
        if IgnoreFilter::new(&self.root).is_ignored(&target) {
            return Err(rejected(format!("invalid path: '{rel}'")));
        }
        Ok(target)
    }

    fn task_path(&self, reference: &str) -> Result<PathBuf> {
        if reference.trim_matches('/').is_empty() {
            return Err(rejected("task path required"));
        }
        let path = self.resolve(reference)?.with_extension("md");
        if IgnoreFilter::new(&self.root).is_ignored(&path) {
            return Err(rejected(format!("invalid path: '{reference}'")));
        }
        Ok(path)
    }

    fn has_symlink(&self, path: &Path) -> bool {
        let Ok(rest) = path.strip_prefix(&self.dir) else {
            return false;
        };
        let mut cur = self.dir.clone();
        for part in rest.components() {
            cur.push(part);
            if let Ok(meta) = std::fs::symlink_metadata(&cur)
                && meta.file_type().is_symlink()
            {
                return true;
            }
        }
        false
    }

    fn real_file(&self, path: &Path) -> bool {
        path.is_file() && !self.has_symlink(path)
    }

    fn rel(&self, path: &Path) -> String {
        let stripped = path.strip_prefix(&self.dir).unwrap_or(path);
        let no_ext = stripped.with_extension("");
        no_ext.to_string_lossy().into_owned()
    }

    fn read_task(&self, path: &Path, reference: &RelPath) -> Result<TaskNote> {
        let bytes = std::fs::read(path).map_err(|e| io_error("read failed", e))?;
        TaskNote::from_bytes(&bytes).map_err(|_| rejected(format!("not a task: '{reference}'")))
    }

    fn files(&self, group: Option<&str>) -> Result<Vec<PathBuf>> {
        let base = match group {
            Some(g) => self.resolve(g)?,
            None => self.dir.clone(),
        };
        if !base.is_dir() || self.has_symlink(&base) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        collect_md(&base, &mut out);
        let filter = IgnoreFilter::new(&self.root);
        out.retain(|p| !filter.is_ignored(p));
        out.sort_by_cached_key(|p| RelPath::new(p.to_string_lossy().into_owned()));
        Ok(out)
    }

    fn next_number(&self, group_dir: &Path) -> u64 {
        let mut max = 0u64;
        let filter = IgnoreFilter::new(&self.root);
        if let Ok(entries) = std::fs::read_dir(group_dir) {
            for entry in entries.flatten() {
                if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                    continue;
                }
                let path = entry.path();
                if filter.is_ignored(&path) {
                    continue;
                }
                let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned());
                if let Some(n) = stem.as_deref().and_then(numbered) {
                    max = max.max(n);
                }
            }
        }
        max + 1
    }

    fn summary(&self, path: &Path, front: &TaskFront) -> serde_json::Value {
        json!({
            "path": self.rel(path),
            "task": front.task,
            "state": front.state,
            "created_at": front.created_at,
            "updated_at": front.updated_at,
        })
    }

    fn claim_name(&self, group_dir: &Path, data: &[u8]) -> Result<PathBuf> {
        for _ in 0..100 {
            let base = self.next_number(group_dir);
            for number in base..base + 1000 {
                let path = group_dir.join(format!("task_{number:04}.md"));
                match atomic_create(&path, data) {
                    Ok(()) => return Ok(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(io_error("write failed", e)),
                }
            }
        }
        Err(rejected(format!(
            "could not allocate a task name in '{}'",
            group_dir.display()
        )))
    }

    pub fn create(
        &self,
        task: &TaskTitle,
        group: &GroupPath,
        notes: &str,
    ) -> Result<serde_json::Value> {
        let group_dir = self.resolve(group.as_str())?;
        let task_note = TaskNote::new(task.clone(), TaskState::Created, notes.to_string());
        let path = self.claim_name(&group_dir, &task_note.to_bytes()?)?;
        Ok(self.summary(&path, task_note.front()))
    }

    pub fn query(
        &self,
        prefix: &str,
        body: bool,
        include_completed: bool,
    ) -> Result<serde_json::Value> {
        let prefix = prefix.trim_matches('/');
        let exact = if prefix.is_empty() {
            None
        } else {
            Some(self.resolve(prefix)?.with_extension("md"))
        };
        let (paths, filter_closed) = match &exact {
            Some(p) if self.real_file(p) => (vec![p.clone()], false),
            _ => {
                let group = if prefix.is_empty() {
                    None
                } else {
                    Some(prefix)
                };
                (self.files(group)?, !include_completed)
            }
        };
        let mut records: Vec<serde_json::Value> = Vec::new();
        for path in paths {
            if self.confine.is_some() && !self.within_confine(&crate::util::normalize(&path)) {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|e| io_error("read failed", e))?;
            let Ok(task_note) = TaskNote::from_bytes(&bytes) else {
                continue;
            };
            if filter_closed && task_note.front().state.is_closed() {
                continue;
            }
            let mut record = self.summary(&path, task_note.front());
            if body {
                record["body"] = json!(task_note.body());
            }
            records.push(record);
        }
        let updated_instant = |r: &serde_json::Value| {
            r["updated_at"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        };
        records.sort_by_cached_key(|r| {
            let path = RelPath::new(r["path"].as_str().unwrap_or_default().to_string());
            (std::cmp::Reverse(updated_instant(r)), path)
        });
        Ok(serde_json::Value::Array(records))
    }

    pub fn update(
        &self,
        reference: &RelPath,
        state: Option<TaskState>,
        note: Option<&str>,
        task: Option<&TaskTitle>,
    ) -> Result<serde_json::Value> {
        let path = self.task_path(reference)?;
        if !self.real_file(&path) {
            return Err(not_found(format!("no task at '{reference}'")));
        }
        let prior = self.read_task(&path, reference)?;
        let updated = prior.reconciled(
            task.unwrap_or(&prior.front().task),
            state.unwrap_or(prior.front().state),
            note.unwrap_or(prior.body()),
        )?;
        atomic_write(&path, &updated.to_bytes()?)?;
        Ok(self.summary(&path, updated.front()))
    }

    pub fn move_task(&self, reference: &RelPath, group: &GroupPath) -> Result<serde_json::Value> {
        let src = self.task_path(reference)?;
        if !self.real_file(&src) {
            return Err(not_found(format!("no task at '{reference}'")));
        }
        let dest_dir = self.resolve(group.as_str())?;
        if dest_dir == src.parent().unwrap_or(&self.dir) {
            return Err(rejected("task already in that group"));
        }
        let relocated = self.read_task(&src, reference)?.restamped();
        let bytes = relocated.to_bytes()?;

        let stem = src
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dest = if numbered(&stem).is_some() {
            self.claim_name(&dest_dir, &bytes)?
        } else {
            let dest = dest_dir.join(format!("{stem}.md"));
            match atomic_create(&dest, &bytes) {
                Ok(()) => dest,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(rejected(format!(
                        "destination exists: '{}'",
                        self.rel(&dest)
                    )));
                }
                Err(e) => return Err(io_error("write failed", e)),
            }
        };
        std::fs::remove_file(&src).map_err(|e| io_error("move failed", e))?;
        Ok(self.summary(&dest, relocated.front()))
    }
}

fn collect_md(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            collect_md(&path, out);
        } else if ft.is_file() && path.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push(path);
        }
    }
}
