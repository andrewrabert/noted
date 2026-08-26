use std::sync::Arc;

mod log;
mod note;
mod task;

use crate::backend::{ToolCall, ToolListing};
use crate::error::Result;
use crate::fragment::PolicyFragment;
use crate::note::{Condition, Edit, LogNote, LogQuery, TextNote, Trashed};
use crate::path::Path;
use crate::policy::RegionPolicy;
use crate::regions::{RegionDir, Regions};
use crate::search::{Hit, SearchQuery};
use crate::store::NotedDir;
use crate::tasks::{GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle};
use crate::tools::{ToolOutput, permitted, run_tool, tool_defs};
use crate::types::{LogBody, Source, TaskBody};

const INSTRUCTIONS: &str = "This is the user's personal notes \u{2014} the canonical place where they keep and organize their own notes, ideas, todos, and log entries as a nested tree of Markdown (.md) files. Whenever the user refers to 'my notes', asks to look something up, record or jot something down, or check what they've written before, use these tools instead of guessing or answering from memory. Search, read, write, edit, move, and delete notes by relative path (e.g. 'proj/ideas.md'). The tree has three regions and each has its own search tool: SearchNotes covers ordinary notes, SearchLog covers Log/, and SearchTasks covers Tasks/ \u{2014} none of them reaches into another's region. Use LogNote to quickly capture an immutable, timestamped log entry (its metadata is auto-generated and it cannot be edited or deleted), then GetLog to list entries newest first or SearchLog to match their text. Track units of work with the task tools: CreateTask opens a task (optionally in a nested 'group' under Tasks/, e.g. group='dev/noted'); GetTasks reads them (by group prefix, or an exact task path with body=true); UpdateTask advances one (state=created/started/blocked/completed/rejected/invalid); MoveTask changes a task's group. A task is identified by its Tasks-relative path minus '.md' (e.g. 'dev/noted/task_0001'); tasks are managed only through these tools \u{2014} WriteNote/EditNote are refused under Tasks/.";

use self::log::LogTools;
use self::note::NoteTools;
use self::task::TaskTools;

struct Root {
    regions: Regions,
    source: Option<Source>,
    note: NoteTools,
    log: LogTools,
    task: TaskTools,
}

#[derive(Clone)]
pub struct NotedRoot(Arc<Root>);

impl NotedRoot {
    pub fn open(dir: NotedDir, source: Option<Source>) -> Result<NotedRoot> {
        let regions = Regions::open(dir)?;
        Ok(NotedRoot(Arc::new(Root {
            note: NoteTools::new(regions.notes.clone()),
            log: LogTools::new(regions.log.clone(), source.clone()),
            task: TaskTools::new(regions.tasks.clone()),
            regions,
            source,
        })))
    }

    pub fn with_authority(&self, fragments: &[PolicyFragment]) -> Result<NotedRoot> {
        let source = self.0.source.clone();
        let regions = fragments.iter().try_fold(
            self.0.regions.clone(),
            |regions: Regions, fragment| -> Result<Regions> {
                regions.with_policy_fragment(fragment)
            },
        )?;
        Ok(NotedRoot(Arc::new(Root {
            note: NoteTools::new(regions.notes.clone()),
            log: LogTools::new(regions.log.clone(), source.clone()),
            task: TaskTools::new(regions.tasks.clone()),
            regions,
            source,
        })))
    }

    pub async fn invoke(&self, call: &ToolCall) -> Result<ToolOutput> {
        run_tool(call.name(), call.args(), self).await
    }

    pub fn tools(&self) -> Vec<ToolListing> {
        let allowed = permitted(
            self.policy(RegionDir::Notes),
            self.policy(RegionDir::Log),
            self.policy(RegionDir::Tasks),
        );
        let scope = self.policy(RegionDir::Notes).scope();
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
        match self.policy(RegionDir::Notes).scope() {
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

    pub(crate) fn policy(&self, dir: RegionDir) -> &RegionPolicy {
        match dir {
            RegionDir::Notes => self.0.regions.notes.policy(),
            RegionDir::Log => self.0.regions.log.policy(),
            RegionDir::Tasks => self.0.regions.tasks.policy(),
        }
    }

    pub async fn note_search(&self, query: &SearchQuery) -> Result<Vec<Hit>> {
        self.0.note.search(query).await
    }

    pub async fn log_search(&self, query: &LogQuery) -> Result<Vec<Hit>> {
        self.0.log.search(query).await
    }

    pub async fn task_search(&self, search: &TaskSearch) -> Result<Vec<Hit<TaskRef>>> {
        self.0.task.search(search).await
    }

    pub async fn note_read(&self, path: &Path) -> Result<TextNote> {
        self.0.note.read(path).await
    }

    pub async fn note_write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        self.0.note.write(note, condition).await
    }

    pub async fn note_edit(&self, path: &Path, edit: &Edit) -> Result<TextNote> {
        self.0.note.edit(path, edit).await
    }

    pub async fn note_move(&self, path: &Path, dest: &Path, overwrite: bool) -> Result<()> {
        self.0.note.move_(path, dest, overwrite).await
    }

    pub async fn note_delete(&self, path: &Path) -> Result<Trashed> {
        self.0.note.delete(path).await
    }

    pub async fn log_note(&self, body: &LogBody) -> Result<LogNote> {
        self.0.log.note(body).await
    }

    pub async fn log_get(&self, query: &LogQuery) -> Result<Vec<LogNote>> {
        self.0.log.get(query).await
    }

    pub async fn task_create(
        &self,
        title: &TaskTitle,
        group: &GroupPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        self.0.task.create(title, group, body).await
    }

    pub async fn task_get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        self.0.task.get(query).await
    }

    pub async fn task_update(&self, task: &TaskRef, change: &TaskChange) -> Result<TaskNote> {
        self.0.task.update(task, change).await
    }

    pub async fn task_move(&self, task: &TaskRef, group: &GroupPath) -> Result<TaskNote> {
        self.0.task.move_(task, group).await
    }
}
