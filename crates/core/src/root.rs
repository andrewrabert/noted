use std::sync::Arc;

mod log;
mod note;
mod task;

use crate::call::{ToolCall, ToolListing};
use crate::domain::{DirPath, LogPath, NotePath, TaskPath, TextPath};
use crate::error::Result;
use crate::fragment::PolicyFragment;
use crate::note::{Condition, Edit, LogNote, LogQuery, TextNote, Trashed};
use crate::policy::Policy;
use crate::policy_store::PolicyStore;
use crate::search::{Hit, SearchQuery};
use crate::store::NotedDir;
use crate::tasks::{TaskChange, TaskNote, TaskQuery, TaskSearch, TaskTitle};
use crate::tools::{ToolOutput, permitted, run_tool, tool_defs};
use crate::types::{LogBody, Source, TaskBody};

const INSTRUCTIONS: &str = "This is the user's personal notes \u{2014} the canonical place where they keep and organize their own notes, ideas, todos, and log entries as a nested tree of Markdown (.md) files. Whenever the user refers to 'my notes', asks to look something up, record or jot something down, or check what they've written before, use these tools instead of guessing or answering from memory. Search, read, write, edit, move, and delete notes by relative path (e.g. 'proj/ideas'). Tasks and log entries live in the same tree as notes: '#N' names task N inside the directory before it (e.g. 'dev/#2') and '@S' names the log entry written at instant S (e.g. 'dev/@2026-08-03T09:15:30.123456-07:00'). Both are directories, so notes, further tasks and further entries can live inside them (e.g. 'dev/#2/plan', 'dev/#2/#1'). Each kind has its own search tool: SearchNotes covers notes (including notes inside tasks and entries), SearchLog covers log entries, and SearchTasks covers tasks. Use LogNote to capture an immutable, timestamped log entry in any directory (its metadata is auto-generated and it cannot be edited or deleted), then GetLog to list entries newest first or SearchLog to match their text. Track units of work with the task tools: CreateTask opens a task in a directory (e.g. dir='dev/noted' creates 'dev/noted/#3'); GetTasks reads them (by directory prefix, or an exact task path with body=true); UpdateTask advances one (state=created/started/blocked/completed/rejected/invalid); MoveTask moves a task into another directory. A task itself is changed only through these tools \u{2014} WriteNote/EditNote/MoveNote are refused on a task or entry path.";

use self::log::LogTools;
use self::note::NoteTools;
use self::task::TaskTools;

struct Root {
    store: PolicyStore,
    source: Option<Source>,
    note: NoteTools,
    log: LogTools,
    task: TaskTools,
}

#[derive(Clone)]
pub struct NotedRoot(Arc<Root>);

impl NotedRoot {
    pub fn open(dir: NotedDir, source: Option<Source>) -> Result<NotedRoot> {
        let store = PolicyStore::open(dir)?;
        Ok(NotedRoot(Arc::new(Root {
            note: NoteTools::new(store.clone()),
            log: LogTools::new(store.clone(), source.clone()),
            task: TaskTools::new(store.clone()),
            store,
            source,
        })))
    }

    pub fn with_authority(&self, fragments: &[PolicyFragment]) -> Result<NotedRoot> {
        let source = self.0.source.clone();
        let store = fragments.iter().try_fold(
            self.0.store.clone(),
            |store: PolicyStore, fragment| -> Result<PolicyStore> {
                store.with_policy_fragment(fragment)
            },
        )?;
        Ok(NotedRoot(Arc::new(Root {
            note: NoteTools::new(store.clone()),
            log: LogTools::new(store.clone(), source.clone()),
            task: TaskTools::new(store.clone()),
            store,
            source,
        })))
    }

    pub async fn invoke(&self, call: &ToolCall) -> Result<ToolOutput> {
        run_tool(call.name(), call.args(), self).await
    }

    pub fn tools(&self) -> Vec<ToolListing> {
        let allowed = permitted(self.policy());
        let scope = self.policy().scope();
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
        let scope = self.policy().scope();
        match scope == &NotePath::default() {
            true => out.push_str(" Notes, tasks and log entries all start at the top of the tree."),
            false => out.push_str(&format!(
                " You are working in {scope}. Every path you write is relative to it. \
Tasks and log entries you create land inside it."
            )),
        }
        out
    }

    pub(crate) fn policy(&self) -> &Policy {
        self.0.store.policy()
    }

    pub async fn note_search(&self, query: &SearchQuery) -> Result<Vec<Hit<TextPath>>> {
        self.0.note.search(query).await
    }

    pub async fn log_search(&self, query: &LogQuery) -> Result<Vec<Hit<LogPath>>> {
        self.0.log.search(query).await
    }

    pub async fn task_search(&self, search: &TaskSearch) -> Result<Vec<Hit<TaskPath>>> {
        self.0.task.search(search).await
    }

    pub async fn note_read(&self, path: &TextPath) -> Result<TextNote> {
        self.0.note.read(path).await
    }

    pub async fn note_write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        self.0.note.write(note, condition).await
    }

    pub async fn note_edit(&self, path: &TextPath, edit: &Edit) -> Result<TextNote> {
        self.0.note.edit(path, edit).await
    }

    pub async fn note_move(&self, path: &TextPath, dest: &TextPath, overwrite: bool) -> Result<()> {
        self.0.note.move_(path, dest, overwrite).await
    }

    pub async fn note_delete(&self, path: &TextPath) -> Result<Trashed> {
        self.0.note.delete(path).await
    }

    pub async fn log_note(&self, dir: &DirPath, body: &LogBody) -> Result<LogNote> {
        self.0.log.note(dir, body).await
    }

    pub async fn log_get(&self, query: &LogQuery) -> Result<Vec<LogNote>> {
        self.0.log.get(query).await
    }

    pub async fn task_create(
        &self,
        title: &TaskTitle,
        dir: &DirPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        self.0.task.create(title, dir, body).await
    }

    pub async fn task_get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        self.0.task.get(query).await
    }

    pub async fn task_update(&self, task: &TaskPath, change: &TaskChange) -> Result<TaskNote> {
        self.0.task.update(task, change).await
    }

    pub async fn task_move(&self, task: &TaskPath, dest: &DirPath) -> Result<TaskNote> {
        self.0.task.move_(task, dest).await
    }
}
