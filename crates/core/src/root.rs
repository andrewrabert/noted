use std::sync::Arc;

mod find;
mod log;
mod note;
mod task;
mod trash;

use crate::areas::Areas;
use crate::caller::{Caller, Policy};
use crate::error::Result;
use crate::note::{Condition, Edit, LogNote, LogQuery, TextNote, Trashed};
use crate::path::RelPath;
use crate::search::{Hit, LogWindow, SearchQuery};
use crate::store::Store;
use crate::tasks::{GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle};
use crate::types::{LogBody, TaskBody};

use self::find::Find;
use self::log::Log;
use self::note::Note;
use self::task::Task;
use self::trash::Trash;

struct Root {
    store: Store,
    caller: Caller,
    note: Note,
    log: Log,
    task: Task,
}

#[derive(Clone)]
pub struct NotedRoot(Arc<Root>);

impl NotedRoot {
    pub fn new(store: Store, caller: Caller) -> NotedRoot {
        let areas = Areas::new();
        let find = Find::new(store.clone(), caller.clone());
        let trash = Trash::new(store.clone(), areas.clone());
        NotedRoot(Arc::new(Root {
            note: Note::new(
                store.clone(),
                areas.clone(),
                caller.clone(),
                find.clone(),
                trash,
            ),
            log: Log::new(store.clone(), areas.clone(), caller.clone(), find.clone()),
            task: Task::new(store.clone(), areas, caller.clone(), find),
            store,
            caller,
        }))
    }

    pub fn confined(&self, admits: Policy) -> NotedRoot {
        NotedRoot::new(self.0.store.clone(), self.0.caller.with_policy(admits))
    }

    pub async fn note_search(&self, query: &SearchQuery) -> Result<Vec<Hit>> {
        self.0.note.search(query).await
    }

    pub async fn log_search(&self, window: &LogWindow, query: &SearchQuery) -> Result<Vec<Hit>> {
        self.0.log.search(window, query).await
    }

    pub async fn task_search(&self, search: &TaskSearch) -> Result<Vec<Hit<TaskRef>>> {
        self.0.task.search(search).await
    }

    pub fn note_read(&self, path: &RelPath) -> Result<TextNote> {
        self.0.note.read(path)
    }

    pub fn note_write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        self.0.note.write(note, condition)
    }

    pub fn note_edit(&self, path: &RelPath, edit: &Edit) -> Result<TextNote> {
        self.0.note.edit(path, edit)
    }

    pub fn note_move(&self, path: &RelPath, dest: &RelPath, overwrite: bool) -> Result<()> {
        self.0.note.move_(path, dest, overwrite)
    }

    pub fn note_delete(&self, path: &RelPath) -> Result<Trashed> {
        self.0.note.delete(path)
    }

    pub fn log_note(&self, body: &LogBody) -> Result<LogNote> {
        self.0.log.note(body)
    }

    pub fn log_get(&self, query: &LogQuery) -> Result<Vec<LogNote>> {
        self.0.log.get(query)
    }

    pub fn task_create(
        &self,
        title: &TaskTitle,
        group: &GroupPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        self.0.task.create(title, group, body)
    }

    pub fn task_get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        self.0.task.get(query)
    }

    pub fn task_update(&self, task: &TaskRef, change: &TaskChange) -> Result<TaskNote> {
        self.0.task.update(task, change)
    }

    pub fn task_move(&self, task: &TaskRef, group: &GroupPath) -> Result<TaskNote> {
        self.0.task.move_(task, group)
    }
}
