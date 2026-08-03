use std::sync::Arc;

mod log;
mod note;
mod task;

use crate::areas::Areas;
use crate::authority::Authority;
use crate::error::Result;
use crate::note::{Condition, Edit, LogNote, LogQuery, TextNote, Trashed};
use crate::path::Path;
use crate::policy::Policy;
use crate::search::{Hit, LogWindow, SearchQuery};
use crate::store::NotedDir;
use crate::tasks::{GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle};
use crate::types::{LogBody, Source, TaskBody};

use self::log::LogTools;
use self::note::NoteTools;
use self::task::TaskTools;

struct Root {
    areas: Areas,
    source: Option<Source>,
    note: NoteTools,
    log: LogTools,
    task: TaskTools,
}

#[derive(Clone)]
pub struct NotedRoot(Arc<Root>);

impl NotedRoot {
    pub fn open(dir: NotedDir, grants: &[Authority], source: Option<Source>) -> Result<NotedRoot> {
        let policy = Authority::policy(grants)?;
        Ok(NotedRoot::over(Areas::new(dir, &policy)?, policy, source))
    }

    pub fn with_authority(&self, authority: &[Authority]) -> Result<NotedRoot> {
        let policy = Authority::policy(authority)?;
        let areas = Areas::over(self.0.areas.store(), &policy)?;
        Ok(NotedRoot::over(areas, policy, self.0.source.clone()))
    }

    fn over(areas: Areas, policy: Policy, source: Option<Source>) -> NotedRoot {
        NotedRoot(Arc::new(Root {
            note: NoteTools::new(areas.notes.clone()),
            log: LogTools::new(areas.log.clone(), source.clone(), policy.scope().cloned()),
            task: TaskTools::new(areas.tasks.clone()),
            areas,
            source,
        }))
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

    pub fn note_read(&self, path: &Path) -> Result<TextNote> {
        self.0.note.read(path)
    }

    pub fn note_write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        self.0.note.write(note, condition)
    }

    pub fn note_edit(&self, path: &Path, edit: &Edit) -> Result<TextNote> {
        self.0.note.edit(path, edit)
    }

    pub fn note_move(&self, path: &Path, dest: &Path, overwrite: bool) -> Result<()> {
        self.0.note.move_(path, dest, overwrite)
    }

    pub fn note_delete(&self, path: &Path) -> Result<Trashed> {
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
