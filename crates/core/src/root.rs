use std::sync::Arc;

mod log;
mod note;
mod task;

use crate::error::Result;
use crate::fragment::PolicyFragment;
use crate::note::{Condition, Edit, LogNote, LogQuery, TextNote, Trashed};
use crate::path::Path;
use crate::policy::RegionPolicy;
use crate::regions::{RegionDir, Regions};
use crate::search::{Hit, SearchQuery};
use crate::store::NotedDir;
use crate::tasks::{GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle};
use crate::types::{LogBody, Source, TaskBody};

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
