use std::cmp::Reverse;
use std::num::NonZeroU64;
use std::sync::OnceLock;

use crate::domain::{DirPath, TaskDirPath, TaskPath};
use crate::error::{NotedError, Result, rejected};
use crate::note::{Condition, Note as _};
use crate::policy_store::PolicyStore;
use crate::search::Hit;
use crate::tasks::{TaskChange, TaskNote, TaskQuery, TaskSearch, TaskTitle};
use crate::types::TaskBody;

// how a claimed task name is filled: a fresh task is built for each
// candidate path and, once its write lands, kept in the slot
#[derive(Clone, Copy)]
enum Placement<'a> {
    Fresh(&'a TaskTitle, &'a TaskBody, &'a OnceLock<TaskNote>),
    Existing(&'a TaskPath),
}

fn named(dir: &DirPath) -> String {
    match dir == &DirPath::default() {
        true => "the top level".to_string(),
        false => dir.to_string(),
    }
}

pub(super) struct TaskTools {
    store: PolicyStore,
}

impl TaskTools {
    pub(super) fn new(store: PolicyStore) -> TaskTools {
        TaskTools { store }
    }

    async fn read(&self, task: &TaskPath) -> Result<TaskNote> {
        let file = self.store.policy().readable(task.as_ref())?.file()?;
        let bytes = self.store.read(&file).await?;
        TaskNote::from_bytes(task.clone(), &bytes).map_err(|_| rejected("not a task"))
    }

    // one more than the largest task sitting directly in `dir`
    async fn next_number(&self, dir: &DirPath) -> Result<u64> {
        let tasks = DirPath::try_from(TaskDirPath::new(dir)?.as_ref().clone())?;
        Ok(self
            .store
            .walk(&tasks, Some(1))
            .await
            .into_iter()
            .filter_map(|at| TaskPath::try_from(at).ok())
            .map(|task| task.number())
            .map(NonZeroU64::get)
            .max()
            .unwrap_or(0)
            + 1)
    }

    async fn place(&self, at: &TaskPath, what: Placement<'_>) -> Result<()> {
        match what {
            Placement::Fresh(title, body, placed) => {
                let task = TaskNote::new(at.clone(), title.clone(), body.clone());
                let file = self.store.policy().writeable(at.as_ref())?.file()?;
                self.store
                    .write(&file, &task.to_bytes(), Condition::Missing)
                    .await?;
                let _ = placed.set(task);
                Ok(())
            }
            // the whole task directory moves, everything inside it included
            Placement::Existing(from) => {
                let source = self.store.policy().writeable(from.as_ref())?.dir()?;
                let target = self.store.policy().writeable(at.as_ref())?.dir()?;
                self.store
                    .rename(source.as_ref(), target.as_ref(), Condition::Missing)
                    .await
            }
        }
    }

    async fn claim(&self, dir: &DirPath, what: Placement<'_>) -> Result<TaskPath> {
        for _ in 0..100 {
            let base = self.next_number(dir).await?;
            for number in (base..base + 1000).filter_map(NonZeroU64::new) {
                let path = TaskPath::new(dir, number)?;
                match self.place(&path, what).await {
                    Ok(()) => return Ok(path),
                    Err(NotedError::Conflict) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Err(rejected(format!(
            "could not allocate a task name in '{}'",
            named(dir)
        )))
    }

    pub(super) async fn create(
        &self,
        title: &TaskTitle,
        dir: &DirPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        let placed = OnceLock::new();
        self.claim(dir, Placement::Fresh(title, body, &placed))
            .await?;
        placed
            .into_inner()
            .ok_or_else(|| rejected("could not allocate a task name"))
    }

    pub(super) async fn get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        let exact = match TaskPath::try_from(query.prefix.as_ref().clone()) {
            Ok(task) => self.read(&task).await.ok(),
            Err(_) => None,
        };
        let (paths, hide_closed) = match exact {
            Some(task) => return Ok(vec![task]),
            None => (
                self.store
                    .walk(&query.prefix, None)
                    .await
                    .into_iter()
                    .filter_map(|at| TaskPath::try_from(at).ok())
                    .collect::<Vec<_>>(),
                !query.include_completed,
            ),
        };

        let mut found = Vec::new();
        for path in paths {
            let Ok(task) = self.read(&path).await else {
                continue;
            };
            if hide_closed && task.front().state.is_closed() {
                continue;
            }
            found.push(task);
        }
        found.sort_by_cached_key(|t| (Reverse(t.front().updated_at), t.path().clone()));
        Ok(found)
    }

    pub(super) async fn search(&self, search: &TaskSearch) -> Result<Vec<Hit<TaskPath>>> {
        let hits = self
            .store
            .search(&search.prefix, &search.query)
            .await?
            .into_iter()
            .filter_map(|hit| {
                Some(Hit {
                    path: TaskPath::try_from(hit.path).ok()?,
                    lines: hit.lines,
                })
            })
            .collect();

        let mut ordered = Vec::new();
        for hit in search.query.assemble(hits)? {
            let Ok(task) = self.read(&hit.path).await else {
                continue;
            };
            if !search.include_completed && task.front().state.is_closed() {
                continue;
            }
            ordered.push((Reverse(task.front().updated_at), hit.path.clone(), hit));
        }
        ordered.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        Ok(ordered.into_iter().map(|(_, _, hit)| hit).collect())
    }

    pub(super) async fn update(
        &self,
        reference: &TaskPath,
        change: &TaskChange,
    ) -> Result<TaskNote> {
        let updated = self.existing(reference).await?.changed(change)?;
        let file = self.store.policy().writeable(reference.as_ref())?.file()?;
        self.store
            .write(&file, &updated.to_bytes(), Condition::Always)
            .await?;
        Ok(updated)
    }

    async fn existing(&self, task: &TaskPath) -> Result<TaskNote> {
        self.read(task).await.map_err(|e| match e {
            NotedError::Io { .. } => NotedError::NotFound,
            other => other,
        })
    }

    pub(super) async fn move_(&self, reference: &TaskPath, dest: &DirPath) -> Result<TaskNote> {
        if dest == &reference.as_ref().parent()? {
            return Err(rejected(format!("task already in '{}'", named(dest))));
        }
        // a destination that continues every segment of the task lies inside it
        if dest.as_ref().starts_with(reference.as_ref()) {
            return Err(rejected("cannot move a task into itself"));
        }

        let moved = self.claim(dest, Placement::Existing(reference)).await?;
        self.existing(&moved).await
    }
}
