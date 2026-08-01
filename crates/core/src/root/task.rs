use std::cmp::Reverse;

use crate::areas::Areas;
use crate::caller::Caller;
use crate::error::{Result, forbidden, io_error, not_found, rejected};
use crate::note::Note as _;
use crate::path::RelPath;
use crate::search::{Hit, assemble};
use crate::store::{Store, Sweep};
use crate::tasks::{
    GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle, numbered,
};
use crate::types::TaskBody;

use super::find::Find;

#[derive(Clone)]
pub(super) struct Task {
    store: Store,
    areas: Areas,
    caller: Caller,
    find: Find,
}

impl Task {
    pub(super) fn new(store: Store, areas: Areas, caller: Caller, find: Find) -> Task {
        Task {
            store,
            areas,
            caller,
            find,
        }
    }

    fn reachable(&self, path: &RelPath, shown: &str) -> Result<()> {
        if self.store.is_ignored(path) {
            return Err(rejected(format!("invalid path: '{shown}'")));
        }
        if !self.caller.admits(path) {
            return Err(forbidden(format!(
                "task path outside allowed folders: '{shown}'"
            )));
        }
        Ok(())
    }

    fn group_dir(&self, group: &GroupPath) -> Result<RelPath> {
        let dir = group.to_rel(&self.areas.tasks);
        self.reachable(&dir, group.as_str())?;
        Ok(dir)
    }

    fn searchable(&self, group: &GroupPath) -> Result<RelPath> {
        let dir = group.to_rel(&self.areas.tasks);
        if self.store.is_ignored(&dir) {
            return Err(rejected(format!("invalid path: '{group}'")));
        }
        if !self.caller.reaches(&dir) {
            return Err(forbidden(format!(
                "task path outside allowed folders: '{group}'"
            )));
        }
        Ok(dir)
    }

    fn file_of(&self, reference: &TaskRef) -> Result<RelPath> {
        if reference.is_empty() {
            return Err(rejected("task path required"));
        }
        let path = reference.to_rel(&self.areas.tasks);
        self.reachable(&path, reference.as_str())?;
        Ok(path)
    }

    fn reference(&self, path: &RelPath) -> TaskRef {
        TaskRef::of_file(path, &self.areas.tasks)
    }

    fn real_file(&self, path: &RelPath) -> bool {
        self.store.is_file(path) && !self.store.has_symlink(path)
    }

    fn read(&self, path: &RelPath) -> Result<TaskNote> {
        let reference = self.reference(path);
        let bytes = self
            .store
            .read(path)
            .map_err(|e| io_error("read failed", e))?;
        TaskNote::from_bytes(reference.clone(), &bytes)
            .map_err(|_| rejected(format!("not a task: '{reference}'")))
    }

    fn next_number(&self, dir: &RelPath) -> u64 {
        self.store
            .children(dir)
            .iter()
            .filter_map(|p| {
                let name = p.file_name();
                numbered(name.strip_suffix(".md").unwrap_or(name))
            })
            .max()
            .unwrap_or(0)
            + 1
    }

    fn claim(&self, dir: &RelPath, data: &[u8]) -> Result<RelPath> {
        for _ in 0..100 {
            let base = self.next_number(dir);
            for number in base..base + 1000 {
                let path = dir.joined(&format!("task_{number:04}.md"));
                match self.store.create(&path, data) {
                    Ok(()) => return Ok(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(io_error("write failed", e)),
                }
            }
        }
        Err(rejected(format!(
            "could not allocate a task name in '{dir}'"
        )))
    }

    pub(super) fn create(
        &self,
        title: &TaskTitle,
        group: &GroupPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        let dir = self.group_dir(group)?;
        let draft = TaskNote::new(title.clone(), body.clone());
        let path = self.claim(&dir, &draft.to_bytes()?)?;
        Ok(draft.with_path(self.reference(&path)))
    }

    pub(super) fn get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        let exact = match query.prefix.is_empty() {
            true => None,
            false => Some(self.file_of(&query.prefix)?),
        };
        let (paths, hide_closed) = match exact {
            Some(path) if self.real_file(&path) => (vec![path], false),
            _ => (self.group_files(&query.prefix)?, !query.include_completed),
        };

        let mut found = Vec::new();
        for path in paths {
            if !self.caller.admits(&path) {
                continue;
            }
            let Ok(bytes) = self.store.read(&path) else {
                continue;
            };
            let Ok(task) = TaskNote::from_bytes(self.reference(&path), &bytes) else {
                continue;
            };
            if hide_closed && task.front().state.is_closed() {
                continue;
            }
            found.push(task);
        }
        found.sort_by_cached_key(|t| {
            (
                Reverse(t.front().updated_at.parse_rfc3339()),
                t.path().clone(),
            )
        });
        Ok(found)
    }

    pub(super) async fn search(&self, search: &TaskSearch) -> Result<Vec<Hit<TaskRef>>> {
        let dir = self.searchable(&search.prefix)?;
        let sweep = Sweep::new(dir, &search.query);
        let hits: Vec<Hit<TaskRef>> = self
            .find
            .content(&sweep)
            .await?
            .into_iter()
            .map(|hit| Hit {
                path: self.reference(&hit.path),
                lines: hit.lines,
            })
            .collect();
        let walked: Vec<TaskRef> = self
            .find
            .paths(&sweep)
            .await?
            .iter()
            .map(|path| self.reference(path))
            .collect();

        let mut ordered = Vec::new();
        for hit in assemble(&search.query, hits, walked)? {
            let path = hit.path.to_rel(&self.areas.tasks);
            if !self.real_file(&path) {
                continue;
            }
            let Ok(task) = self.read(&path) else {
                continue;
            };
            if !search.include_completed && task.front().state.is_closed() {
                continue;
            }
            ordered.push((
                Reverse(task.front().updated_at.parse_rfc3339()),
                hit.path.clone(),
                hit,
            ));
        }
        ordered.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        Ok(ordered.into_iter().map(|(_, _, hit)| hit).collect())
    }

    fn group_files(&self, prefix: &TaskRef) -> Result<Vec<RelPath>> {
        let dir = self.areas.tasks.joined(prefix.as_str());
        if self.store.is_ignored(&dir) {
            return Err(rejected(format!("invalid path: '{prefix}'")));
        }
        if !self.store.is_dir(&dir) || self.store.has_symlink(&dir) {
            return Ok(Vec::new());
        }
        Ok(self.store.walk(&dir))
    }

    pub(super) fn update(&self, reference: &TaskRef, change: &TaskChange) -> Result<TaskNote> {
        let path = self.file_of(reference)?;
        if !self.real_file(&path) {
            return Err(not_found(format!("no task at '{reference}'")));
        }
        let updated = self.read(&path)?.changed(change)?;
        self.store.write(&path, &updated.to_bytes()?)?;
        Ok(updated)
    }

    pub(super) fn move_(&self, reference: &TaskRef, group: &GroupPath) -> Result<TaskNote> {
        let src = self.file_of(reference)?;
        if !self.real_file(&src) {
            return Err(not_found(format!("no task at '{reference}'")));
        }
        let dir = self.group_dir(group)?;
        if dir == src.parent() {
            return Err(rejected("task already in that group"));
        }

        let relocated = self.read(&src)?.restamped();
        let bytes = relocated.to_bytes()?;
        let stem = reference.stem();
        let dest = if numbered(stem).is_some() {
            self.claim(&dir, &bytes)?
        } else {
            let dest = dir.joined(&format!("{stem}.md"));
            match self.store.create(&dest, &bytes) {
                Ok(()) => dest,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(rejected(format!(
                        "destination exists: '{}'",
                        self.reference(&dest)
                    )));
                }
                Err(e) => return Err(io_error("write failed", e)),
            }
        };
        self.store
            .remove(&src)
            .map_err(|e| io_error("move failed", e))?;
        Ok(relocated.with_path(self.reference(&dest)))
    }
}
