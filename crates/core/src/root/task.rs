use std::cmp::Reverse;

use crate::error::{NotedError, Result, rejected};
use crate::note::{Condition, Note as _};
use crate::path::Path;
use crate::regions::RegionStore;
use crate::search::{Hit, assemble};
use crate::tasks::{
    GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle, numbered,
};
use crate::types::TaskBody;

pub(super) struct TaskTools {
    region: RegionStore,
}

impl TaskTools {
    pub(super) fn new(region: RegionStore) -> TaskTools {
        TaskTools { region }
    }

    fn file_of(&self, reference: &TaskRef) -> Result<Path> {
        reference
            .to_path()
            .ok_or_else(|| rejected("task path required"))
    }

    fn within(dir: Option<&Path>, name: &str) -> Result<Path> {
        match dir {
            Some(dir) => dir.joined(name),
            None => Path::new(name),
        }
    }

    fn named(dir: Option<&Path>) -> String {
        match dir {
            Some(dir) => dir.to_string(),
            None => "the top of Tasks".to_string(),
        }
    }

    fn read(&self, path: &Path) -> Result<TaskNote> {
        let reference = TaskRef::of_file(path);
        let bytes = self.region.read(path)?;
        TaskNote::from_bytes(reference, &bytes).map_err(|_| rejected("not a task"))
    }

    fn next_number(&self, dir: Option<&Path>) -> u64 {
        self.region
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

    fn claim(&self, dir: Option<&Path>, data: &[u8]) -> Result<Path> {
        for _ in 0..100 {
            let base = self.next_number(dir);
            for number in base..base + 1000 {
                let path = TaskTools::within(dir, &format!("task_{number:04}.md"))?;
                match self.region.write(&path, data, Condition::Missing) {
                    Ok(()) => return Ok(path),
                    Err(NotedError::Conflict) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Err(rejected(format!(
            "could not allocate a task name in '{}'",
            TaskTools::named(dir)
        )))
    }

    pub(super) fn create(
        &self,
        title: &TaskTitle,
        group: &GroupPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        let draft = TaskNote::new(title.clone(), body.clone());
        let path = self.claim(group.to_path().as_ref(), &draft.to_bytes()?)?;
        Ok(draft.with_path(TaskRef::of_file(&path)))
    }

    pub(super) fn get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        let exact = query
            .prefix
            .to_path()
            .and_then(|path| self.read(&path).ok());
        let (paths, hide_closed) = match exact {
            Some(task) => return Ok(vec![task]),
            None => (
                self.region.walk(query.prefix.to_dir().as_ref()),
                !query.include_completed,
            ),
        };

        let mut found = Vec::new();
        for path in paths {
            let Ok(task) = self.read(&path) else {
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
        let hits: Vec<Hit<TaskRef>> = self
            .region
            .search(search.prefix.to_path().as_ref(), &search.query)
            .await?
            .into_iter()
            .map(|hit| Hit {
                path: TaskRef::of_file(&hit.path),
                lines: hit.lines,
            })
            .collect();

        let mut ordered = Vec::new();
        for hit in assemble(&search.query, hits)? {
            let Some(task) = hit.path.to_path().and_then(|p| self.read(&p).ok()) else {
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

    pub(super) fn update(&self, reference: &TaskRef, change: &TaskChange) -> Result<TaskNote> {
        let path = self.file_of(reference)?;
        let updated = self
            .read(&path)
            .map_err(|e| match e {
                NotedError::Io { .. } => NotedError::NotFound,
                other => other,
            })?
            .changed(change)?;
        self.region
            .write(&path, &updated.to_bytes()?, Condition::Always)?;
        Ok(updated)
    }

    pub(super) fn move_(&self, reference: &TaskRef, group: &GroupPath) -> Result<TaskNote> {
        let src = self.file_of(reference)?;
        let relocated = self
            .read(&src)
            .map_err(|e| match e {
                NotedError::Io { .. } => NotedError::NotFound,
                other => other,
            })?
            .restamped();
        let dir = group.to_path();
        if dir == src.parent() {
            return Err(rejected("task already in that group"));
        }

        let bytes = relocated.to_bytes()?;
        let stem = reference.stem();
        let dest = match numbered(stem).is_some() {
            true => self.claim(dir.as_ref(), &bytes)?,
            false => {
                let dest = TaskTools::within(dir.as_ref(), &format!("{stem}.md"))?;
                match self.region.write(&dest, &bytes, Condition::Missing) {
                    Ok(()) => dest,
                    Err(e) => return Err(e),
                }
            }
        };
        self.region.remove(&src)?;
        Ok(relocated.with_path(TaskRef::of_file(&dest)))
    }
}
