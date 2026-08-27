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

// how a claimed task name is filled
#[derive(Clone, Copy)]
enum Placement<'a> {
    Fresh(&'a [u8]),
    Existing(&'a Path),
}

pub(super) struct TaskTools {
    region: RegionStore,
}

impl TaskTools {
    pub(super) fn new(region: RegionStore) -> TaskTools {
        TaskTools { region }
    }

    fn entry_of(&self, reference: &TaskRef) -> Result<Path> {
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
            None => "the top of .tasks".to_string(),
        }
    }

    async fn read(&self, entry: &Path) -> Result<TaskNote> {
        let reference = TaskRef::of_entry(entry).ok_or_else(|| rejected("not a task"))?;
        let bytes = self.region.read(entry).await?;
        TaskNote::from_bytes(reference, &bytes).map_err(|_| rejected("not a task"))
    }

    async fn next_number(&self, dir: Option<&Path>) -> u64 {
        self.region
            .children(dir)
            .await
            .iter()
            .filter_map(|p| {
                let name = p.file_name();
                numbered(name.strip_suffix(".md").unwrap_or(name))
            })
            .max()
            .unwrap_or(0)
            + 1
    }

    async fn place(&self, at: &Path, what: Placement<'_>) -> Result<()> {
        match what {
            Placement::Fresh(data) => self.region.write(at, data, Condition::Missing).await,
            Placement::Existing(from) => self.region.rename(from, at, Condition::Missing).await,
        }
    }

    async fn claim(&self, dir: Option<&Path>, what: Placement<'_>) -> Result<Path> {
        for _ in 0..100 {
            let base = self.next_number(dir).await;
            for number in base..base + 1000 {
                let path = TaskTools::within(dir, &format!("task_{number:04}.md"))?;
                match self.place(&path, what).await {
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

    pub(super) async fn create(
        &self,
        title: &TaskTitle,
        group: &GroupPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        let draft = TaskNote::new(title.clone(), body.clone());
        let path = self
            .claim(
                group.to_path().as_ref(),
                Placement::Fresh(&draft.to_bytes()),
            )
            .await?;
        Ok(draft.with_path(TaskTools::named_by(&path)?))
    }

    fn named_by(entry: &Path) -> Result<TaskRef> {
        TaskRef::of_entry(entry).ok_or_else(|| rejected("not a task"))
    }

    pub(super) async fn get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        let exact = match query.prefix.to_path() {
            Some(path) => self.read(&path).await.ok(),
            None => None,
        };
        let (paths, hide_closed) = match exact {
            Some(task) => return Ok(vec![task]),
            None => (
                self.region.walk(query.prefix.to_dir().as_ref()).await,
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

    pub(super) async fn search(&self, search: &TaskSearch) -> Result<Vec<Hit<TaskRef>>> {
        let mut hits: Vec<Hit<TaskRef>> = Vec::new();
        for hit in self
            .region
            .search(search.prefix.to_path().as_ref(), &search.query)
            .await?
        {
            let Some(reference) = TaskRef::of_entry(&hit.path) else {
                continue;
            };
            hits.push(Hit {
                path: reference,
                lines: hit.lines,
            });
        }

        let mut ordered = Vec::new();
        for hit in assemble(&search.query, hits)? {
            let task = match hit.path.to_path() {
                Some(p) => self.read(&p).await.ok(),
                None => None,
            };
            let Some(task) = task else {
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
        reference: &TaskRef,
        change: &TaskChange,
    ) -> Result<TaskNote> {
        let entry = self.entry_of(reference)?;
        let updated = self.existing(&entry).await?.changed(change)?;
        self.region
            .write(&entry, &updated.to_bytes(), Condition::Always)
            .await?;
        Ok(updated)
    }

    async fn existing(&self, entry: &Path) -> Result<TaskNote> {
        self.read(entry).await.map_err(|e| match e {
            NotedError::Io { .. } => NotedError::NotFound,
            other => other,
        })
    }

    pub(super) async fn move_(&self, reference: &TaskRef, group: &GroupPath) -> Result<TaskNote> {
        let entry = self.entry_of(reference)?;
        let relocated = self.existing(&entry).await?.restamped();
        let dir = group.to_path();
        if dir == entry.parent() {
            return Err(rejected("task already in that group"));
        }

        let stem = reference.stem();
        let dest = match numbered(stem).is_some() {
            true => {
                self.claim(dir.as_ref(), Placement::Existing(&entry))
                    .await?
            }
            false => {
                let dest = TaskTools::within(dir.as_ref(), &format!("{stem}.md"))?;
                self.place(&dest, Placement::Existing(&entry)).await?;
                dest
            }
        };
        self.region
            .write(&dest, &relocated.to_bytes(), Condition::Always)
            .await?;
        Ok(relocated.with_path(TaskTools::named_by(&dest)?))
    }
}
