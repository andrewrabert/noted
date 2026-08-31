use std::cmp::Reverse;

use crate::domain::NotePath;
use crate::error::{NotedError, Result, rejected};
use crate::note::{Condition, Note as _};
use crate::regions::RegionStore;
use crate::search::Hit;
use crate::tasks::{
    GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle, numbered,
};
use crate::types::TaskBody;

// how a claimed task name is filled
#[derive(Clone, Copy)]
enum Placement<'a> {
    Fresh(&'a [u8]),
    Existing(&'a NotePath),
}

// the note a task lives in: its reference plus the note suffix
fn entry_of(reference: &TaskRef) -> Result<NotePath> {
    if reference.is_empty() {
        return Err(rejected("task path required"));
    }
    NotePath::new(&format!("/{}.md", reference.as_str()))
}

// the reference a task note carries; refused when the note is not a task entry
fn reference_of(entry: &NotePath) -> Result<TaskRef> {
    let spelled = entry.to_string();
    match spelled
        .strip_prefix('/')
        .and_then(|s| s.strip_suffix(".md"))
    {
        Some(reference) => TaskRef::new(reference),
        None => Err(rejected("not a task")),
    }
}

// the directory a group or a reference prefix names; '' is the top of the region
fn dir_of(raw: &str) -> Result<NotePath> {
    NotePath::new(&format!("/{raw}"))
}

fn within(dir: &NotePath, name: &str) -> Result<NotePath> {
    Ok(dir.join(&NotePath::new(&format!("/{name}"))?))
}

fn named(dir: &NotePath) -> String {
    match dir == &NotePath::default() {
        true => "the top of .tasks".to_string(),
        false => dir.to_string(),
    }
}

pub(super) struct TaskTools {
    region: RegionStore,
}

impl TaskTools {
    pub(super) fn new(region: RegionStore) -> TaskTools {
        TaskTools { region }
    }

    async fn read(&self, entry: &NotePath) -> Result<TaskNote> {
        let reference = reference_of(entry)?;
        let bytes = self.region.read(entry).await?;
        TaskNote::from_bytes(reference, &bytes).map_err(|_| rejected("not a task"))
    }

    async fn next_number(&self, dir: &NotePath) -> u64 {
        self.region
            .children(dir)
            .await
            .iter()
            .filter_map(|p| {
                let name = p.segments().last()?.as_str();
                numbered(name.strip_suffix(".md").unwrap_or(name))
            })
            .max()
            .unwrap_or(0)
            + 1
    }

    async fn place(&self, at: &NotePath, what: Placement<'_>) -> Result<()> {
        match what {
            Placement::Fresh(data) => self.region.write(at, data, Condition::Missing).await,
            Placement::Existing(from) => self.region.rename(from, at, Condition::Missing).await,
        }
    }

    async fn claim(&self, dir: &NotePath, what: Placement<'_>) -> Result<NotePath> {
        for _ in 0..100 {
            let base = self.next_number(dir).await;
            for number in base..base + 1000 {
                let path = within(dir, &format!("task_{number:04}.md"))?;
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
        group: &GroupPath,
        body: &TaskBody,
    ) -> Result<TaskNote> {
        let draft = TaskNote::new(title.clone(), body.clone());
        let dir = dir_of(group.as_str())?;
        let path = self
            .claim(&dir, Placement::Fresh(&draft.to_bytes()))
            .await?;
        Ok(draft.with_path(reference_of(&path)?))
    }

    pub(super) async fn get(&self, query: &TaskQuery) -> Result<Vec<TaskNote>> {
        let exact = match query.prefix.is_empty() {
            true => None,
            false => self.read(&entry_of(&query.prefix)?).await.ok(),
        };
        let (paths, hide_closed) = match exact {
            Some(task) => return Ok(vec![task]),
            None => (
                self.region.walk(&dir_of(query.prefix.as_str())?).await,
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
        let prefix = dir_of(search.prefix.as_str())?;
        for hit in self.region.search(&prefix, &search.query).await? {
            let Ok(reference) = reference_of(&hit.path) else {
                continue;
            };
            hits.push(Hit {
                path: reference,
                lines: hit.lines,
            });
        }

        let mut ordered = Vec::new();
        for hit in search.query.assemble(hits)? {
            let Ok(entry) = entry_of(&hit.path) else {
                continue;
            };
            let Ok(task) = self.read(&entry).await else {
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
        let entry = entry_of(reference)?;
        let updated = self.existing(&entry).await?.changed(change)?;
        self.region
            .write(&entry, &updated.to_bytes(), Condition::Always)
            .await?;
        Ok(updated)
    }

    async fn existing(&self, entry: &NotePath) -> Result<TaskNote> {
        self.read(entry).await.map_err(|e| match e {
            NotedError::Io { .. } => NotedError::NotFound,
            other => other,
        })
    }

    pub(super) async fn move_(&self, reference: &TaskRef, group: &GroupPath) -> Result<TaskNote> {
        let entry = entry_of(reference)?;
        let relocated = self.existing(&entry).await?.restamped();
        if group.as_str() == reference.group() {
            return Err(rejected("task already in that group"));
        }
        let dir = dir_of(group.as_str())?;

        let stem = reference.stem();
        let dest = match numbered(stem).is_some() {
            true => self.claim(&dir, Placement::Existing(&entry)).await?,
            false => {
                let dest = within(&dir, &format!("{stem}.md"))?;
                self.place(&dest, Placement::Existing(&entry)).await?;
                dest
            }
        };
        self.region
            .write(&dest, &relocated.to_bytes(), Condition::Always)
            .await?;
        Ok(relocated.with_path(reference_of(&dest)?))
    }
}
