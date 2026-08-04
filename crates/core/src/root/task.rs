use std::cmp::Reverse;

use crate::error::{NotedError, Result, rejected};
use crate::note::{Condition, Note as _};
use crate::path::{Path, Reserved};
use crate::regions::RegionStore;
use crate::search::{Hit, assemble};
use crate::tasks::{
    AttachmentName, GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskSearch, TaskTitle,
    numbered,
};
use crate::types::{Base64Bytes, TaskBody};

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
            None => "the top of Tasks".to_string(),
        }
    }

    // reads the markdown of either form and lists what sits beside it
    fn read(&self, entry: &Path) -> Result<TaskNote> {
        let reference = TaskRef::of_entry(entry).ok_or_else(|| rejected("not a task"))?;
        let bytes = self
            .region
            .read(&self.region.body_of(entry, Reserved::TaskBody)?)?;
        let task = TaskNote::from_bytes(reference, &bytes).map_err(|_| rejected("not a task"))?;
        Ok(task.with_attachments(self.attachments(entry)))
    }

    fn attachments(&self, entry: &Path) -> Vec<AttachmentName> {
        let mut beside = self.region.files(entry);
        beside.sort();
        beside
            .iter()
            .filter_map(|at| AttachmentName::new(at.file_name()).ok())
            .collect()
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

    fn place(&self, at: &Path, what: Placement<'_>) -> Result<()> {
        match what {
            Placement::Fresh(data) => self.region.write(at, data, Condition::Missing),
            Placement::Existing(from) => self.region.rename(from, at, Condition::Missing),
        }
    }

    fn claim(&self, dir: Option<&Path>, what: Placement<'_>) -> Result<Path> {
        for _ in 0..100 {
            let base = self.next_number(dir);
            for number in base..base + 1000 {
                let path = TaskTools::within(dir, &format!("task_{number:04}.md"))?;
                match self.place(&path, what) {
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
        let path = self.claim(
            group.to_path().as_ref(),
            Placement::Fresh(&draft.to_bytes()),
        )?;
        Ok(draft.with_path(TaskTools::named_by(&path)?))
    }

    fn named_by(entry: &Path) -> Result<TaskRef> {
        TaskRef::of_entry(entry).ok_or_else(|| rejected("not a task"))
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
            let Some(task) = hit.path.to_path().and_then(|p| self.read(&p).ok()) else {
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

    pub(super) fn update(&self, reference: &TaskRef, change: &TaskChange) -> Result<TaskNote> {
        let entry = self.entry_of(reference)?;
        let updated = self.existing(&entry)?.changed(change)?;
        self.region.write(
            &self.region.body_of(&entry, Reserved::TaskBody)?,
            &updated.to_bytes(),
            Condition::Always,
        )?;
        Ok(updated)
    }

    fn existing(&self, entry: &Path) -> Result<TaskNote> {
        self.read(entry).map_err(|e| match e {
            NotedError::Io { .. } => NotedError::NotFound,
            other => other,
        })
    }

    pub(super) fn move_(&self, reference: &TaskRef, group: &GroupPath) -> Result<TaskNote> {
        let entry = self.entry_of(reference)?;
        let relocated = self.existing(&entry)?.restamped();
        let dir = group.to_path();
        if dir == entry.parent() {
            return Err(rejected("task already in that group"));
        }

        let stem = reference.stem();
        let dest = match numbered(stem).is_some() {
            true => self.claim(dir.as_ref(), Placement::Existing(&entry))?,
            false => {
                let dest = TaskTools::within(dir.as_ref(), &format!("{stem}.md"))?;
                self.place(&dest, Placement::Existing(&entry))?;
                dest
            }
        };
        self.region.write(
            &self.region.body_of(&dest, Reserved::TaskBody)?,
            &relocated.to_bytes(),
            Condition::Always,
        )?;
        Ok(relocated.with_path(TaskTools::named_by(&dest)?))
    }

    // the attachment's Tasks-relative path
    pub(super) fn attach(
        &self,
        reference: &TaskRef,
        name: &AttachmentName,
        content: &Base64Bytes,
    ) -> Result<Path> {
        let entry = self.entry_of(reference)?;
        self.existing(&entry)?;
        let file = entry.joined(name.as_str())?;
        self.region
            .attach(&entry, Reserved::TaskBody, &file, content.as_bytes())?;
        Ok(file)
    }
}
