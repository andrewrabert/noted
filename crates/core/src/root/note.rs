use crate::areas::Areas;
use crate::caller::Caller;
use crate::error::{Result, conflict, forbidden, io_error, not_found, rejected};
use crate::note::{Condition, Edit, Etag, Note as _, TextNote, Trashed};
use crate::path::RelPath;
use crate::store::Store;

use super::trash::Trash;

#[derive(Clone)]
pub(super) struct Note {
    store: Store,
    areas: Areas,
    caller: Caller,
    trash: Trash,
}

impl Note {
    pub(super) fn new(store: Store, areas: Areas, caller: Caller, trash: Trash) -> Note {
        Note {
            store,
            areas,
            caller,
            trash,
        }
    }

    fn addressable(&self, path: &RelPath) -> Result<()> {
        if path.is_empty() {
            return Err(rejected("path required"));
        }
        if self.store.is_ignored(path) {
            return Err(rejected(format!("invalid path: '{path}'")));
        }
        if !self.caller.admits(path) {
            return Err(forbidden(format!("path outside allowed folders: '{path}'")));
        }
        Ok(())
    }

    fn open_region(&self, path: &RelPath, on_task: impl FnOnce() -> String) -> Result<()> {
        self.addressable(path)?;
        if path.under(&self.areas.log) {
            return Err(rejected(format!("log entries are immutable: '{path}'")));
        }
        if path.under(&self.areas.tasks) {
            return Err(rejected(on_task()));
        }
        Ok(())
    }

    pub(super) fn read(&self, path: &RelPath) -> Result<TextNote> {
        self.addressable(path)?;
        if !self.store.is_file(path) {
            return Err(not_found(format!("no note at '{path}'")));
        }
        let bytes = self
            .store
            .read(path)
            .map_err(|e| io_error(format!("no note at '{path}'"), e))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| rejected(format!("note is not valid utf-8: '{path}'")))?;
        Ok(TextNote::new(path.clone(), text))
    }

    pub(super) fn write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        let path = note.path();
        self.open_region(path, || {
            format!("tasks are managed: '{path}' (use CreateTask/UpdateTask/MoveTask)")
        })?;
        let bytes = note.to_bytes()?;
        if matches!(condition, Condition::Missing) {
            return self.store.create(path, &bytes).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    conflict(format!("note already exists: '{path}'"))
                } else {
                    io_error(format!("cannot write note: '{path}'"), e)
                }
            });
        }
        self.store.swap(path, &bytes, |current| match &condition {
            Condition::Always => Ok(()),
            Condition::Missing => unreachable!("handled by the no-clobber create above"),
            Condition::Exists if current.is_none() => Err(conflict(format!("no note at '{path}'"))),
            Condition::Exists => Ok(()),
            Condition::Matching(token) => match current {
                Some(bytes) if &Etag::of(bytes) == token => Ok(()),
                Some(_) => Err(conflict(format!(
                    "note changed since it was read: '{path}'"
                ))),
                None => Err(conflict(format!("no note at '{path}'"))),
            },
        })
    }

    pub(super) fn edit(&self, path: &RelPath, edit: &Edit) -> Result<TextNote> {
        let original = self.read(path)?;
        let revised = original.clone().with_body(edit.apply(original.body())?);
        self.write(&revised, Condition::Matching(original.etag()))?;
        Ok(revised)
    }

    pub(super) fn move_(&self, path: &RelPath, dest: &RelPath, overwrite: bool) -> Result<()> {
        self.open_region(path, || format!("tasks cannot be moved: '{path}'"))?;
        self.open_region(dest, || format!("tasks cannot be moved: '{dest}'"))?;
        if !self.store.exists(path) {
            return Err(not_found(format!("no note or folder at '{path}'")));
        }
        if dest == path {
            return Err(rejected("source and destination are the same"));
        }
        if dest.under(path) {
            return Err(rejected(format!(
                "cannot move a folder into itself: '{path}'"
            )));
        }
        if self.store.exists(dest) && !overwrite {
            return Err(rejected(format!(
                "destination exists: '{dest}' (pass overwrite)"
            )));
        }
        self.store
            .rename(path, dest)
            .map_err(|e| io_error(format!("cannot overwrite non-empty folder: '{dest}'"), e))
    }

    pub(super) fn delete(&self, path: &RelPath) -> Result<Trashed> {
        self.open_region(path, || format!("tasks cannot be deleted: '{path}'"))?;
        if !self.store.is_file(path) {
            return Err(not_found(format!("no note at '{path}'")));
        }
        self.trash.accept(path)
    }
}
