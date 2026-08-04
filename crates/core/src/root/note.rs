use crate::error::{NotedError, Result, rejected};
use crate::note::{Condition, Edit, Note as _, TextNote, Trashed};
use crate::path::Path;
use crate::regions::RegionStore;
use crate::search::{Hit, SearchQuery, assemble};

pub(super) struct NoteTools {
    region: RegionStore,
}

impl NoteTools {
    pub(super) fn new(region: RegionStore) -> NoteTools {
        NoteTools { region }
    }

    pub(super) async fn search(&self, query: &SearchQuery) -> Result<Vec<Hit>> {
        let hits = self.region.search(None, query).await?;
        let mut hits = assemble(query, hits)?;
        hits.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(hits)
    }

    pub(super) fn read(&self, path: &Path) -> Result<TextNote> {
        let bytes = self.region.read(path).map_err(|e| match e {
            NotedError::Io { .. } => NotedError::NotFound,
            other => other,
        })?;
        let text = String::from_utf8(bytes).map_err(|_| rejected("note is not valid utf-8"))?;
        Ok(TextNote::new(path.clone(), text))
    }

    pub(super) fn write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        self.region.write(note.path(), &note.to_bytes()?, condition)
    }

    pub(super) fn edit(&self, path: &Path, edit: &Edit) -> Result<TextNote> {
        let original = self.read(path)?;
        let revised = original.clone().with_body(edit.apply(original.body())?);
        self.write(&revised, Condition::Matching(original.etag()))?;
        Ok(revised)
    }

    pub(super) fn move_(&self, path: &Path, dest: &Path, overwrite: bool) -> Result<()> {
        if dest == path {
            return Err(rejected("source and destination are the same"));
        }
        if dest.under(path) {
            return Err(rejected("cannot move a folder into itself"));
        }
        let when = match overwrite {
            true => Condition::Always,
            false => Condition::Missing,
        };
        self.region.rename(path, dest, when).map_err(|e| match e {
            NotedError::Io { .. } => rejected("cannot overwrite non-empty folder"),
            other => other,
        })
    }

    pub(super) fn delete(&self, path: &Path) -> Result<Trashed> {
        self.region.remove(path)
    }
}
