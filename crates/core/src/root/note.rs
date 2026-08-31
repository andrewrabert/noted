use crate::domain::NotePath;
use crate::error::{NotedError, Result, rejected};
use crate::note::{Condition, Edit, Note as _, TextNote, Trashed};
use crate::regions::RegionStore;
use crate::search::{Hit, SearchQuery};

pub(super) struct NoteTools {
    region: RegionStore,
}

impl NoteTools {
    pub(super) fn new(region: RegionStore) -> NoteTools {
        NoteTools { region }
    }

    pub(super) async fn search(&self, query: &SearchQuery) -> Result<Vec<Hit>> {
        query.assemble(self.region.search(&NotePath::default(), query).await?)
    }

    pub(super) async fn read(&self, path: &NotePath) -> Result<TextNote> {
        let bytes = self.region.read(path).await.map_err(|e| match e {
            NotedError::Io { .. } => NotedError::NotFound,
            other => other,
        })?;
        let text = String::from_utf8(bytes).map_err(|_| rejected("note is not valid utf-8"))?;
        Ok(TextNote::new(path.clone(), text))
    }

    pub(super) async fn write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        self.region
            .write(note.path(), &note.to_bytes(), condition)
            .await
    }

    pub(super) async fn edit(&self, path: &NotePath, edit: &Edit) -> Result<TextNote> {
        let original = self.read(path).await?;
        let revised = original.clone().with_body(edit.apply(original.body())?);
        self.write(&revised, Condition::Matching(original.etag()))
            .await?;
        Ok(revised)
    }

    pub(super) async fn move_(
        &self,
        path: &NotePath,
        dest: &NotePath,
        overwrite: bool,
    ) -> Result<()> {
        if dest == path {
            return Err(rejected("source and destination are the same"));
        }
        // a destination that continues every segment of the source lies inside it
        let mut inner = dest.segments();
        if path.segments().all(|part| inner.next() == Some(part)) {
            return Err(rejected("cannot move a folder into itself"));
        }
        let when = match overwrite {
            true => Condition::Always,
            false => Condition::Missing,
        };
        self.region
            .rename(path, dest, when)
            .await
            .map_err(|e| match e {
                NotedError::Io { .. } => rejected("cannot overwrite non-empty folder"),
                other => other,
            })
    }

    pub(super) async fn delete(&self, path: &NotePath) -> Result<Trashed> {
        self.region.remove(path).await
    }
}
