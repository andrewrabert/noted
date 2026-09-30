use crate::domain::{DirPath, TextPath};
use crate::error::{NotedError, Result, rejected};
use crate::note::{Condition, Edit, Note as _, TextNote, Trashed};
use crate::policy_store::PolicyStore;
use crate::search::{Hit, SearchQuery};

pub(super) struct NoteTools {
    store: PolicyStore,
}

impl NoteTools {
    pub(super) fn new(store: PolicyStore) -> NoteTools {
        NoteTools { store }
    }

    // notes kept inside tasks and entries are searched; the task and entry
    // records are not
    pub(super) async fn search(&self, query: &SearchQuery) -> Result<Vec<Hit<TextPath>>> {
        let hits = self
            .store
            .search(&DirPath::default(), query)
            .await?
            .into_iter()
            .filter_map(|hit| {
                Some(Hit {
                    path: TextPath::try_from(hit.path).ok()?,
                    lines: hit.lines,
                })
            })
            .collect();
        query.assemble(hits)
    }

    pub(super) async fn read(&self, path: &TextPath) -> Result<TextNote> {
        let at = self.store.policy().readable(path.as_ref())?.file()?;
        let bytes = self.store.read(&at).await.map_err(|e| match e {
            NotedError::Io { .. } => NotedError::NotFound,
            other => other,
        })?;
        let text = String::from_utf8(bytes).map_err(|_| rejected("note is not valid utf-8"))?;
        Ok(TextNote::new(path.clone(), text))
    }

    pub(super) async fn write(&self, note: &TextNote, condition: Condition) -> Result<()> {
        let at = self
            .store
            .policy()
            .writeable(note.path().as_ref())?
            .file()?;
        self.store.write(&at, &note.to_bytes(), condition).await
    }

    pub(super) async fn edit(&self, path: &TextPath, edit: &Edit) -> Result<TextNote> {
        let original = self.read(path).await?;
        let revised = original.clone().with_body(edit.apply(original.body())?);
        self.write(&revised, Condition::Matching(original.etag()))
            .await?;
        Ok(revised)
    }

    pub(super) async fn move_(
        &self,
        path: &TextPath,
        dest: &TextPath,
        overwrite: bool,
    ) -> Result<()> {
        if dest == path {
            return Err(rejected("source and destination are the same"));
        }
        let when = match overwrite {
            true => Condition::Always,
            false => Condition::Missing,
        };
        let from = self.store.policy().writeable(path.as_ref())?;
        let to = self.store.policy().writeable(dest.as_ref())?;
        self.store
            .rename(from.file()?.as_ref(), to.file()?.as_ref(), when)
            .await
            .map_err(|e| match e {
                NotedError::Io { .. } => rejected("cannot overwrite non-empty folder"),
                other => other,
            })?;
        Ok(())
    }

    // the note file alone
    pub(super) async fn delete(&self, path: &TextPath) -> Result<Trashed> {
        let at = path.as_ref();
        let allowed = self.store.policy().writeable(at)?;
        self.store.remove(allowed.file()?.as_ref()).await?;
        Ok(Trashed::new(at.clone()))
    }
}
