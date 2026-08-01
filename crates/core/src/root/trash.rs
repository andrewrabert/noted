use crate::areas::Areas;
use crate::error::{Result, io_error};
use crate::note::Trashed;
use crate::path::RelPath;
use crate::store::Store;

#[derive(Clone)]
pub(super) struct Trash {
    store: Store,
    areas: Areas,
}

impl Trash {
    pub(super) fn new(store: Store, areas: Areas) -> Trash {
        Trash { store, areas }
    }

    pub(super) fn accept(&self, path: &RelPath) -> Result<Trashed> {
        let target = self.store.unique(&self.areas.trash.join(path), " ");
        self.store
            .rename(path, &target)
            .map_err(|e| io_error("delete failed", e))?;
        Ok(Trashed::new(target))
    }
}
