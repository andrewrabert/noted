use crate::caller::Caller;
use crate::error::Result;
use crate::path::RelPath;
use crate::search::{Hit, SearchMode};
use crate::store::{Store, Sweep};

#[derive(Clone)]
pub(super) struct Find {
    store: Store,
    caller: Caller,
}

impl Find {
    pub(super) fn new(store: Store, caller: Caller) -> Find {
        Find { store, caller }
    }

    pub(super) async fn content(&self, sweep: &Sweep) -> Result<Vec<Hit>> {
        if matches!(sweep.query().mode, SearchMode::Path) {
            return Ok(Vec::new());
        }
        Ok(self
            .store
            .grep(sweep)
            .await?
            .into_iter()
            .filter(|hit| self.caller.admits(&hit.path))
            .collect())
    }

    pub(super) async fn paths(&self, sweep: &Sweep) -> Result<Vec<RelPath>> {
        if !matches!(sweep.query().mode, SearchMode::Any | SearchMode::Path) {
            return Ok(Vec::new());
        }
        Ok(self
            .store
            .walk_search(sweep)
            .await?
            .into_iter()
            .filter(|path| self.caller.admits(path))
            .collect())
    }
}
