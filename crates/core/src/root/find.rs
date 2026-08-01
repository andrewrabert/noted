use std::collections::HashSet;

use crate::caller::Caller;
use crate::error::Result;
use crate::path::RelPath;
use crate::search::{Hit, SearchMode, SearchQuery, match_paths};
use crate::store::Store;

#[derive(Clone)]
pub(super) struct Find {
    store: Store,
    caller: Caller,
}

impl Find {
    pub(super) fn new(store: Store, caller: Caller) -> Find {
        Find { store, caller }
    }

    pub(super) async fn search(&self, query: &SearchQuery) -> Result<Vec<Hit>> {
        let mut hits: Vec<Hit> = match query.mode {
            SearchMode::Path => Vec::new(),
            _ => self.store.grep(query).await?,
        };
        hits.retain(|hit| self.caller.admits(&hit.path));

        if matches!(query.mode, SearchMode::Any | SearchMode::Path) {
            let seen: HashSet<RelPath> = hits.iter().map(|hit| hit.path.clone()).collect();
            let walked: Vec<RelPath> = self
                .store
                .walk_search(query)
                .await?
                .into_iter()
                .filter(|path| self.caller.admits(path))
                .collect();
            for path in match_paths(query, walked)? {
                if !seen.contains(&path) {
                    hits.push(Hit {
                        path,
                        lines: Default::default(),
                    });
                }
            }
        }

        hits.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(hits)
    }
}
