use std::collections::BTreeSet;

use crate::domain::{DirPath, NotePath, Path};
use crate::error::Result;
use crate::fragment::PolicyFragment;
use crate::note::Condition;
use crate::policy::{Policy, ReadableFile, WriteableFile, WriteablePath};
use crate::search::{Hit, SearchQuery};
use crate::store::{NotedDir, Store};

// `entry` is measured from `dir`'s store directory and starts with a
// separator; the whole store path is read back at once so an entry under a
// task or log directory keeps its prefix
fn under(dir: &DirPath, entry: &str) -> Result<NotePath> {
    let base: String = dir
        .as_ref()
        .to_store_dir()?
        .iter()
        .map(|part| format!("{}{part}", Path::SEPARATOR))
        .collect();
    NotePath::from_store(&format!("{base}{entry}"))
}

/// The store as one holder sees it: every name that comes in is minted
/// against the policy before the store sees it, and every name that goes out
/// is one the policy would mint.
#[derive(Clone)]
pub(crate) struct PolicyStore {
    store: Store,
    policy: Policy,
}

impl PolicyStore {
    pub(crate) fn open(dir: NotedDir) -> Result<PolicyStore> {
        Ok(PolicyStore {
            store: Store::open(dir)?,
            policy: Policy::new(),
        })
    }

    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }

    pub(crate) fn with_policy_fragment(&self, fragment: &PolicyFragment) -> Result<PolicyStore> {
        Ok(PolicyStore {
            store: self.store.clone(),
            policy: self.policy.with_policy_fragment(fragment)?,
        })
    }

    pub(crate) async fn read(&self, at: &ReadableFile) -> Result<Vec<u8>> {
        self.store.read(at).await
    }

    pub(crate) async fn write(
        &self,
        at: &WriteableFile,
        data: &[u8],
        when: Condition,
    ) -> Result<()> {
        self.store.write(at, data, when).await
    }

    pub(crate) async fn rename(
        &self,
        from: &WriteablePath,
        to: &WriteablePath,
        when: Condition,
    ) -> Result<()> {
        self.store.rename(from, to, when).await
    }

    pub(crate) async fn remove(&self, at: &WriteablePath) -> Result<()> {
        self.store.remove(at).await
    }

    // every listing is rooted at the scope; `dir` is where inside it to start,
    // and what comes back is spelled from the scope, as the caller names notes
    pub(crate) async fn walk(&self, dir: &DirPath, max_depth: Option<usize>) -> Vec<NotePath> {
        let Ok(start) = self.policy.readable(dir.as_ref()).and_then(|at| at.dir()) else {
            return Vec::new();
        };
        let found = self.store.walk(&start, max_depth).await;
        self.named(dir, found)
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    // each entry read back as one store path under `dir`, kept when readable
    fn named(&self, dir: &DirPath, found: Vec<String>) -> Vec<NotePath> {
        found
            .iter()
            .filter_map(|entry| under(dir, entry).ok())
            .filter(|rel| self.policy.readable(rel).is_ok())
            .collect()
    }

    // a starting directory the policy denies outright is refused, not silently empty
    pub(crate) async fn search(
        &self,
        dir: &DirPath,
        query: &SearchQuery,
    ) -> Result<Vec<Hit<NotePath>>> {
        let start = self.policy.readable(dir.as_ref())?.dir()?;
        let found = self.store.search(&start, query).await?;
        let mut hits = Vec::new();
        for raw in found {
            let Ok(rel) = under(dir, &raw.path) else {
                continue;
            };
            let Ok(_) = self.policy.readable(&rel) else {
                continue;
            };
            hits.push(Hit {
                path: rel,
                lines: raw.lines,
            });
        }
        Ok(hits)
    }
}
