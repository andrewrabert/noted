use crate::domain::{NotePath, Region};
use crate::error::{NotedError, Result};
use crate::fragment::PolicyFragment;
use crate::note::{Condition, Trashed};
use crate::policy::RegionPolicy;
use crate::search::{Hit, SearchQuery};
use crate::store::{NotedDir, Store};

/// One region as one holder sees it: every name that comes in is minted
/// against the policy before the store sees it, and every name that goes out
/// is one the policy would mint.
#[derive(Clone)]
pub(crate) struct RegionStore {
    region: Region,
    store: Store,
    policy: RegionPolicy,
}

impl RegionStore {
    fn new(region: Region, store: Store) -> RegionStore {
        RegionStore {
            region,
            store,
            policy: RegionPolicy::new(region),
        }
    }

    pub(crate) fn policy(&self) -> &RegionPolicy {
        &self.policy
    }

    fn with_policy_fragment(&self, fragment: &PolicyFragment) -> Result<RegionStore> {
        Ok(RegionStore {
            region: self.region,
            store: self.store.clone(),
            policy: self.policy.with_policy_fragment(fragment)?,
        })
    }

    pub(crate) async fn read(&self, rel: &NotePath) -> Result<Vec<u8>> {
        self.store.read(&self.policy.readable(rel)?).await
    }

    pub(crate) async fn write(&self, rel: &NotePath, data: &[u8], when: Condition) -> Result<()> {
        self.store
            .write(&self.policy.writeable(rel)?, data, when)
            .await
    }

    pub(crate) async fn rename(
        &self,
        from: &NotePath,
        to: &NotePath,
        when: Condition,
    ) -> Result<()> {
        self.store
            .rename(
                &self.policy.writeable(from)?,
                &self.policy.writeable(to)?,
                when,
            )
            .await
    }

    pub(crate) async fn remove(&self, rel: &NotePath) -> Result<Trashed> {
        self.store.remove(&self.policy.writeable(rel)?).await?;
        Ok(Trashed::new(rel.clone()))
    }

    // every listing is rooted at the scope; `dir` is where inside it to start,
    // and what comes back is spelled from the scope, as the caller names notes
    pub(crate) async fn walk(&self, dir: &NotePath) -> Vec<NotePath> {
        let found = self
            .store
            .walk(self.region, &self.policy.scope().join(dir))
            .await;
        self.admitted(dir, found)
    }

    pub(crate) async fn children(&self, dir: &NotePath) -> Vec<NotePath> {
        let found = self
            .store
            .children(self.region, &self.policy.scope().join(dir))
            .await;
        self.admitted(dir, found)
    }

    fn admitted(&self, dir: &NotePath, found: Vec<NotePath>) -> Vec<NotePath> {
        let mut out = Vec::new();
        for at in found {
            let rel = dir.join(&at);
            let Ok(_) = self.policy.readable(&rel) else {
                continue;
            };
            out.push(rel);
        }
        out
    }

    // a starting directory the policy denies outright is refused, not silently empty
    pub(crate) async fn search(&self, dir: &NotePath, query: &SearchQuery) -> Result<Vec<Hit>> {
        match dir.segments().next() {
            Some(_) => {
                self.policy.readable(dir)?;
            }
            None if !self.policy.access().read => return Err(NotedError::Forbidden),
            None => {}
        }
        let found = self
            .store
            .search(self.region, &self.policy.scope().join(dir), query)
            .await?;
        let mut hits = Vec::new();
        for raw in found {
            let rel = dir.join(&raw.path);
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

#[derive(Clone)]
pub(crate) struct Regions {
    pub(crate) notes: RegionStore,
    pub(crate) log: RegionStore,
    pub(crate) tasks: RegionStore,
}

impl Regions {
    pub(crate) fn open(dir: NotedDir) -> Result<Regions> {
        let store = Store::open(dir)?;
        Ok(Regions {
            notes: RegionStore::new(Region::Notes, store.clone()),
            log: RegionStore::new(Region::Log, store.clone()),
            tasks: RegionStore::new(Region::Tasks, store),
        })
    }

    pub(crate) fn with_policy_fragment(&self, fragment: &PolicyFragment) -> Result<Regions> {
        Ok(Regions {
            notes: self.notes.with_policy_fragment(fragment)?,
            log: self.log.with_policy_fragment(fragment)?,
            tasks: self.tasks.with_policy_fragment(fragment)?,
        })
    }
}
