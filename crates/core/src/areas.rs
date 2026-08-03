use crate::error::{NotedError, Result};
use crate::note::{Condition, Trashed};
use crate::path::Path;
use crate::policy::{Policy, ReadableFile, WriteableFile};
use crate::search::{Hit, SearchQuery};
use crate::store::{NotedDir, Region, Store};

const LOG: &str = "Log";
const TASKS: &str = "Tasks";

pub(crate) const ROOT_PROBE: &str = "_";

#[derive(Clone)]
pub(crate) struct Area {
    region: Region,
    policy: Policy,
    deny: Vec<Path>,
}

impl Area {
    fn new(region: Region, policy: Policy, deny: Vec<Path>) -> Area {
        Area {
            region,
            policy,
            deny,
        }
    }

    fn allows(deny: &[Path], rel: &Path) -> bool {
        !deny.iter().any(|denied| rel.under(denied))
    }

    fn readable(&self, rel: &Path) -> Result<ReadableFile> {
        let at = match Area::allows(&self.deny, rel) {
            true => self.region.framed(Some(rel)),
            false => None,
        };
        self.policy.readable(&at.ok_or(NotedError::Forbidden)?)
    }

    fn writeable(&self, rel: &Path) -> Result<WriteableFile> {
        let at = match Area::allows(&self.deny, rel) {
            true => self.region.framed(Some(rel)),
            false => None,
        };
        self.policy.writeable(&at.ok_or(NotedError::Forbidden)?)
    }

    fn from(&self, rel: Option<&Path>) -> Result<Option<ReadableFile>> {
        match rel {
            Some(rel) => self.readable(rel).map(Some),
            None => match self.region.framed(None) {
                Some(at) => self.policy.readable(&at).map(Some),
                None => {
                    self.policy.readable(&Path::new(ROOT_PROBE)?)?;
                    Ok(None)
                }
            },
        }
    }

    pub(crate) fn read(&self, at: &Path) -> Result<Vec<u8>> {
        self.region.read(&self.readable(at)?)
    }

    pub(crate) fn write(&self, at: &Path, data: &[u8], when: Condition) -> Result<()> {
        self.region.write(&self.writeable(at)?, data, when)
    }

    pub(crate) fn rename(&self, from: &Path, to: &Path, when: Condition) -> Result<()> {
        self.region
            .rename(&self.writeable(from)?, &self.writeable(to)?, when)
    }

    pub(crate) fn remove(&self, at: &Path) -> Result<Trashed> {
        self.region.remove(&self.writeable(at)?)
    }

    pub(crate) fn walk(
        &self,
        dir: Option<&Path>,
        descend: impl Fn(&Path) -> bool + Send + Sync + 'static,
    ) -> Vec<Path> {
        let Ok(from) = self.from(dir) else {
            return Vec::new();
        };
        let deny = self.deny.clone();
        self.region
            .walk(from.as_ref(), move |candidate| {
                Area::allows(&deny, candidate) && descend(candidate)
            })
            .into_iter()
            .filter(|candidate| self.readable(candidate).is_ok())
            .collect()
    }

    pub(crate) async fn search(
        &self,
        dir: Option<&Path>,
        query: &SearchQuery,
        descend: impl Fn(&Path) -> bool + Send + Sync + 'static,
    ) -> Result<Vec<Hit>> {
        let from = self.from(dir)?;
        let deny = self.deny.clone();
        let found = self
            .region
            .search(from.as_ref(), query, move |candidate| {
                Area::allows(&deny, candidate) && descend(candidate)
            })
            .await?;
        Ok(found
            .into_iter()
            .filter_map(|raw| {
                let rel = self.region.relative(raw.path())?;
                let hit = raw.into_hit(self.readable(&rel).ok()?).ok()?;
                Some(Hit {
                    path: rel,
                    lines: hit.lines,
                })
            })
            .collect())
    }
}

#[derive(Clone)]
pub(crate) struct Areas {
    pub(crate) notes: Area,
    pub(crate) log: Area,
    pub(crate) tasks: Area,
}

impl Areas {
    pub(crate) fn new(dir: NotedDir, policy: &Policy) -> Result<Areas> {
        Areas::over(Store::open(dir)?, policy)
    }

    pub(crate) fn store(&self) -> Store {
        self.notes.region.store()
    }

    pub(crate) fn over(store: Store, policy: &Policy) -> Result<Areas> {
        let scope = policy.scope().cloned();
        let log = Path::new(LOG)?;
        let tasks = Path::new(TASKS)?;

        let reserved = match scope {
            Some(_) => Vec::new(),
            None => vec![log.clone(), tasks.clone()],
        };
        let framed = |name: &Path| match &scope {
            Some(scope) => scope.join(name),
            None => name.clone(),
        };
        let tasks_base = match &scope {
            Some(scope) => tasks.join(scope),
            None => tasks.clone(),
        };

        Ok(Areas {
            notes: Area::new(
                Region::new(store.clone(), scope.clone(), scope.clone()),
                policy.clone(),
                reserved,
            ),
            log: Area::new(
                Region::new(store.clone(), Some(log.clone()), Some(framed(&log))),
                policy.clone(),
                Vec::new(),
            ),
            tasks: Area::new(
                Region::new(store, Some(tasks_base), Some(framed(&tasks))),
                policy.clone(),
                Vec::new(),
            ),
        })
    }
}
