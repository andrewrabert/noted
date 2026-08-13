use std::fmt;

use crate::error::{NotedError, Result, rejected};
use crate::fragment::{PolicyFragment, RegionFragment};
use crate::note::{Condition, Trashed};
use crate::path::{DirPath, Path, Reserved};
use crate::policy::{Readable, RegionPolicy, Writeable};
use crate::search::{Hit, SearchQuery};
use crate::store::{NotedDir, Store};

const LOG: &str = "Log";
const TASKS: &str = "Tasks";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionDir {
    Notes,
    Log,
    Tasks,
}

impl From<RegionDir> for DirPath {
    fn from(dir: RegionDir) -> DirPath {
        let root = DirPath::root();
        match dir {
            RegionDir::Notes => root,
            RegionDir::Log => root.child(LOG),
            RegionDir::Tasks => root.child(TASKS),
        }
    }
}

impl RegionDir {
    pub(crate) fn reserved() -> Result<Vec<Path>> {
        Ok(vec![Path::new(LOG)?, Path::new(TASKS)?])
    }

    fn of_key(key: &Path) -> (RegionDir, Option<Path>) {
        for (dir, name) in [(RegionDir::Log, LOG), (RegionDir::Tasks, TASKS)] {
            if key.as_str() == name {
                return (dir, None);
            }
            if let Some(rest) = key
                .as_str()
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('/'))
                && let Ok(rest) = Path::new(rest)
            {
                return (dir, Some(rest));
            }
        }
        (RegionDir::Notes, Some(key.clone()))
    }

    pub(crate) fn project(self, fragment: &PolicyFragment) -> Result<RegionFragment> {
        if let Some(scope) = &fragment.scope
            && RegionDir::of_key(scope).0 != RegionDir::Notes
        {
            return Err(RegionError::ReservedScope {
                path: scope.clone(),
            }
            .into());
        }
        let named = fragment
            .paths
            .iter()
            .filter_map(|(key, asked)| {
                let (dir, rest) = RegionDir::of_key(key);
                (dir == self).then_some((rest, *asked))
            })
            .collect();
        Ok(RegionFragment {
            scope: fragment.scope.clone(),
            access: fragment.access,
            named,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RegionError {
    ReservedScope { path: Path },
}

impl fmt::Display for RegionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegionError::ReservedScope { path } => write!(
                f,
                "scope '{path}' is the log or task region: a scope addresses notes"
            ),
        }
    }
}

impl From<RegionError> for NotedError {
    fn from(e: RegionError) -> NotedError {
        rejected(e.to_string())
    }
}

#[derive(Clone)]
pub(crate) struct RegionStore {
    dir: RegionDir,
    store: Store,
    policy: RegionPolicy,
    deny: Vec<Path>,
}

impl RegionStore {
    pub(crate) fn new(
        dir: RegionDir,
        store: Store,
        policy: RegionPolicy,
        deny: Vec<Path>,
    ) -> RegionStore {
        RegionStore {
            dir,
            store,
            policy,
            deny,
        }
    }

    pub(crate) fn policy(&self) -> &RegionPolicy {
        &self.policy
    }

    fn with_policy_fragment(&self, fragment: &PolicyFragment) -> Result<RegionStore> {
        Ok(RegionStore {
            dir: self.dir,
            store: self.store.clone(),
            policy: self
                .policy
                .with_policy_fragment(&self.dir.project(fragment)?)?,
            deny: self.deny.clone(),
        })
    }

    fn allows(&self, rel: &Path) -> bool {
        !self.deny.iter().any(|denied| rel.under(denied))
    }

    fn readable(&self, rel: &Path) -> Result<Readable> {
        match self.allows(rel) {
            true => self.policy.readable(rel),
            false => Err(NotedError::Forbidden),
        }
    }

    fn writeable(&self, rel: &Path) -> Result<Writeable> {
        match self.allows(rel) {
            true => self.policy.writeable(rel),
            false => Err(NotedError::Forbidden),
        }
    }

    fn from(&self, dir: Option<&Path>) -> DirPath {
        let base = self.policy.base().clone();
        match dir {
            Some(rel) => base.join(rel),
            None => base,
        }
    }

    pub(crate) async fn read(&self, rel: &Path) -> Result<Vec<u8>> {
        self.store.read(&self.readable(rel)?).await
    }

    pub(crate) async fn write(&self, rel: &Path, data: &[u8], when: Condition) -> Result<()> {
        self.store.write(&self.writeable(rel)?, data, when).await
    }

    pub(crate) async fn rename(&self, from: &Path, to: &Path, when: Condition) -> Result<()> {
        self.store
            .rename(&self.writeable(from)?, &self.writeable(to)?, when)
            .await
    }

    pub(crate) async fn remove(&self, rel: &Path) -> Result<Trashed> {
        self.store.remove(&self.writeable(rel)?).await?;
        Ok(Trashed::new(rel.clone()))
    }

    // the file carrying an entry's markdown: the entry itself, or 'leaf' inside it
    // when the entry is a directory
    pub(crate) async fn body_of(&self, entry: &Path, leaf: Reserved) -> Result<Path> {
        match self.store.is_dir(&self.readable(entry)?).await {
            true => Ok(entry.joined_reserved(leaf)),
            false => Ok(entry.clone()),
        }
    }

    // every attachment file directly inside 'dir'
    pub(crate) async fn files(&self, dir: &Path) -> Vec<Path> {
        self.admitted(self.store.files(&self.from(Some(dir))).await)
    }

    pub(crate) async fn attach(
        &self,
        entry: &Path,
        leaf: Reserved,
        file: &Path,
        data: &[u8],
    ) -> Result<()> {
        self.store
            .attach(
                &self.writeable(entry)?,
                &self.writeable(&entry.joined_reserved(leaf))?,
                &self.writeable(file)?,
                data,
            )
            .await
    }

    pub(crate) async fn walk(&self, dir: Option<&Path>) -> Vec<Path> {
        self.admitted(self.store.walk(&self.from(dir)).await)
    }

    pub(crate) async fn children(&self, dir: Option<&Path>) -> Vec<Path> {
        self.admitted(self.store.children(&self.from(dir)).await)
    }

    fn admitted(&self, found: Vec<Path>) -> Vec<Path> {
        let base = self.from(None);
        found
            .into_iter()
            .filter_map(|at| base.relative(&at))
            .filter(|rel| self.readable(rel).is_ok())
            .collect()
    }

    // a starting directory the policy denies outright is refused, not silently empty
    pub(crate) async fn search(&self, dir: Option<&Path>, query: &SearchQuery) -> Result<Vec<Hit>> {
        match dir {
            Some(rel) => {
                self.readable(rel)?;
            }
            None if !self.policy.access().read => return Err(NotedError::Forbidden),
            None => {}
        }
        let base = self.from(None);
        let found = self.store.search(&self.from(dir), query).await?;
        Ok(found
            .into_iter()
            .filter_map(|raw| {
                let rel = base.relative(raw.path())?;
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
pub(crate) struct Regions {
    pub(crate) notes: RegionStore,
    pub(crate) log: RegionStore,
    pub(crate) tasks: RegionStore,
}

impl Regions {
    pub(crate) fn open(dir: NotedDir) -> Result<Regions> {
        let store = Store::open(dir)?;
        Ok(Regions {
            notes: RegionStore::new(
                RegionDir::Notes,
                store.clone(),
                RegionPolicy::new(RegionDir::Notes.into()),
                RegionDir::reserved()?,
            ),
            log: RegionStore::new(
                RegionDir::Log,
                store.clone(),
                RegionPolicy::new(RegionDir::Log.into()),
                Vec::new(),
            ),
            tasks: RegionStore::new(
                RegionDir::Tasks,
                store,
                RegionPolicy::new(RegionDir::Tasks.into()),
                Vec::new(),
            ),
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

#[cfg(test)]
pub(crate) fn folded(dir: RegionDir, fragments: &[PolicyFragment]) -> Result<RegionPolicy> {
    fragments
        .iter()
        .try_fold(RegionPolicy::new(dir.into()), |policy, fragment| {
            policy.with_policy_fragment(&dir.project(fragment)?)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> Path {
        Path::new(s).unwrap()
    }

    fn fragment(s: &str) -> PolicyFragment {
        s.parse().unwrap()
    }

    fn asked(read: Option<bool>) -> crate::fragment::AccessFragment {
        crate::fragment::AccessFragment { read, write: None }
    }

    #[test]
    fn a_region_directory_closes_with_a_separator() {
        assert_eq!(DirPath::from(RegionDir::Notes).as_str(), "/");
        assert_eq!(DirPath::from(RegionDir::Log).as_str(), "/Log/");
        assert_eq!(DirPath::from(RegionDir::Tasks).as_str(), "/Tasks/");
    }

    #[test]
    fn a_scope_is_cumulative_across_the_regions() {
        let fragment = fragment(r#"{"scope":"a/b/c"}"#);
        for (dir, base) in [
            (RegionDir::Notes, "/a/b/c/"),
            (RegionDir::Log, "/Log/a/b/c/"),
            (RegionDir::Tasks, "/Tasks/a/b/c/"),
        ] {
            let policy = folded(dir, std::slice::from_ref(&fragment)).unwrap();
            assert_eq!(policy.base().as_str(), base);
        }
    }

    #[test]
    fn a_key_names_its_own_region_and_loses_the_region_name() {
        assert_eq!(RegionDir::of_key(&at("Log")), (RegionDir::Log, None));
        assert_eq!(
            RegionDir::of_key(&at("Tasks/dev/x")),
            (RegionDir::Tasks, Some(at("dev/x")))
        );
        assert_eq!(
            RegionDir::of_key(&at("Logbook")),
            (RegionDir::Notes, Some(at("Logbook")))
        );
    }

    #[test]
    fn a_projection_keeps_only_its_own_regions_keys() {
        let fragment = fragment(
            r#"{"scope":"dev","access":{"write":false},"paths":{"Tasks":{"read":true},"vendor":{"read":false}}}"#,
        );
        let tasks = RegionDir::Tasks.project(&fragment).unwrap();
        assert_eq!(tasks.scope, Some(at("dev")));
        assert_eq!(tasks.access.write, Some(false));
        assert_eq!(tasks.named, vec![(None, asked(Some(true)))]);

        let notes = RegionDir::Notes.project(&fragment).unwrap();
        assert_eq!(notes.named, vec![(Some(at("vendor")), asked(Some(false)))]);
    }

    #[test]
    fn a_reserved_scope_is_refused() {
        for text in [r#"{"scope":"Log"}"#, r#"{"scope":"Tasks/dev"}"#] {
            assert!(
                matches!(RegionDir::Notes.project(&fragment(text)), Err(NotedError::InvalidInput(ref m)) if m.contains("a scope addresses notes")),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn a_scoped_key_names_its_own_region() {
        let fragment = fragment(
            r#"{"scope":"dev","paths":{"Tasks":{"read":true,"write":false},"Log":{"read":false,"write":false}}}"#,
        );
        let tasks = folded(RegionDir::Tasks, std::slice::from_ref(&fragment)).unwrap();
        assert!(tasks.access().read && !tasks.access().write);
        let log = folded(RegionDir::Log, std::slice::from_ref(&fragment)).unwrap();
        assert!(!log.access().read && !log.access().write);
    }
}
