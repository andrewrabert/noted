use std::collections::BTreeMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use crate::error::{NotedError, Result, io_error, rejected};
use crate::note::{Condition, Etag};
use crate::path::{DirPath, Path};
use crate::platform::{self, Entry};
use crate::policy::{Readable, Writeable};
use crate::search::{Hit, SearchQuery};

const TRASH: &str = ".trash";

#[derive(Clone, Copy)]
struct Listing {
    deep: bool,
}

pub struct NotedDir(PathBuf);

impl NotedDir {
    pub fn new(path: impl Into<PathBuf>) -> NotedDir {
        NotedDir(path.into())
    }
}

pub(crate) struct RawHit {
    pub(crate) path: Path,
    #[allow(dead_code)]
    pub(crate) modified: SystemTime,
    pub(crate) lines: BTreeMap<u64, String>,
}

impl RawHit {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_hit(self, at: Readable) -> Result<Hit> {
        match at.0 == self.path {
            true => Ok(Hit {
                path: self.path,
                lines: self.lines,
            }),
            false => Err(rejected("search hit unlocked by another path")),
        }
    }
}

fn spare_names(at: &Path) -> impl Iterator<Item = String> + use<> {
    let full = at.to_string();
    let name = at.file_name().to_string();
    let dir = match full.strip_suffix(&name) {
        Some(dir) => dir.to_string(),
        None => String::new(),
    };
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), Some(ext.to_string())),
        _ => (name, None),
    };
    std::iter::once(full).chain((1u64..1000).map(move |n| match &ext {
        Some(ext) => format!("{dir}{stem} {n}.{ext}"),
        None => format!("{dir}{stem} {n}"),
    }))
}

struct StoreInner {
    base: PathBuf,
    writes: platform::Lock,
}

#[derive(Clone)]
pub(crate) struct Store {
    inner: Arc<StoreInner>,
}

impl Store {
    pub(crate) fn open(dir: NotedDir) -> Result<Store> {
        let base = dir
            .0
            .canonicalize()
            .map_err(|e| io_error("notes dir unusable", e))?;
        Ok(Store {
            inner: Arc::new(StoreInner {
                base,
                writes: platform::Lock::new(),
            }),
        })
    }

    fn base(&self) -> &StdPath {
        &self.inner.base
    }

    fn absolute(&self, at: &Path) -> PathBuf {
        self.inner.base.join(at.as_str())
    }

    fn directory(&self, from: &DirPath) -> PathBuf {
        match from.to_path() {
            Some(at) => self.absolute(&at),
            None => self.inner.base.clone(),
        }
    }

    // where a listing of 'from' starts in root-relative terms
    fn prefix(&self, from: &DirPath) -> String {
        match from.to_path() {
            Some(at) => format!("{at}/"),
            None => String::new(),
        }
    }

    async fn addressable(&self, at: &Path) -> Result<PathBuf> {
        let abs = self.absolute(at);
        if platform::crosses_symlink(self.base(), &abs)
            || platform::ignored(self.base(), &abs).await?
        {
            return Err(rejected("invalid path"));
        }
        Ok(abs)
    }

    // the entry's kind as its parent directory reports it, None when it is not
    // there at all
    async fn kind(&self, abs: &StdPath) -> Option<bool> {
        let parent = abs.parent()?;
        let name = abs.file_name()?.to_string_lossy().into_owned();
        platform::entries(self.base(), parent, false)
            .await
            .ok()?
            .into_iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.is_dir)
    }

    async fn current(&self, abs: &StdPath) -> Result<Option<Vec<u8>>> {
        match platform::read(abs).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(NotedError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn read(&self, at: &Readable) -> Result<Vec<u8>> {
        platform::read(&self.addressable(&at.0).await?).await
    }

    pub(crate) async fn write(&self, at: &Writeable, data: &[u8], when: Condition) -> Result<()> {
        let abs = self.addressable(&at.0).await?;
        let _guard = self.inner.writes.hold().await;
        match when {
            Condition::Always => platform::write(&abs, data).await,
            Condition::Missing => platform::create(&abs, data).await,
            Condition::Exists => match self.kind(&abs).await {
                Some(_) => platform::write(&abs, data).await,
                None => Err(NotedError::NotFound),
            },
            Condition::Matching(token) => match self.current(&abs).await? {
                Some(bytes) if Etag::of(&bytes) == token => platform::write(&abs, data).await,
                _ => Err(NotedError::Conflict),
            },
        }
    }

    pub(crate) async fn rename(
        &self,
        from: &Writeable,
        to: &Writeable,
        when: Condition,
    ) -> Result<()> {
        let source = self.addressable(&from.0).await?;
        let target = self.addressable(&to.0).await?;
        let _guard = self.inner.writes.hold().await;
        match when {
            Condition::Missing => platform::rename(&source, &target, false).await,
            Condition::Always => platform::rename(&source, &target, true).await,
            Condition::Exists => match self.kind(&target).await {
                Some(_) => platform::rename(&source, &target, true).await,
                None => Err(NotedError::NotFound),
            },
            Condition::Matching(token) => match self.current(&target).await? {
                Some(bytes) if Etag::of(&bytes) == token => {
                    platform::rename(&source, &target, true).await
                }
                _ => Err(NotedError::Conflict),
            },
        }
    }

    pub(crate) async fn remove(&self, at: &Writeable) -> Result<()> {
        let from = self.addressable(&at.0).await?;
        let _guard = self.inner.writes.hold().await;
        for candidate in spare_names(&at.0) {
            let target = self.inner.base.join(TRASH).join(&candidate);
            match platform::relocate(&from, &target).await {
                Err(NotedError::Conflict) => continue,
                other => return other,
            }
        }
        Err(NotedError::Conflict)
    }

    pub(crate) async fn walk(&self, from: &DirPath) -> Vec<Path> {
        self.listing(from, Listing { deep: true }).await
    }

    pub(crate) async fn children(&self, from: &DirPath) -> Vec<Path> {
        self.listing(from, Listing { deep: false }).await
    }

    async fn listing(&self, from: &DirPath, listing: Listing) -> Vec<Path> {
        let mut out = Vec::new();
        self.collect(&self.directory(from), &self.prefix(from), listing, &mut out)
            .await;
        out
    }

    async fn collect(&self, dir: &StdPath, prefix: &str, listing: Listing, out: &mut Vec<Path>) {
        let found = platform::entries(self.base(), dir, false)
            .await
            .unwrap_or_default();
        for Entry { name, is_dir, .. } in found {
            if name.starts_with('.') {
                continue;
            }
            let at = format!("{prefix}{name}");
            let Ok(rel) = Path::new(&at) else {
                continue;
            };
            if !is_dir {
                if name.ends_with(".md") {
                    out.push(rel);
                }
            } else if listing.deep {
                Box::pin(self.collect(&dir.join(&name), &format!("{at}/"), listing, out)).await;
            }
        }
    }

    pub(crate) async fn search(&self, from: &DirPath, query: &SearchQuery) -> Result<Vec<RawHit>> {
        platform::grep(self.base(), &self.directory(from), query).await
    }
}
