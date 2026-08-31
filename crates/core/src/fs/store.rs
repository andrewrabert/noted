use std::collections::BTreeMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use crate::domain::{NotePath, Region, Segment};
use crate::error::{NotedError, Result, io_error, rejected};
use crate::note::{Condition, Etag};
use crate::platform::{self, Entry};
use crate::policy::{Readable, RegionNotePath, Writeable};
use crate::search::SearchQuery;

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

/// A search hit as the disk reports it: the name is spelled from the
/// directory the search started in.
pub(crate) struct RawHit {
    pub(crate) path: NotePath,
    #[allow(dead_code)]
    pub(crate) modified: SystemTime,
    pub(crate) lines: BTreeMap<u64, String>,
}

// the name itself, then 'stem 1.ext', 'stem 2.ext', ... for a trash that
// already holds it
fn spare_names(name: &str) -> impl Iterator<Item = String> + use<> {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), Some(ext.to_string())),
        _ => (name.to_string(), None),
    };
    std::iter::once(name.to_string()).chain((1u64..1000).map(move |n| match &ext {
        Some(ext) => format!("{stem} {n}.{ext}"),
        None => format!("{stem} {n}"),
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

    // the one place segments become an OS path: the store root, the region's
    // directory, then the segments given
    fn rooted<'a>(&self, region: Region, parts: impl Iterator<Item = &'a Segment>) -> PathBuf {
        let mut out = self.inner.base.clone();
        for part in region.base().segments() {
            out.push(part.as_str());
        }
        for part in parts {
            out.push(part.as_str());
        }
        out
    }

    async fn addressable(&self, region: Region, at: &RegionNotePath) -> Result<PathBuf> {
        let abs = self.rooted(region, at.segments());
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
        platform::read(&self.addressable(at.region(), at.at()).await?).await
    }

    pub(crate) async fn write(&self, at: &Writeable, data: &[u8], when: Condition) -> Result<()> {
        let abs = self.addressable(at.region(), at.at()).await?;
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
        let source = self.addressable(from.region(), from.at()).await?;
        let target = self.addressable(to.region(), to.at()).await?;
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

    // the trash mirrors the store: the entry lands under the same region
    // directory and path it was removed from
    pub(crate) async fn remove(&self, at: &Writeable) -> Result<()> {
        let from = self.addressable(at.region(), at.at()).await?;
        let parts: Vec<&Segment> = at.at().segments().collect();
        let Some((name, dirs)) = parts.split_last() else {
            return Err(NotedError::Forbidden);
        };
        let base = at.region().base();
        let mut dir = self.inner.base.join(TRASH);
        for part in base.segments().chain(dirs.iter().copied()) {
            dir.push(part.as_str());
        }
        let _guard = self.inner.writes.hold().await;
        for candidate in spare_names(name.as_str()) {
            match platform::relocate(&from, &dir.join(&candidate)).await {
                Err(NotedError::Conflict) => continue,
                other => return other,
            }
        }
        Err(NotedError::Conflict)
    }

    pub(crate) async fn walk(&self, region: Region, start: &NotePath) -> Vec<NotePath> {
        self.listing(region, start, Listing { deep: true }).await
    }

    pub(crate) async fn children(&self, region: Region, start: &NotePath) -> Vec<NotePath> {
        self.listing(region, start, Listing { deep: false }).await
    }

    async fn listing(&self, region: Region, start: &NotePath, listing: Listing) -> Vec<NotePath> {
        let mut out = Vec::new();
        self.collect(
            &self.rooted(region, start.segments()),
            "",
            listing,
            &mut out,
        )
        .await;
        out
    }

    // an entry the note grammar refuses (a dotted name, an untrimmed one) is
    // not a note and is not entered
    async fn collect(
        &self,
        dir: &StdPath,
        prefix: &str,
        listing: Listing,
        out: &mut Vec<NotePath>,
    ) {
        let found = platform::entries(self.base(), dir, false)
            .await
            .unwrap_or_default();
        for Entry { name, is_dir, .. } in found {
            let spelled = format!("{prefix}/{name}");
            let Ok(rel) = NotePath::new(&spelled) else {
                continue;
            };
            if !is_dir {
                out.push(rel);
            } else if listing.deep {
                Box::pin(self.collect(&dir.join(&name), &spelled, listing, out)).await;
            }
        }
    }

    pub(crate) async fn search(
        &self,
        region: Region,
        start: &NotePath,
        query: &SearchQuery,
    ) -> Result<Vec<RawHit>> {
        platform::grep(self.base(), &self.rooted(region, start.segments()), query).await
    }
}
