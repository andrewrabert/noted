use std::collections::BTreeMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use crate::domain::Path;
use crate::error::{NotedError, Result, io_error};
use crate::note::{Condition, Etag};
use crate::platform;
use crate::policy::{ReadableDir, ReadableFile, ReadablePath, WriteableFile, WriteablePath};
use crate::search::SearchQuery;

const TRASH: &str = ".trash";

pub struct NotedDir(PathBuf);

impl NotedDir {
    pub fn new(path: impl Into<PathBuf>) -> NotedDir {
        NotedDir(path.into())
    }
}

/// A search hit as the disk reports it: the name is spelled from the
/// directory the search started in.
pub(crate) struct RawHit {
    pub(crate) path: String,
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

    async fn current(&self, abs: &StdPath) -> Result<Option<Vec<u8>>> {
        match platform::read(abs).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(NotedError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn read(&self, at: &ReadableFile) -> Result<Vec<u8>> {
        let at: &ReadablePath = at.as_ref();
        platform::read(&at.to_store_path(&self.inner.base)?).await
    }

    pub(crate) async fn write(
        &self,
        at: &WriteableFile,
        data: &[u8],
        when: Condition,
    ) -> Result<()> {
        let at: &WriteablePath = at.as_ref();
        let abs = at.to_store_path(&self.inner.base)?;
        let _guard = self.inner.writes.hold().await;
        match when {
            Condition::Always => platform::write(&abs, data).await,
            Condition::Missing => platform::create(&abs, data).await,
            Condition::Exists => match platform::exists(&abs).await {
                true => platform::write(&abs, data).await,
                false => Err(NotedError::NotFound),
            },
            Condition::Matching(token) => match self.current(&abs).await? {
                Some(bytes) if Etag::of(&bytes) == token => platform::write(&abs, data).await,
                _ => Err(NotedError::Conflict),
            },
        }
    }

    pub(crate) async fn rename(
        &self,
        from: &WriteablePath,
        to: &WriteablePath,
        when: Condition,
    ) -> Result<()> {
        let source = from.to_store_path(&self.inner.base)?;
        let target = to.to_store_path(&self.inner.base)?;
        let _guard = self.inner.writes.hold().await;
        match when {
            Condition::Missing => platform::rename(&source, &target, false).await,
            Condition::Always => platform::rename(&source, &target, true).await,
            Condition::Exists => match platform::exists(&target).await {
                true => platform::rename(&source, &target, true).await,
                false => Err(NotedError::NotFound),
            },
            Condition::Matching(token) => match self.current(&target).await? {
                Some(bytes) if Etag::of(&bytes) == token => {
                    platform::rename(&source, &target, true).await
                }
                _ => Err(NotedError::Conflict),
            },
        }
    }

    // the trash mirrors the store: the entry lands under the same path it was
    // removed from
    pub(crate) async fn remove(&self, at: &WriteablePath) -> Result<()> {
        let from = at.to_store_path(&self.inner.base)?;
        let to = at.to_store_path(&self.inner.base.join(TRASH))?;
        let Some(name) = to
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
        else {
            unreachable!("a writeable path is never the store root")
        };
        let _guard = self.inner.writes.hold().await;
        for candidate in spare_names(&name) {
            match platform::relocate(&from, &to.with_file_name(candidate)).await {
                Err(NotedError::Conflict) => continue,
                other => return other,
            }
        }
        Err(NotedError::Conflict)
    }

    pub(crate) async fn walk(&self, start: &ReadableDir, max_depth: Option<usize>) -> Vec<String> {
        let start: &ReadablePath = start.as_ref();
        let Ok(abs) = start.to_store_path(&self.inner.base) else {
            return Vec::new();
        };
        platform::walk(&abs, max_depth)
            .await
            .unwrap_or_default()
            .iter()
            .map(|rel| {
                rel.components()
                    .map(|part| {
                        format!("{}{}", Path::SEPARATOR, part.as_os_str().to_string_lossy())
                    })
                    .collect()
            })
            .collect()
    }

    pub(crate) async fn search(
        &self,
        start: &ReadableDir,
        query: &SearchQuery,
    ) -> Result<Vec<RawHit>> {
        let start: &ReadablePath = start.as_ref();
        platform::grep(self.base(), &start.to_store_path(&self.inner.base)?, query).await
    }
}
