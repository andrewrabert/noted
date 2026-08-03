use std::collections::{BTreeMap, HashMap};
use std::path::{Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex};

use grep::searcher::SearcherBuilder;
use ignore::{WalkBuilder, WalkState};

use crate::error::{NotedError, Result, io_error, rejected, unavailable};
use crate::note::{Condition, Etag, Trashed};
use crate::path::Path;
use crate::policy::{ReadableFile, WriteableFile};
use crate::search::{Hit, LineSink, SearchMode, SearchQuery, build_matcher, narrow};
use crate::util::{IgnoreFilter, atomic_write, normalize};

const TRASH: &str = ".trash";

pub struct NotedDir(PathBuf);

impl NotedDir {
    pub fn new(path: impl Into<PathBuf>) -> NotedDir {
        NotedDir(path.into())
    }
}

pub(crate) struct RawHit {
    path: Path,
    lines: BTreeMap<u64, String>,
}

impl RawHit {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_hit(self, at: ReadableFile) -> Result<Hit> {
        match at.path() == self.path {
            true => Ok(Hit {
                path: self.path,
                lines: self.lines,
            }),
            false => Err(crate::error::rejected(
                "search hit unlocked by another path",
            )),
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

fn within(prefix: Option<&Path>, at: &str) -> Option<Option<Path>> {
    let Some(prefix) = prefix else {
        return Some(Path::new(at).ok());
    };
    if at == prefix.as_str() {
        return Some(None);
    }
    at.strip_prefix(prefix.as_str())
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| Path::new(rest).ok())
        .map(Some)
}

fn joined(prefix: Option<&Path>, rest: Option<&Path>) -> Option<Path> {
    match (prefix, rest) {
        (Some(prefix), Some(rest)) => Some(prefix.join(rest)),
        (Some(prefix), None) => Some(prefix.clone()),
        (None, rest) => rest.cloned(),
    }
}

#[derive(Clone)]
pub(crate) struct Region {
    store: Store,
    base: Option<Path>,
    frame: Option<Path>,
}

impl Region {
    pub(crate) fn new(store: Store, base: Option<Path>, frame: Option<Path>) -> Region {
        Region { store, base, frame }
    }

    pub(crate) fn store(&self) -> Store {
        self.store.clone()
    }

    pub(crate) fn framed(&self, rel: Option<&Path>) -> Option<Path> {
        joined(self.frame.as_ref(), rel)
    }

    pub(crate) fn relative(&self, framed: &Path) -> Option<Path> {
        within(self.frame.as_ref(), framed.as_str()).flatten()
    }

    fn located(&self, granted: &str) -> Result<Path> {
        within(self.frame.as_ref(), granted)
            .and_then(|rel| joined(self.base.as_ref(), rel.as_ref()))
            .ok_or(NotedError::Forbidden)
    }

    pub(crate) fn read(&self, at: &ReadableFile) -> Result<Vec<u8>> {
        self.store.read(&self.located(at.as_str())?)
    }

    pub(crate) fn write(&self, at: &WriteableFile, data: &[u8], when: Condition) -> Result<()> {
        self.store.write(&self.located(at.as_str())?, data, when)
    }

    pub(crate) fn rename(
        &self,
        from: &WriteableFile,
        to: &WriteableFile,
        when: Condition,
    ) -> Result<()> {
        self.store.rename(
            &self.located(from.as_str())?,
            &self.located(to.as_str())?,
            when,
        )
    }

    pub(crate) fn remove(&self, at: &WriteableFile) -> Result<Trashed> {
        self.store.remove(&self.located(at.as_str())?)?;
        self.relative(&at.path())
            .map(Trashed::new)
            .ok_or(NotedError::Forbidden)
    }

    fn from(&self, at: Option<&ReadableFile>) -> Result<Option<Path>> {
        match at {
            Some(at) => self.located(at.as_str()).map(Some),
            None => Ok(self.base.clone()),
        }
    }

    fn descending(
        &self,
        descend: impl Fn(&Path) -> bool + Send + Sync + 'static,
    ) -> impl Fn(&Path) -> bool + Send + Sync + 'static {
        let base = self.base.clone();
        move |candidate| match within(base.as_ref(), candidate.as_str()) {
            Some(Some(rel)) => descend(&rel),
            Some(None) => true,
            None => false,
        }
    }

    pub(crate) fn walk(
        &self,
        at: Option<&ReadableFile>,
        descend: impl Fn(&Path) -> bool + Send + Sync + 'static,
    ) -> Vec<Path> {
        let Ok(from) = self.from(at) else {
            return Vec::new();
        };
        self.store
            .walk(from.as_ref(), self.descending(descend))
            .into_iter()
            .filter_map(|found| within(self.base.as_ref(), found.as_str()).flatten())
            .collect()
    }

    pub(crate) async fn search(
        &self,
        at: Option<&ReadableFile>,
        query: &SearchQuery,
        descend: impl Fn(&Path) -> bool + Send + Sync + 'static,
    ) -> Result<Vec<RawHit>> {
        let from = self.from(at)?;
        let found = self
            .store
            .search(from.as_ref(), query, self.descending(descend))
            .await?;
        Ok(found
            .into_iter()
            .filter_map(|raw| {
                let rel = within(self.base.as_ref(), raw.path.as_str()).flatten()?;
                Some(RawHit {
                    path: self.framed(Some(&rel))?,
                    lines: raw.lines,
                })
            })
            .collect())
    }
}

struct StoreInner {
    root: PathBuf,
    writes: Mutex<()>,
    ignore: IgnoreFilter,
}

#[derive(Clone)]
pub(crate) struct Store(Arc<StoreInner>);

impl Store {
    pub(crate) fn open(dir: NotedDir) -> Result<Store> {
        let root = dir
            .0
            .canonicalize()
            .map_err(|e| io_error("notes dir unusable", e))?;
        let ignore = IgnoreFilter::new(&root);
        Ok(Store(Arc::new(StoreInner {
            root,
            writes: Mutex::new(()),
            ignore,
        })))
    }

    fn absolute(&self, at: Option<&Path>) -> PathBuf {
        match at {
            Some(at) => self.0.root.join(at.as_str()),
            None => self.0.root.clone(),
        }
    }

    fn rel(&self, abs: &StdPath) -> Option<Path> {
        let cleaned = normalize(abs);
        let under = cleaned.strip_prefix(&self.0.root).ok()?;
        Path::new(under.to_string_lossy()).ok()
    }

    fn addressable(&self, at: &Path) -> Result<PathBuf> {
        let abs = self.absolute(Some(at));
        if self.0.ignore.is_ignored(&abs) || self.crosses_symlink(at.as_str()) {
            return Err(rejected("invalid path"));
        }
        Ok(abs)
    }

    fn crosses_symlink(&self, at: &str) -> bool {
        let mut walked = self.0.root.clone();
        for part in at.split('/').filter(|p| !p.is_empty()) {
            walked.push(part);
            if let Ok(meta) = std::fs::symlink_metadata(&walked)
                && meta.file_type().is_symlink()
            {
                return true;
            }
        }
        false
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0.writes.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn current(&self, abs: &StdPath) -> Result<Option<Vec<u8>>> {
        match std::fs::read(abs) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error("cannot read note", e)),
        }
    }

    fn precondition(&self, abs: &StdPath, when: &Condition) -> Result<()> {
        match when {
            Condition::Always => Ok(()),
            Condition::Missing => match self.current(abs)? {
                None => Ok(()),
                Some(_) => Err(NotedError::Conflict),
            },
            Condition::Exists => match self.current(abs)? {
                Some(_) => Ok(()),
                None => Err(NotedError::NotFound),
            },
            Condition::Matching(token) => match self.current(abs)? {
                Some(bytes) if &Etag::of(&bytes) == token => Ok(()),
                Some(_) => Err(NotedError::Conflict),
                None => Err(NotedError::Conflict),
            },
        }
    }

    fn read(&self, at: &Path) -> Result<Vec<u8>> {
        std::fs::read(self.addressable(at)?).map_err(|e| io_error("no note", e))
    }

    fn write(&self, at: &Path, data: &[u8], when: Condition) -> Result<()> {
        let abs = self.addressable(at)?;
        let _guard = self.lock();
        self.precondition(&abs, &when)?;
        atomic_write(&abs, data)
    }

    fn rename(&self, from: &Path, to: &Path, when: Condition) -> Result<()> {
        let source = self.addressable(from)?;
        let target = self.addressable(to)?;
        let _guard = self.lock();
        if !source.exists() {
            return Err(NotedError::NotFound);
        }
        self.precondition(&target, &when)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("cannot create folder", e))?;
        }
        std::fs::rename(&source, &target).map_err(|e| io_error("cannot rename", e))
    }

    fn remove(&self, at: &Path) -> Result<()> {
        let source = self.addressable(at)?;
        let _guard = self.lock();
        if !source.exists() {
            return Err(NotedError::NotFound);
        }
        for candidate in spare_names(at) {
            let target = self.0.root.join(TRASH).join(&candidate);
            if target.exists() {
                continue;
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| io_error("delete failed", e))?;
            }
            return match std::fs::rename(&source, &target) {
                Ok(()) => Ok(()),
                Err(e) => Err(io_error("delete failed", e)),
            };
        }
        Err(NotedError::Conflict)
    }

    fn walk(&self, at: Option<&Path>, descend: impl Fn(&Path) -> bool + Send + Sync) -> Vec<Path> {
        let mut out = Vec::new();
        self.collect(&self.absolute(at), &descend, &mut out);
        out
    }

    fn collect(
        &self,
        dir: &StdPath,
        descend: &(impl Fn(&Path) -> bool + Send + Sync),
        out: &mut Vec<Path>,
    ) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() || entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let path = entry.path();
            if self.0.ignore.is_ignored(&path) {
                continue;
            }
            let Some(rel) = self.rel(&path) else { continue };
            if kind.is_dir() {
                if descend(&rel) {
                    self.collect(&path, descend, out);
                }
            } else if kind.is_file() && path.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(rel);
            }
        }
    }

    async fn search(
        &self,
        at: Option<&Path>,
        query: &SearchQuery,
        descend: impl Fn(&Path) -> bool + Send + Sync + 'static,
    ) -> Result<Vec<RawHit>> {
        let matcher = match query.mode {
            SearchMode::Path => None,
            _ => Some(build_matcher(query)?),
        };
        let store = self.clone();
        let base = self.absolute(at);
        let query = query.clone();

        tokio::task::spawn_blocking(move || {
            let descend = Arc::new(descend);
            let lines: Mutex<HashMap<Path, BTreeMap<u64, String>>> = Mutex::new(HashMap::new());
            let walked: Mutex<Vec<Path>> = Mutex::new(Vec::new());

            let mut wb = store.walk_builder(&base, descend);
            narrow(&mut wb, &base, &query)?;
            wb.build_parallel().run(|| {
                let mut searcher = SearcherBuilder::new()
                    .line_number(true)
                    .multi_line(query.multiline)
                    .before_context(query.context as usize)
                    .after_context(query.context as usize)
                    .build();
                let matcher = matcher.as_ref();
                let lines = &lines;
                let walked = &walked;
                let store = &store;
                Box::new(move |entry| {
                    let Ok(entry) = entry else {
                        return WalkState::Continue;
                    };
                    match entry.file_type() {
                        Some(kind) if kind.is_file() => {}
                        _ => return WalkState::Continue,
                    }
                    let path = entry.into_path();
                    let Some(rel) = store.rel(&path) else {
                        return WalkState::Continue;
                    };
                    if let Some(matcher) = matcher {
                        let mut sink = LineSink::new();
                        if searcher.search_path(matcher, &path, &mut sink).is_err() {
                            return WalkState::Continue;
                        }
                        if !sink.lines.is_empty() {
                            lines
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .entry(rel)
                                .or_default()
                                .extend(sink.lines);
                            return WalkState::Continue;
                        }
                    }
                    walked.lock().unwrap_or_else(|e| e.into_inner()).push(rel);
                    WalkState::Continue
                })
            });

            let mut hits: Vec<RawHit> = lines
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .into_iter()
                .map(|(path, lines)| RawHit { path, lines })
                .collect();
            if matches!(query.mode, SearchMode::Any | SearchMode::Path) {
                hits.extend(
                    walked
                        .into_inner()
                        .unwrap_or_else(|e| e.into_inner())
                        .into_iter()
                        .map(|path| RawHit {
                            path,
                            lines: BTreeMap::new(),
                        }),
                );
            }
            Ok(hits)
        })
        .await
        .map_err(|e| unavailable(format!("search: {e}")))?
    }

    fn walk_builder(
        &self,
        base: &StdPath,
        descend: Arc<dyn Fn(&Path) -> bool + Send + Sync>,
    ) -> WalkBuilder {
        let filter = self.0.ignore.clone();
        let store = self.clone();
        let mut wb = WalkBuilder::new(base);
        wb.hidden(true)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .filter_entry(move |entry| {
                if filter.is_ignored(entry.path()) {
                    return false;
                }
                let Some(rel) = store.rel(entry.path()) else {
                    return true;
                };
                match entry.file_type() {
                    Some(kind) if kind.is_dir() => descend(&rel),
                    _ => true,
                }
            });
        wb
    }
}
