use std::collections::BTreeMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use grep::searcher::SearcherBuilder;
use ignore::{WalkBuilder, WalkState};

use crate::error::{NotedError, Result, io_error, rejected, unavailable};
use crate::note::{Condition, Etag};
use crate::path::{DirPath, Path, Reserved};
use crate::policy::{Readable, Writeable};
use crate::search::{Hit, LineSink, SearchMode, SearchOrder, SearchQuery, build_matcher, narrow};
use crate::util::{IgnoreFilter, atomic_create, atomic_write, normalize, temp_dir_in};

const TRASH: &str = ".trash";

// '.md' files, and the '.md' directories that carry a task: a task directory is an
// entry in itself and is never descended into
#[derive(Clone, Copy)]
enum Listing {
    Notes { deep: bool },
    Files,
}

pub struct NotedDir(PathBuf);

impl NotedDir {
    pub fn new(path: impl Into<PathBuf>) -> NotedDir {
        NotedDir(path.into())
    }
}

pub(crate) struct RawHit {
    path: Path,
    modified: SystemTime,
    lines: BTreeMap<u64, String>,
}

fn ordered(hits: &mut [RawHit], order: SearchOrder) {
    match order {
        SearchOrder::Path => hits.sort_by(|a, b| a.path.cmp(&b.path)),
        SearchOrder::Modified => hits.sort_by(|a, b| {
            b.modified
                .cmp(&a.modified)
                .then_with(|| a.path.cmp(&b.path))
        }),
    }
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

    fn absolute(&self, at: &Path) -> PathBuf {
        self.0.root.join(at.as_str())
    }

    fn directory(&self, from: &DirPath) -> PathBuf {
        match from.to_path() {
            Some(at) => self.absolute(&at),
            None => self.0.root.clone(),
        }
    }

    fn rel(&self, abs: &StdPath) -> Option<Path> {
        let cleaned = normalize(abs);
        let under = cleaned.strip_prefix(&self.0.root).ok()?;
        Path::stored(under.to_string_lossy().as_ref()).ok()
    }

    fn addressable(&self, at: &Path) -> Result<PathBuf> {
        let abs = self.absolute(at);
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
            Condition::Missing => match std::fs::symlink_metadata(abs).is_ok() {
                false => Ok(()),
                true => Err(NotedError::Conflict),
            },
            Condition::Exists => match std::fs::symlink_metadata(abs).is_ok() {
                true => Ok(()),
                false => Err(NotedError::NotFound),
            },
            Condition::Matching(token) => match self.current(abs)? {
                Some(bytes) if &Etag::of(&bytes) == token => Ok(()),
                Some(_) => Err(NotedError::Conflict),
                None => Err(NotedError::Conflict),
            },
        }
    }

    pub(crate) fn read(&self, at: &Readable) -> Result<Vec<u8>> {
        std::fs::read(self.addressable(&at.0)?).map_err(|e| io_error("no note", e))
    }

    pub(crate) fn write(&self, at: &Writeable, data: &[u8], when: Condition) -> Result<()> {
        let abs = self.addressable(&at.0)?;
        let _guard = self.lock();
        self.precondition(&abs, &when)?;
        atomic_write(&abs, data)
    }

    pub(crate) fn rename(&self, from: &Writeable, to: &Writeable, when: Condition) -> Result<()> {
        let source = self.addressable(&from.0)?;
        let target = self.addressable(&to.0)?;
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

    pub(crate) fn remove(&self, at: &Writeable) -> Result<()> {
        let at = &at.0;
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

    pub(crate) fn walk(&self, from: &DirPath) -> Vec<Path> {
        let mut out = Vec::new();
        self.collect(
            &self.directory(from),
            Listing::Notes { deep: true },
            &mut out,
        );
        out
    }

    pub(crate) fn children(&self, from: &DirPath) -> Vec<Path> {
        let mut out = Vec::new();
        self.collect(
            &self.directory(from),
            Listing::Notes { deep: false },
            &mut out,
        );
        out
    }

    // every plain file directly inside 'from', whatever its extension
    pub(crate) fn files(&self, from: &DirPath) -> Vec<Path> {
        let mut out = Vec::new();
        self.collect(&self.directory(from), Listing::Files, &mut out);
        out
    }

    pub(crate) fn is_dir(&self, at: &Readable) -> bool {
        match self.addressable(&at.0) {
            Ok(abs) => abs.is_dir(),
            Err(_) => false,
        }
    }

    // makes 'entry' a directory carrying its markdown at 'body' when 'entry' is a
    // plain file, then writes 'data' at 'file' inside it, in one rename
    pub(crate) fn attach(
        &self,
        entry: &Writeable,
        body: &Writeable,
        file: &Writeable,
        data: &[u8],
    ) -> Result<()> {
        let entry_abs = self.addressable(&entry.0)?;
        let file_abs = self.addressable(&file.0)?;
        let leaf = body.0.file_name().to_string();
        let name = file.0.file_name().to_string();
        let _guard = self.lock();
        let meta = std::fs::symlink_metadata(&entry_abs).map_err(|_| NotedError::NotFound)?;
        if meta.is_dir() {
            return atomic_create(&file_abs, data).map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => NotedError::Conflict,
                _ => io_error("cannot attach", e),
            });
        }

        let parent = entry_abs.parent().unwrap_or_else(|| StdPath::new("."));
        let staged = temp_dir_in(parent)?;
        atomic_write(&staged.path().join(&name), data)?;
        let held = staged.path().join(&leaf);
        std::fs::rename(&entry_abs, &held).map_err(|e| io_error("cannot attach", e))?;
        match std::fs::rename(staged.path(), &entry_abs) {
            Ok(()) => {
                let _ = staged.keep();
                Ok(())
            }
            // a failed attach leaves the task where it was
            Err(e) => {
                let _ = std::fs::rename(&held, &entry_abs);
                Err(io_error("cannot attach", e))
            }
        }
    }

    fn collect(&self, dir: &StdPath, listing: Listing, out: &mut Vec<Path>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if kind.is_symlink() || name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            if self.0.ignore.is_ignored(&path) {
                continue;
            }
            let Some(rel) = self.rel(&path) else { continue };
            match listing {
                Listing::Files if kind.is_file() => out.push(rel),
                Listing::Files => {}
                Listing::Notes { .. } if kind.is_file() => {
                    if name.ends_with(".md") {
                        out.push(rel);
                    }
                }
                Listing::Notes { .. } if name.ends_with(".md") && kind.is_dir() => out.push(rel),
                Listing::Notes { deep: true } if kind.is_dir() => self.collect(&path, listing, out),
                Listing::Notes { .. } => {}
            }
        }
    }

    pub(crate) async fn search(&self, from: &DirPath, query: &SearchQuery) -> Result<Vec<RawHit>> {
        let matcher = match query.mode {
            SearchMode::Path => None,
            _ => Some(build_matcher(query)?),
        };
        let store = self.clone();
        let base = self.directory(from);
        let query = query.clone();

        tokio::task::spawn_blocking(move || {
            let matched: Mutex<Vec<RawHit>> = Mutex::new(Vec::new());
            let walked: Mutex<Vec<RawHit>> = Mutex::new(Vec::new());

            let mut wb = store.walk_builder(&base);
            narrow(&mut wb, &base, &query)?;
            wb.build_parallel().run(|| {
                let mut searcher = SearcherBuilder::new()
                    .line_number(true)
                    .multi_line(query.multiline)
                    .before_context(query.context as usize)
                    .after_context(query.context as usize)
                    .build();
                let matcher = matcher.as_ref();
                let matched = &matched;
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
                    let modified = entry
                        .metadata()
                        .and_then(|meta| meta.modified().map_err(ignore::Error::from))
                        .unwrap_or(SystemTime::UNIX_EPOCH);
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
                            matched
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(RawHit {
                                    path: rel,
                                    modified,
                                    lines: sink.lines,
                                });
                            return WalkState::Continue;
                        }
                    }
                    walked
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(RawHit {
                            path: rel,
                            modified,
                            lines: BTreeMap::new(),
                        });
                    WalkState::Continue
                })
            });

            let mut hits = matched.into_inner().unwrap_or_else(|e| e.into_inner());
            if matches!(query.mode, SearchMode::Any | SearchMode::Path) {
                hits.extend(walked.into_inner().unwrap_or_else(|e| e.into_inner()));
            }
            ordered(&mut hits, query.order);
            Ok(hits)
        })
        .await
        .map_err(|e| unavailable(format!("search: {e}")))?
    }

    fn walk_builder(&self, base: &StdPath) -> WalkBuilder {
        let filter = self.0.ignore.clone();
        let mut wb = WalkBuilder::new(base);
        wb.hidden(false)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .filter_entry(move |entry| {
                let name = entry.file_name().to_string_lossy();
                let visible = entry.depth() == 0
                    || !name.starts_with('.')
                    || name == Reserved::TaskBody.as_str();
                visible && !filter.is_ignored(entry.path())
            });
        wb
    }
}
