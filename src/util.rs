use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use ignore::gitignore::Gitignore;
use ignore::WalkBuilder;
use rand::RngCore;

use crate::error::{io_error, Result};

pub fn walk_builder(base: &Path) -> WalkBuilder {
    let filter = IgnoreFilter::new(base);
    let mut wb = WalkBuilder::new(base);
    wb.hidden(true)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .filter_entry(move |entry| !filter.is_ignored(entry.path()));
    wb
}

pub fn walk_files(base: &Path) -> Vec<PathBuf> {
    walk_builder(base)
        .build()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            match entry.file_type() {
                Some(ft) if ft.is_file() => Some(entry.into_path()),
                _ => None,
            }
        })
        .collect()
}

#[derive(Clone)]
pub struct IgnoreFilter {
    root: PathBuf,
    cache: Arc<Mutex<HashMap<PathBuf, Arc<Vec<Gitignore>>>>>,
}

impl IgnoreFilter {
    pub fn new(root: &Path) -> IgnoreFilter {
        IgnoreFilter {
            root: root.to_path_buf(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_ignored(&self, path: &Path) -> bool {
        if path == self.root {
            return false;
        }
        let is_dir = path.is_dir();
        let mut dir = path.parent();
        while let Some(d) = dir {
            if !d.starts_with(&self.root) {
                break;
            }
            for gi in self.matchers(d).iter() {
                let m = gi.matched_path_or_any_parents(path, is_dir);
                if m.is_ignore() {
                    return true;
                }
                if m.is_whitelist() {
                    return false;
                }
            }
            if d == self.root {
                break;
            }
            dir = d.parent();
        }
        false
    }

    fn matchers(&self, d: &Path) -> Arc<Vec<Gitignore>> {
        if let Some(hit) = self.cache.lock().unwrap().get(d) {
            return hit.clone();
        }
        let mut built = Vec::new();
        for name in [".ignore", ".gitignore"] {
            let f = d.join(name);
            if f.is_file() {
                built.push(Gitignore::new(&f).0);
            }
        }
        let built = Arc::new(built);
        self.cache
            .lock()
            .unwrap()
            .insert(d.to_path_buf(), built.clone());
        built
    }
}

pub fn random_token(n_bytes: usize) -> String {
    let mut bytes = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

fn new_temp(parent: &Path) -> Result<tempfile::NamedTempFile> {
    std::fs::create_dir_all(parent).map_err(|e| io_error("mkdir failed", e))?;
    tempfile::Builder::new()
        .prefix(".noted-tmp-")
        .tempfile_in(parent)
        .map_err(|e| io_error("write failed", e))
}

pub fn atomic_write(path: &Path, text: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = new_temp(parent)?;
    tmp.write_all(text.as_bytes())
        .and_then(|_| tmp.flush())
        .map_err(|e| io_error("write failed", e))?;
    tmp.persist(path)
        .map(|_| ())
        .map_err(|e| io_error("write failed", e.error))
}

pub fn atomic_create(path: &Path, text: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = new_temp(parent).map_err(std::io::Error::other)?;
    tmp.write_all(text.as_bytes())?;
    tmp.flush()?;
    tmp.persist_noclobber(path).map(|_| ()).map_err(|e| e.error)
}

pub fn normalize(path: &Path) -> PathBuf {
    path_clean::clean(path)
}

pub fn slice_lines(text: &str, offset: Option<i64>, limit: Option<i64>) -> String {
    if offset.is_none() && limit.is_none() {
        return text.to_string();
    }
    let lines: Vec<&str> = text.lines().collect();
    let start = offset
        .filter(|o| *o > 0)
        .map(|o| (o - 1) as usize)
        .unwrap_or(0);
    let start = start.min(lines.len());
    let end = match limit {
        Some(l) if l > 0 => (start + l as usize).min(lines.len()),
        _ => lines.len(),
    };
    lines[start..end].join("\n")
}
