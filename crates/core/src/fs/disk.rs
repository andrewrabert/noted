//! Disk writes that leave no half-written file behind, and the one path
//! normalization the store uses. Re-exported through `util` for the crates
//! that persist their own files.

use std::io::Write;
use std::path::{Path as StdPath, PathBuf};

use crate::error::{Result, io_error};

fn new_temp(parent: &StdPath) -> Result<tempfile::NamedTempFile> {
    std::fs::create_dir_all(parent).map_err(|e| io_error("mkdir failed", e))?;
    tempfile::Builder::new()
        .prefix(".noted-tmp-")
        .tempfile_in(parent)
        .map_err(|e| io_error("write failed", e))
}

// a hidden temporary directory beside the entry being rewritten
pub fn temp_dir_in(parent: &StdPath) -> Result<tempfile::TempDir> {
    std::fs::create_dir_all(parent).map_err(|e| io_error("mkdir failed", e))?;
    tempfile::Builder::new()
        .prefix(".noted-tmp-")
        .tempdir_in(parent)
        .map_err(|e| io_error("write failed", e))
}

pub fn atomic_write(path: &StdPath, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| StdPath::new("."));
    let mut tmp = new_temp(parent)?;
    tmp.write_all(data)
        .and_then(|_| tmp.flush())
        .map_err(|e| io_error("write failed", e))?;
    tmp.persist(path)
        .map(|_| ())
        .map_err(|e| io_error("write failed", e.error))
}

pub fn atomic_create(path: &StdPath, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| StdPath::new("."));
    let mut tmp = new_temp(parent).map_err(std::io::Error::other)?;
    tmp.write_all(data)?;
    tmp.flush()?;
    tmp.persist_noclobber(path).map(|_| ()).map_err(|e| e.error)
}

pub fn normalize(path: &StdPath) -> PathBuf {
    path_clean::clean(path)
}
