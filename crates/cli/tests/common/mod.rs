#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

pub fn fixture_dir() -> tempfile::TempDir {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures/notes");
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("notes");
    copy_tree(&src, &dst);
    tmp
}

pub fn notes_root(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("notes")
}
