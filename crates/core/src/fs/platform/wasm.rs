use std::path::{Path as StdPath, PathBuf};

use crate::error::{Result, unavailable};
use crate::search::SearchQuery;
use crate::store::RawHit;

pub(crate) struct Lock;

impl Lock {
    pub(crate) fn new() -> Lock {
        Lock
    }

    pub(crate) async fn hold(&self) -> impl Drop + '_ {
        Held(std::marker::PhantomData)
    }
}

struct Held<'a>(std::marker::PhantomData<&'a Lock>);

impl Drop for Held<'_> {
    fn drop(&mut self) {}
}

fn absent<T>() -> Result<T> {
    Err(unavailable("this build has no local notes directory"))
}

pub(crate) async fn read(_abs: &StdPath) -> Result<Vec<u8>> {
    absent()
}

pub(crate) async fn write(_abs: &StdPath, _data: &[u8]) -> Result<()> {
    absent()
}

pub(crate) async fn create(_abs: &StdPath, _data: &[u8]) -> Result<()> {
    absent()
}

pub(crate) async fn rename(_from: &StdPath, _to: &StdPath, _overwrite: bool) -> Result<()> {
    absent()
}

pub(crate) async fn relocate(_from: &StdPath, _to: &StdPath) -> Result<()> {
    absent()
}

pub(crate) async fn exists(_abs: &StdPath) -> bool {
    false
}

pub(crate) async fn walk(_dir: &StdPath, _max_depth: Option<usize>) -> Result<Vec<PathBuf>> {
    Ok(Vec::new())
}

pub(crate) async fn grep(
    _base: &StdPath,
    _from: &StdPath,
    _query: &SearchQuery,
) -> Result<Vec<RawHit>> {
    Ok(Vec::new())
}

pub(crate) fn host() -> String {
    String::new()
}
