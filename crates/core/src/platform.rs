use std::pin::Pin;
use std::time::SystemTime;

#[cfg(not(target_arch = "wasm32"))]
mod system;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use system::{
    Lock, Router, create, crosses_symlink, entries, grep, host, ignored, read, relocate, rename,
    route, write,
};

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::{
    Lock, Router, create, crosses_symlink, entries, grep, host, ignored, read, relocate, rename,
    route, write,
};

pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    #[allow(dead_code)]
    pub(crate) modified: Option<SystemTime>,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait Threadsafe: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> Threadsafe for T {}
#[cfg(target_arch = "wasm32")]
pub(crate) trait Threadsafe {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> Threadsafe for T {}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
