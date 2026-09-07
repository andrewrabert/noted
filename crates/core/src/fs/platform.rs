use std::time::SystemTime;

#[cfg(not(target_arch = "wasm32"))]
#[path = "platform/system.rs"]
mod system;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use system::{
    Lock, create, crosses_symlink, entries, grep, host, ignored, read, relocate, rename, write,
};

#[cfg(target_arch = "wasm32")]
#[path = "platform/wasm.rs"]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::{
    Lock, create, crosses_symlink, entries, grep, host, ignored, read, relocate, rename, write,
};

pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    #[allow(dead_code)]
    pub(crate) modified: Option<SystemTime>,
}
