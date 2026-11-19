#[cfg(not(target_arch = "wasm32"))]
#[path = "platform/system.rs"]
mod system;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use system::{
    Changes, Lock, Watcher, create, grep, host, present, read, relocate, rename, walk, watcher,
    write,
};

#[cfg(target_arch = "wasm32")]
#[path = "platform/wasm.rs"]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::{
    Changes, Lock, Watcher, create, grep, host, present, read, relocate, rename, walk, watcher,
    write,
};
