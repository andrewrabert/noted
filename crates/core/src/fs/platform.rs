#[cfg(not(target_arch = "wasm32"))]
#[path = "platform/system.rs"]
mod system;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use system::{Lock, create, exists, grep, host, read, relocate, rename, walk, write};

#[cfg(target_arch = "wasm32")]
#[path = "platform/wasm.rs"]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::{Lock, create, exists, grep, host, read, relocate, rename, walk, write};
