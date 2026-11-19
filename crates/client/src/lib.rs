//! Local and remote note clients, HTTP transport, and optional desktop authentication.

mod backend;
mod platform;
mod upstream;

#[cfg(not(target_arch = "wasm32"))]
pub use backend::NoteChanges;
pub use backend::{Backend, BackendArgs};
#[cfg(not(target_arch = "wasm32"))]
pub use upstream::{ByteStream, Streamed};
pub use upstream::{Reply, Transport, Upstream, oauth};

#[cfg(feature = "desktop")]
pub mod admin;
#[cfg(feature = "desktop")]
pub mod authclient;
#[cfg(feature = "desktop")]
pub mod credentials;
