//! Local and remote note clients, HTTP transport, and optional desktop authentication.

mod backend;
mod platform;
mod upstream;

pub use backend::{Backend, BackendArgs};
pub use upstream::{Reply, Transport, Upstream, oauth};

#[cfg(feature = "desktop")]
pub mod admin;
#[cfg(feature = "desktop")]
pub mod authclient;
#[cfg(feature = "desktop")]
pub mod credentials;
