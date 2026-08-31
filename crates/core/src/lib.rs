mod backend;
#[path = "fs/disk.rs"]
mod disk;
mod domain;
#[path = "fs/endpoint.rs"]
mod endpoint;
mod fragment;
#[path = "fs/platform.rs"]
mod platform;
mod policy;
mod policyargs;
#[path = "fs/regions.rs"]
mod regions;
mod root;
mod timerange;
mod upstream;

pub mod error;
pub mod front_matter;
pub mod httpurl;
pub mod newtype;
pub mod note;
pub mod search;
#[path = "fs/store.rs"]
pub mod store;
pub mod tasks;
pub mod tools;
pub mod types;
pub mod util;

pub use backend::{Backend, BackendArgs, ToolCall, ToolListing};
pub use domain::NotePath;
pub use endpoint::Endpoint;
pub use error::{NotedError, Result};
pub use fragment::{AccessFragment, PolicyFragment};
pub use httpurl::HttpUrl;
pub use note::{Etag, LogNote, Note, TextNote, Trashed};
pub use policy::{Access, RegionPolicy};
pub use policyargs::PolicyArgs;
pub use root::NotedRoot;
pub use store::NotedDir;
pub use tasks::TaskNote;
pub use timerange::{TimeRange, TimeRangeBound};
pub use types::Bearer;
pub use upstream::{Reply, Transport, Upstream};

pub const APP_NAME: &str = env!("CARGO_CRATE_NAME");
pub const APP_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), env!("VERSION_SUFFIX"));
