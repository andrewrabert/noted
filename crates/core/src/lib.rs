mod call;
#[path = "fs/disk.rs"]
mod disk;
mod domain;
#[path = "fs/endpoint.rs"]
mod endpoint;
mod fragment;
pub mod oauth;
#[path = "fs/platform.rs"]
mod platform;
mod policy;
#[path = "fs/policy_store.rs"]
mod policy_store;
mod policyargs;
mod root;
mod timerange;

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

pub use call::{ToolCall, ToolListing};
pub use domain::{DirPath, LogPath, NotePath, TaskPath, TextPath};
pub use endpoint::Endpoint;
pub use error::{NotedError, Result};
pub use fragment::{AccessFragment, PolicyFragment};
pub use httpurl::HttpUrl;
pub use note::{Etag, LogNote, Note, TextNote, Trashed};
pub use policy::Access;
pub use policyargs::PolicyArgs;
pub use root::NotedRoot;
pub use store::NotedDir;
pub use tasks::TaskNote;
pub use timerange::{TimeRange, TimeRangeBound};
pub use types::Bearer;

pub const APP_NAME: &str = env!("CARGO_CRATE_NAME");
pub const APP_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), env!("VERSION_SUFFIX"));
