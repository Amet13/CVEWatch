//! Pure logic for `unpatched`. No network, no files, no clock: callers pass
//! everything in, which keeps every verdict reproducible in tests.
//!
//! The types in [`model`], [`catalog`], [`config`] and [`report`] are the
//! contract between the crates. Change them deliberately.

pub mod catalog;
pub mod config;
pub mod matching;
pub mod model;
pub mod report;
pub mod rules;
pub mod version;

pub use catalog::{CatalogEntry, MatchKeys, ProductKind};
pub use config::Config;
pub use matching::{Dataset, evaluate};
pub use model::*;
pub use report::*;
pub use version::{Scheme, VersionError};
