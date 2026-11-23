//! The `unpatched` SQLite database: build it from the sources, read it
//! (as a [`unpatched_core::Dataset`]), download it.
//!
//! See `PLAN.md` §4 and §16. The schema is in [`schema`]; a database with a
//! newer major `schema_version` than [`SCHEMA_VERSION`] is refused.

mod build;
mod check;
mod codec;
mod download;
mod error;
mod health;
mod paths;
mod read;
pub mod schema;

pub use build::{BuildOptions, BuildSummary, build};
pub use check::run_check;
pub use download::{DEFAULT_DB_URL, db_url, download};
pub use error::{DbError, Result};
pub use health::sources_health;
pub use paths::{cache_dir, default_db_path};
pub use read::Db;
pub use schema::SCHEMA_VERSION;
