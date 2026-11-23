use std::path::PathBuf;

use unpatched_sources::SourceError;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// SQLite said no.
    #[error(
        "database error: {0}. If the file is damaged, run `unpatched db update` to fetch it again"
    )]
    Sqlite(#[from] rusqlite::Error),
    /// A file could not be read or written.
    #[error("{path}: {source}. Check that the path exists and you can write to it")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A source failed.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// Stored JSON could not be read (a damaged or hand-edited database).
    #[error("bad data in the database: {0}. Run `unpatched db update` to fetch it again")]
    Json(#[from] serde_json::Error),
    /// The database was made by a newer `unpatched`.
    #[error(
        "this database needs a newer unpatched (schema version {found}, this build reads up to {supported}); run `unpatched db update` after upgrading"
    )]
    NewerSchema { found: u32, supported: u32 },
    /// The file is not a database this program made.
    #[error(
        "{path} is not an unpatched database ({reason}). Run `unpatched db update` to download one"
    )]
    NotADatabase { path: PathBuf, reason: String },
    /// A source the database cannot do without failed, so nothing was written.
    #[error(
        "the {source_name} source failed, so no database was built (a broken database must never be published): {message}"
    )]
    RequiredSource {
        source_name: &'static str,
        message: String,
    },
    /// A download does not match its checksum.
    #[error(
        "checksum mismatch for {what}: expected {expected}, got {actual}. The release may still be publishing; try again in a few minutes"
    )]
    Checksum {
        what: String,
        expected: String,
        actual: String,
    },
    /// Anything else, with the next step in the message.
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

pub(crate) fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> DbError {
    let path = path.into();
    move |source| DbError::Io { path, source }
}
