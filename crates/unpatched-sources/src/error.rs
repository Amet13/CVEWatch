//! Errors for every source. Each message says what to do next.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The request never got an answer (DNS, TLS, timeout, reset).
    #[error("could not reach {url}: {source}. Check your network connection and try again")]
    Network {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    /// The server kept answering with an error status.
    #[error(
        "{url} answered HTTP {status} (after {attempts} attempts). Try again later, or check the service status page"
    )]
    Status {
        url: String,
        status: u16,
        attempts: u32,
    },
    /// The data did not look like the format we expect.
    #[error(
        "could not read {what}: {message}. The source may have changed its format; update unpatched or report a bug"
    )]
    Parse { what: String, message: String },
    /// A downloaded file does not match its published checksum.
    #[error(
        "checksum mismatch for {what}: expected {expected}, got {actual}. The download is corrupt or still being published; run it again"
    )]
    Checksum {
        what: String,
        expected: String,
        actual: String,
    },
    /// A package URL could not be used.
    #[error(
        "invalid package URL {purl:?}: {reason}. Write it as pkg:<type>/<namespace>/<name>@<version>"
    )]
    Purl { purl: String, reason: String },
    /// A file or directory could not be read.
    #[error("could not read {path}: {source}. Check that the path exists and is readable")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The caller asked for something that does not exist.
    #[error("{what} not found. Check the id and try again")]
    NotFound { what: String },
}

impl SourceError {
    pub(crate) fn parse(what: impl Into<String>, message: impl std::fmt::Display) -> Self {
        Self::Parse {
            what: what.into(),
            message: message.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, SourceError>;
