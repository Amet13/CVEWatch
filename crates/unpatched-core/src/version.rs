//! Version parsing and comparison, one scheme per family of products.
//! See ADR-0004. Each scheme is a total order; a version that does not parse
//! is an error, and the caller turns it into an `unknown` verdict.

use std::cmp::Ordering;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Scheme {
    /// Numbers separated by dots, with an optional suffix (`7.2.5`, `15.4`, `2.4.58`).
    Dotted,
    /// Semantic Versioning 2.0 (pre-releases sort before releases).
    Semver,
    /// Calendar versions (`2024.10.1`); compared like dotted.
    Calver,
    /// dpkg rules (epoch, upstream, revision, `~`).
    Debian,
    /// rpmvercmp rules (epoch, version, release).
    Rpm,
    /// Alpine apk rules.
    Apk,
    /// Python PEP 440.
    Pep440,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot read {version:?} as a {scheme:?} version: {reason}")]
pub struct VersionError {
    pub scheme: Scheme,
    pub version: String,
    pub reason: String,
}

impl Scheme {
    /// Compare two versions under this scheme.
    pub fn compare(&self, a: &str, b: &str) -> Result<Ordering, VersionError> {
        let _ = (a, b);
        unimplemented!("version::Scheme::compare")
    }

    /// Check that a version parses under this scheme.
    pub fn validate(&self, v: &str) -> Result<(), VersionError> {
        self.compare(v, v).map(|_| ())
    }
}
