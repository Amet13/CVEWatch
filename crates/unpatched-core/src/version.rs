//! Version parsing and comparison, one scheme per family of products.
//! See ADR-0004. Each scheme is a total order; a version that does not parse
//! is an error, and the caller turns it into an `unknown` verdict.

#![allow(clippy::many_single_char_names)]

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
    /// Synology DSM: `major.minor[.patch]-build[-update]` (`7.2.1-69057-5`).
    Synology,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot read {version:?} as a {scheme:?} version: {reason}")]
pub struct VersionError {
    pub scheme: Scheme,
    pub version: String,
    pub reason: String,
}

mod apk;
mod debian;
mod dotted;
mod pep440;
#[cfg(test)]
mod props;
mod range;
mod rpm;
mod semver;
mod synology;

pub use range::constraint_matches;

/// Compare two strings of ASCII digits as numbers of any size.
pub(crate) fn cmp_digits(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

impl Scheme {
    /// Compare two versions under this scheme.
    pub fn compare(&self, a: &str, b: &str) -> Result<Ordering, VersionError> {
        let err = |v: &str, reason: String| VersionError {
            scheme: self.clone(),
            version: v.to_string(),
            reason,
        };
        match self {
            Scheme::Dotted | Scheme::Calver => {
                let pa = dotted::parse(a).map_err(|r| err(a, r))?;
                let pb = dotted::parse(b).map_err(|r| err(b, r))?;
                Ok(pa.cmp(&pb))
            }
            Scheme::Semver => {
                let pa = semver::parse(a).map_err(|r| err(a, r))?;
                let pb = semver::parse(b).map_err(|r| err(b, r))?;
                Ok(pa.cmp(&pb))
            }
            Scheme::Debian => {
                let pa = debian::parse(a).map_err(|r| err(a, r))?;
                let pb = debian::parse(b).map_err(|r| err(b, r))?;
                Ok(pa.cmp(&pb))
            }
            Scheme::Rpm => {
                let pa = rpm::parse(a).map_err(|r| err(a, r))?;
                let pb = rpm::parse(b).map_err(|r| err(b, r))?;
                Ok(pa.cmp(&pb))
            }
            Scheme::Apk => {
                let pa = apk::parse(a).map_err(|r| err(a, r))?;
                let pb = apk::parse(b).map_err(|r| err(b, r))?;
                Ok(pa.cmp(&pb))
            }
            Scheme::Pep440 => {
                let pa = pep440::parse(a).map_err(|r| err(a, r))?;
                let pb = pep440::parse(b).map_err(|r| err(b, r))?;
                Ok(pa.cmp(&pb))
            }
            Scheme::Synology => {
                let pa = synology::parse(a).map_err(|r| err(a, r))?;
                let pb = synology::parse(b).map_err(|r| err(b, r))?;
                Ok(pa.cmp(&pb))
            }
        }
    }

    /// Check that a version parses under this scheme.
    pub fn validate(&self, v: &str) -> Result<(), VersionError> {
        self.compare(v, v).map(|_| ())
    }

    /// The scheme to use for a package URL type (`deb`, `npm`, ...).
    /// `ecosystem_hint` (for example the purl namespace `debian` or `alpine`)
    /// only matters for generic types.
    pub fn for_purl_type(purl_type: &str, ecosystem_hint: Option<&str>) -> Scheme {
        match purl_type.to_ascii_lowercase().as_str() {
            "deb" => Scheme::Debian,
            "rpm" => Scheme::Rpm,
            "apk" => Scheme::Apk,
            "pypi" => Scheme::Pep440,
            "npm" | "cargo" | "golang" | "gem" | "composer" | "nuget" | "maven" | "hex" => {
                Scheme::Semver
            }
            _ => match ecosystem_hint.map(str::to_ascii_lowercase).as_deref() {
                Some("debian" | "ubuntu") => Scheme::Debian,
                Some("alpine") => Scheme::Apk,
                Some(
                    "rhel" | "redhat" | "centos" | "fedora" | "rocky" | "almalinux" | "alma"
                    | "suse" | "opensuse" | "amazon" | "oracle",
                ) => Scheme::Rpm,
                Some("pypi") => Scheme::Pep440,
                _ => Scheme::Dotted,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_types_map_to_schemes() {
        assert_eq!(Scheme::for_purl_type("deb", None), Scheme::Debian);
        assert_eq!(Scheme::for_purl_type("rpm", None), Scheme::Rpm);
        assert_eq!(Scheme::for_purl_type("apk", None), Scheme::Apk);
        assert_eq!(Scheme::for_purl_type("pypi", None), Scheme::Pep440);
        for t in [
            "npm", "cargo", "golang", "gem", "composer", "nuget", "maven", "hex",
        ] {
            assert_eq!(Scheme::for_purl_type(t, None), Scheme::Semver, "{t}");
        }
        assert_eq!(Scheme::for_purl_type("generic", None), Scheme::Dotted);
        assert_eq!(
            Scheme::for_purl_type("generic", Some("Alpine")),
            Scheme::Apk
        );
        assert_eq!(Scheme::for_purl_type("DEB", None), Scheme::Debian);
    }

    #[test]
    fn cmp_digits_handles_big_numbers() {
        assert_eq!(cmp_digits("007", "7"), Ordering::Equal);
        assert_eq!(
            cmp_digits("99999999999999999999999", "100000000000000000000000"),
            Ordering::Less
        );
    }

    #[test]
    fn errors_name_the_version_and_scheme() {
        let e = Scheme::Semver.compare("1.2.3", "nope").unwrap_err();
        assert_eq!(e.version, "nope");
        assert_eq!(e.scheme, Scheme::Semver);
        assert!(Scheme::Dotted.validate("").is_err());
    }
}
