//! Checking one [`Constraint`] against a version.

use std::cmp::Ordering;

use crate::model::{Bound, Constraint};
use crate::version::{Scheme, VersionError};

/// Does `version` fall inside `constraint` under `scheme`?
///
/// A bound that cannot be parsed, or a version that cannot be parsed, is an
/// error: the caller turns it into an `unknown` verdict.
///
/// For Debian and RPM versions, a bound without a revision (`1.2.3` rather
/// than `1.2.3-4`) is compared against the upstream version only. Upstream
/// advisories say "before 1.2.3" and mean every build of 1.2.3 is fixed.
pub fn constraint_matches(
    scheme: &Scheme,
    constraint: &Constraint,
    version: &str,
) -> Result<bool, VersionError> {
    match constraint {
        Constraint::All => {
            scheme.validate(version)?;
            Ok(true)
        }
        Constraint::Exact { version: v } => {
            Ok(cmp_to_bound(scheme, version, v)? == Ordering::Equal)
        }
        Constraint::Range { start, end } => {
            // Validate even when both ends are open.
            scheme.validate(version)?;
            if let Some(Bound {
                version: s,
                inclusive,
            }) = start
            {
                let o = cmp_to_bound(scheme, version, s)?;
                let ok = if *inclusive {
                    o != Ordering::Less
                } else {
                    o == Ordering::Greater
                };
                if !ok {
                    return Ok(false);
                }
            }
            if let Some(Bound {
                version: e,
                inclusive,
            }) = end
            {
                let o = cmp_to_bound(scheme, version, e)?;
                let ok = if *inclusive {
                    o != Ordering::Greater
                } else {
                    o == Ordering::Less
                };
                if !ok {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

/// Compare an item version with a bound, as described on [`constraint_matches`].
pub(crate) fn cmp_to_bound(
    scheme: &Scheme,
    version: &str,
    bound: &str,
) -> Result<Ordering, VersionError> {
    match scheme {
        Scheme::Debian | Scheme::Rpm if !bound.contains('-') => {
            let upstream = version.rfind('-').map_or(version, |i| &version[..i]);
            // Validate the full text too, so garbage never slips through.
            scheme.validate(version)?;
            scheme.compare(upstream, bound)
        }
        Scheme::Dotted | Scheme::Calver if is_portable_release_of(version, bound) => {
            scheme.validate(version)?;
            Ok(Ordering::Equal)
        }
        _ => scheme.compare(version, bound),
    }
}

/// True for `9.8p1` against the bound `9.8`.
///
/// OpenSSH has no release `9.8`, only `9.8p1` (the portable release), yet
/// advisories and NVD write "up to and including 9.8". A `p<number>` suffix
/// directly after the bound's text is the same release for a bound check, so
/// `<= 9.8` includes 9.8p1 and `< 9.8` does not. A bound that already has its
/// own suffix (`9.8p2`) is compared as it is.
fn is_portable_release_of(version: &str, bound: &str) -> bool {
    let v = version.trim();
    let b = bound.trim();
    if !b.ends_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let Some(rest) = v.get(b.len()..) else {
        return false;
    };
    if !v.is_char_boundary(b.len()) || !v[..b.len()].eq_ignore_ascii_case(b) {
        return false;
    }
    rest.strip_prefix(['p', 'P'])
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: Option<(&str, bool)>, end: Option<(&str, bool)>) -> Constraint {
        let b = |(v, inclusive): (&str, bool)| Bound {
            version: v.to_string(),
            inclusive,
        };
        Constraint::Range {
            start: start.map(b),
            end: end.map(b),
        }
    }

    #[test]
    fn all_and_exact() {
        let d = Scheme::Dotted;
        assert!(constraint_matches(&d, &Constraint::All, "1.0").unwrap());
        assert!(constraint_matches(&d, &Constraint::All, "nope").is_err());
        let exact = Constraint::Exact {
            version: "7.2".into(),
        };
        assert!(constraint_matches(&d, &exact, "7.2.0").unwrap());
        assert!(!constraint_matches(&d, &exact, "7.2.1").unwrap());
    }

    #[test]
    fn range_edges() {
        let d = Scheme::Dotted;
        let r = range(Some(("7.2.0", true)), Some(("7.2.6", false)));
        for (v, want) in [
            ("7.1.9", false),
            ("7.2.0", true),
            ("7.2.5", true),
            ("7.2.6", false),
            ("7.3", false),
        ] {
            assert_eq!(constraint_matches(&d, &r, v).unwrap(), want, "{v}");
        }
        let r = range(Some(("1.0", false)), Some(("2.0", true)));
        assert!(!constraint_matches(&d, &r, "1.0").unwrap());
        assert!(constraint_matches(&d, &r, "2.0").unwrap());
        assert!(!constraint_matches(&d, &r, "2.0.1").unwrap());
    }

    #[test]
    fn open_ends() {
        let d = Scheme::Dotted;
        let below = range(None, Some(("3.0", false)));
        assert!(constraint_matches(&d, &below, "2.9").unwrap());
        assert!(!constraint_matches(&d, &below, "3.0").unwrap());
        let above = range(Some(("3.0", true)), None);
        assert!(constraint_matches(&d, &above, "99").unwrap());
        assert!(constraint_matches(&d, &range(None, None), "1.0").unwrap());
        assert!(constraint_matches(&d, &range(None, None), "x").is_err());
    }

    #[test]
    fn unparseable_bound_is_an_error() {
        let r = range(None, Some(("garbage", false)));
        let e = constraint_matches(&Scheme::Semver, &r, "1.0.0").unwrap_err();
        assert_eq!(e.version, "garbage");
    }

    #[test]
    fn revisionless_bounds_compare_upstream_only() {
        let r = range(None, Some(("3.0.11", true)));
        assert!(constraint_matches(&Scheme::Debian, &r, "3.0.11-1~deb12u1").unwrap());
        assert!(!constraint_matches(&Scheme::Debian, &r, "3.0.12-1").unwrap());
        let r = range(None, Some(("3.0.11-2", false)));
        assert!(constraint_matches(&Scheme::Debian, &r, "3.0.11-1").unwrap());
        assert!(!constraint_matches(&Scheme::Debian, &r, "3.0.11-2").unwrap());
        let r = range(None, Some(("3.0.7", false)));
        assert!(!constraint_matches(&Scheme::Rpm, &r, "3.0.7-27.el9").unwrap());
        assert!(constraint_matches(&Scheme::Rpm, &r, "3.0.6-27.el9").unwrap());
    }

    #[test]
    fn semver_prerelease_ranges() {
        let r = range(Some(("1.0.0", true)), Some(("1.2.0", false)));
        assert!(!constraint_matches(&Scheme::Semver, &r, "1.0.0-rc.1").unwrap());
        assert!(constraint_matches(&Scheme::Semver, &r, "1.1").unwrap());
    }
}
