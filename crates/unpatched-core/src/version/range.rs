//! Checking one [`Constraint`] against a version.

use std::cmp::Ordering;

use crate::model::{Bound, Constraint};
use crate::version::{Scheme, VersionError, cmp_digits};

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
            portable_release_is_ambiguous(scheme, version, v)?;
            Ok(cmp_to_bound(scheme, version, v)? == Ordering::Equal)
        }
        Constraint::Unplaced {
            version: base,
            update,
        } => {
            scheme.validate(version)?;
            if unplaced_is_elsewhere(version, base) {
                Ok(false)
            } else {
                Err(VersionError {
                    scheme: scheme.clone(),
                    version: format!("{base}:{update}"),
                    reason: format!(
                        "the update {update:?} of release {base} cannot be placed in the version order"
                    ),
                })
            }
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
                if *inclusive {
                    portable_release_is_ambiguous(scheme, version, e)?;
                }
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

/// Can `version` not be the release `base` plus some update?
///
/// An update such as `update2` follows its release (`8.0` and `update2` is
/// 8.0.2), so only a version that clearly belongs to another release is ruled
/// out: both start with a number of the same kind, and `base` is not the start
/// of `version`. A first number of four or more digits is a year or a name
/// (`2019`), shorter ones are release numbers (`9`, `22`). When the kinds
/// differ (build 15.2.1544 against the name `2019`), nothing can be said.
fn unplaced_is_elsewhere(version: &str, base: &str) -> bool {
    let parts = |s: &'_ str| -> Vec<String> {
        s.trim()
            .split(['.', '-', '_', '+'])
            .map(|p| {
                p.bytes()
                    .take_while(u8::is_ascii_digit)
                    .map(char::from)
                    .collect()
            })
            .collect()
    };
    let (v, b) = (parts(version), parts(base));
    let (Some(v0), Some(b0)) = (v.first(), b.first()) else {
        return false;
    };
    if v0.is_empty() || b0.is_empty() || (v0.len() >= 4) != (b0.len() >= 4) {
        return false;
    }
    b.iter().enumerate().any(|(i, bp)| {
        !bp.is_empty()
            && v.get(i)
                .is_some_and(|vp| !vp.is_empty() && cmp_digits(vp, bp).is_ne())
    })
}

/// `9.8p1` against "up to and including 9.8" (or exactly `9.8`) cannot be
/// decided: for OpenSSH the first portable release of 9.8 *is* the fix for
/// CVE-2024-6387, while other advisories mean every 9.8pN. Saying `affected`
/// would raise a false alarm on a patched system, and saying `not-affected`
/// needs evidence, so the source's verdict is `unknown` and the reason says why.
fn portable_release_is_ambiguous(
    scheme: &Scheme,
    version: &str,
    bound: &str,
) -> Result<(), VersionError> {
    if matches!(scheme, Scheme::Dotted | Scheme::Calver) && is_portable_release_of(version, bound) {
        return Err(VersionError {
            scheme: scheme.clone(),
            version: bound.to_string(),
            reason: format!(
                "the data says \"up to {bound}\" and it is not clear whether {version} (a release of {bound}) is included"
            ),
        });
    }
    Ok(())
}

/// True for `9.8p1` against the bound `9.8`.
///
/// OpenSSH has no release `9.8`, only `9.8p1` (the portable release). A
/// `p<number>` suffix directly after the bound's text is the same release for a
/// bound check: `>= 8.6` includes 8.6p1 and `< 9.8` does not include 9.8p1.
/// Inclusive ends and exact matches are ambiguous (see above). A bound that already has its
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
    fn unplaced_updates_are_unknown_unless_clearly_elsewhere() {
        let d = Scheme::Dotted;
        let u = |v: &str, up: &str| Constraint::Unplaced {
            version: v.into(),
            update: up.into(),
        };
        // 8.0 + update2 may be 8.0.2: cannot say.
        let e = constraint_matches(&d, &u("8.0", "update2"), "8.0.2").unwrap_err();
        assert!(e.to_string().contains("8.0:update2"), "{e}");
        assert!(constraint_matches(&d, &u("8.0", "update2"), "8.0").is_err());
        // Another release of the same width: not matched.
        assert!(!constraint_matches(&d, &u("7.0", "update3o"), "8.0.2").unwrap());
        assert!(!constraint_matches(&d, &u("8.1", "update1"), "8.0.2").unwrap());
        assert!(!constraint_matches(&d, &u("2.8.4", "a"), "6.4.1").unwrap());
        assert!(!constraint_matches(&d, &u("9.0", "rx"), "22.7R2").unwrap());
        // A name against a build number (Exchange 2019 against 15.2.1544.4): cannot say.
        assert!(constraint_matches(&d, &u("2019", "cumulative_update_14"), "15.2.1544.4").is_err());
        // A version that does not parse is still an error.
        assert!(constraint_matches(&d, &u("8.0", "update2"), "nope").is_err());
    }

    #[test]
    fn portable_release_suffix_matches_the_bound() {
        // OpenSSH has no 9.8, only 9.8p1; "up to and including 9.8" includes it.
        let d = Scheme::Dotted;
        let upto = range(Some(("8.6", true)), Some(("9.8", true)));
        // 9.8p1 against "up to and including 9.8": cannot be decided (unknown).
        let e = constraint_matches(&d, &upto, "9.8p1").unwrap_err();
        assert!(e.reason.contains("not clear"), "{e}");
        assert!(
            constraint_matches(
                &d,
                &Constraint::Exact {
                    version: "9.8".into()
                },
                "9.8p1"
            )
            .is_err()
        );
        assert!(constraint_matches(&d, &upto, "9.7p1").unwrap());
        assert!(!constraint_matches(&d, &upto, "9.9p1").unwrap());
        // `< 9.8` does not include 9.8p1, and `>= 8.6` does include 8.6p1.
        let before = range(None, Some(("9.8", false)));
        assert!(!constraint_matches(&d, &before, "9.8p1").unwrap());
        assert!(constraint_matches(&d, &before, "9.7p2").unwrap());
        assert!(constraint_matches(&d, &range(Some(("8.6", true)), None), "8.6p1").unwrap());
        // A bound with its own suffix, or a plain letter suffix, is compared as written.
        let p2 = range(None, Some(("9.8p2", true)));
        assert!(constraint_matches(&d, &p2, "9.8p1").unwrap());
        assert!(!constraint_matches(&d, &p2, "9.8p3").unwrap());
        let openssl = range(None, Some(("1.1.1", true)));
        assert!(!constraint_matches(&d, &openssl, "1.1.1w").unwrap());
        assert!(!constraint_matches(&d, &openssl, "1.1.1p").unwrap());
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
