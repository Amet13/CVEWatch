//! Each scheme must be a total preorder on valid versions.

use std::cmp::Ordering;

use proptest::prelude::*;

use super::Scheme;

fn check(scheme: &Scheme, a: &str, b: &str, c: &str) -> Result<(), TestCaseError> {
    let cmp = |x: &str, y: &str| scheme.compare(x, y).expect("generated versions parse");
    prop_assert_eq!(cmp(a, a), Ordering::Equal);
    prop_assert_eq!(cmp(a, b), cmp(b, a).reverse());
    if cmp(a, b) != Ordering::Greater && cmp(b, c) != Ordering::Greater {
        prop_assert_ne!(cmp(a, c), Ordering::Greater, "{} {} {}", a, b, c);
    }
    if cmp(a, b) == Ordering::Equal && cmp(b, c) == Ordering::Equal {
        prop_assert_eq!(cmp(a, c), Ordering::Equal);
    }
    Ok(())
}

const DOTTED: &str = "v?[0-9]{1,3}(\\.[0-9]{1,3}){0,3}([a-z]|-rc[0-9]|-build[0-9]{1,4}|_beta)?";
const SEMVER: &str = "v?[0-9]{1,2}(\\.[0-9]{1,2}){0,3}(-(alpha|beta|[0-9]{1,2})(\\.[0-9a-z]{1,3}){0,2})?(\\+[a-z0-9]{1,4})?";
const DEBIAN: &str = "([0-9]:)?[0-9][0-9a-z.+~]{0,6}(-[0-9a-z.+~]{1,4})?";
const RPM: &str = "([0-9]:)?[0-9a-z][0-9a-z.~^_+]{0,7}(-[0-9a-z][0-9a-z.~^_]{0,4})?";
const APK: &str = "[0-9]{1,2}(\\.[0-9]{1,2}){0,3}[a-z]?(_(alpha|beta|pre|rc|p|git|hg)[0-9]{0,2}){0,2}(-r[0-9]{1,2})?";
const PEP440: &str = "([0-9]!)?[0-9]{1,2}(\\.[0-9]{1,2}){0,3}((a|b|rc)[0-9]{1,2})?(\\.post[0-9]{1,2})?(\\.dev[0-9]{1,2})?(\\+[a-z0-9]{1,3}(\\.[a-z0-9]{1,3})?)?";

proptest! {
    #[test]
    fn dotted_is_ordered(a in DOTTED, b in DOTTED, c in DOTTED) {
        check(&Scheme::Dotted, &a, &b, &c)?;
        check(&Scheme::Calver, &a, &b, &c)?;
    }

    #[test]
    fn semver_is_ordered(a in SEMVER, b in SEMVER, c in SEMVER) {
        check(&Scheme::Semver, &a, &b, &c)?;
    }

    #[test]
    fn debian_is_ordered(a in DEBIAN, b in DEBIAN, c in DEBIAN) {
        check(&Scheme::Debian, &a, &b, &c)?;
    }

    #[test]
    fn rpm_is_ordered(a in RPM, b in RPM, c in RPM) {
        check(&Scheme::Rpm, &a, &b, &c)?;
    }

    #[test]
    fn apk_is_ordered(a in APK, b in APK, c in APK) {
        check(&Scheme::Apk, &a, &b, &c)?;
    }

    #[test]
    fn pep440_is_ordered(a in PEP440, b in PEP440, c in PEP440) {
        check(&Scheme::Pep440, &a, &b, &c)?;
    }

    #[test]
    fn garbage_never_panics(s in "\\PC{0,20}") {
        for scheme in [
            Scheme::Dotted,
            Scheme::Semver,
            Scheme::Debian,
            Scheme::Rpm,
            Scheme::Apk,
            Scheme::Pep440,
        ] {
            let _ = scheme.compare(&s, "1.0");
        }
    }
}
