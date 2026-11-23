//! RPM versions: `[epoch:]version[-release]`, compared with `rpmvercmp`
//! (including `~` for pre-releases and `^` for post-release snapshots).

use std::cmp::Ordering;

use super::cmp_digits;

#[derive(Debug, Clone)]
pub(super) struct Rpm {
    epoch: String,
    version: String,
    release: String,
}

/// A port of `rpmvercmp` from rpm's `rpmvercmp.c`.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let a = a.as_bytes();
    let b = b.as_bytes();
    let (mut i, mut j) = (0, 0);
    let sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    while i < a.len() || j < b.len() {
        while i < a.len() && sep(a[i]) {
            i += 1;
        }
        while j < b.len() && sep(b[j]) {
            j += 1;
        }
        let ta = a.get(i) == Some(&b'~');
        let tb = b.get(j) == Some(&b'~');
        if ta || tb {
            if !ta {
                return Ordering::Greater;
            }
            if !tb {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        let ca = a.get(i) == Some(&b'^');
        let cb = b.get(j) == Some(&b'^');
        if ca || cb {
            if i >= a.len() {
                return Ordering::Less;
            }
            if j >= b.len() {
                return Ordering::Greater;
            }
            if !ca {
                return Ordering::Greater;
            }
            if !cb {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        let numeric = a[i].is_ascii_digit();
        let si = i;
        let sj = j;
        if numeric {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
        }
        let sa = std::str::from_utf8(&a[si..i]).unwrap_or("");
        let sb = std::str::from_utf8(&b[sj..j]).unwrap_or("");
        if sb.is_empty() {
            // Different kinds of segment: numbers are newer than letters.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let o = if numeric {
            cmp_digits(sa, sb)
        } else {
            sa.cmp(sb)
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, _) => Ordering::Greater,
    }
}

impl Rpm {
    fn cmp_inner(&self, other: &Self) -> Ordering {
        cmp_digits(&self.epoch, &other.epoch)
            .then_with(|| rpmvercmp(&self.version, &other.version))
            .then_with(|| rpmvercmp(&self.release, &other.release))
    }
}

impl PartialEq for Rpm {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_inner(other) == Ordering::Equal
    }
}
impl Eq for Rpm {}
impl PartialOrd for Rpm {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Rpm {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_inner(other)
    }
}

pub(super) fn parse(input: &str) -> Result<Rpm, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("the version is empty".into());
    }
    let (epoch, rest) = match s.split_once(':') {
        Some((e, r)) => {
            if e.is_empty() || !e.bytes().all(|c| c.is_ascii_digit()) {
                return Err("the epoch before ':' must be a number".into());
            }
            (e, r)
        }
        None => ("0", s),
    };
    let (version, release) = match rest.rfind('-') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if version.is_empty() || !version.bytes().any(|c| c.is_ascii_alphanumeric()) {
        return Err("the version part needs at least one letter or digit".into());
    }
    if rest.contains('-') && release.is_empty() {
        return Err("the release after '-' is empty".into());
    }
    let ok = |t: &str| {
        t.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'~' | b'^'))
    };
    if !ok(version) || !ok(release) {
        return Err("only letters, digits and . _ + ~ ^ are allowed".into());
    }
    Ok(Rpm {
        epoch: epoch.to_string(),
        version: version.to_string(),
        release: release.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use super::rpmvercmp;
    use std::cmp::Ordering::{Equal, Greater, Less};

    fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
        Scheme::Rpm.compare(a, b).unwrap()
    }

    #[test]
    fn rpmvercmp_test_suite() {
        // From rpm's tests/rpmvercmp.at.
        let cases = [
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0", "1.0", Greater),
            ("2.0.1", "2.0.1", Equal),
            ("2.0", "2.0.1", Less),
            ("2.0.1", "2.0", Greater),
            ("2.0.1a", "2.0.1a", Equal),
            ("2.0.1a", "2.0.1", Greater),
            ("2.0.1", "2.0.1a", Less),
            ("5.5p1", "5.5p1", Equal),
            ("5.5p1", "5.5p2", Less),
            ("5.5p2", "5.5p1", Greater),
            ("5.5p10", "5.5p10", Equal),
            ("5.5p1", "5.5p10", Less),
            ("5.5p10", "5.5p1", Greater),
            ("10xyz", "10.1xyz", Less),
            ("10.1xyz", "10xyz", Greater),
            ("xyz10", "xyz10", Equal),
            ("xyz10", "xyz10.1", Less),
            ("xyz10.1", "xyz10", Greater),
            ("xyz.4", "xyz.4", Equal),
            ("xyz.4", "8", Less),
            ("8", "xyz.4", Greater),
            ("xyz.4", "2", Less),
            ("2", "xyz.4", Greater),
            ("5.5p2", "5.6p1", Less),
            ("5.6p1", "5.5p2", Greater),
            ("5.6p1", "6.5p1", Less),
            ("6.5p1", "5.6p1", Greater),
            ("6.0.rc1", "6.0", Greater),
            ("6.0", "6.0.rc1", Less),
            ("10b2", "10a1", Greater),
            ("10a2", "10b2", Less),
            ("1.0aa", "1.0aa", Equal),
            ("1.0a", "1.0aa", Less),
            ("1.0aa", "1.0a", Greater),
            ("10.0001", "10.0001", Equal),
            ("10.0001", "10.1", Equal),
            ("10.1", "10.0001", Equal),
            ("10.0001", "10.0039", Less),
            ("10.0039", "10.0001", Greater),
            ("4.999.9", "5.0", Less),
            ("5.0", "4.999.9", Greater),
            ("20101121", "20101121", Equal),
            ("20101121", "20101122", Less),
            ("20101122", "20101121", Greater),
            ("2_0", "2_0", Equal),
            ("2.0", "2_0", Equal),
            ("2_0", "2.0", Equal),
            ("a", "a", Equal),
            ("a+", "a+", Equal),
            ("a+", "a_", Equal),
            ("a_", "a+", Equal),
            ("+a", "+a", Equal),
            ("+a", "_a", Equal),
            ("_a", "+a", Equal),
            ("+_", "+_", Equal),
            ("_+", "+_", Equal),
            ("_+", "_+", Equal),
            ("+", "_", Equal),
            ("_", "+", Equal),
            ("1.0~rc1", "1.0~rc1", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0", "1.0~rc1", Greater),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~rc2", "1.0~rc1", Greater),
            ("1.0~rc1~git123", "1.0~rc1~git123", Equal),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0~rc1", "1.0~rc1~git123", Greater),
            ("1.0^", "1.0^", Equal),
            ("1.0^", "1.0", Greater),
            ("1.0", "1.0^", Less),
            ("1.0^git1", "1.0^git1", Equal),
            ("1.0^git1", "1.0", Greater),
            ("1.0", "1.0^git1", Less),
            ("1.0^git1", "1.0^git2", Less),
            ("1.0^git2", "1.0^git1", Greater),
            ("1.0^git1", "1.01", Less),
            ("1.01", "1.0^git1", Greater),
            ("1.0^20160101", "1.0^20160101", Equal),
            ("1.0^20160101", "1.0.1", Less),
            ("1.0.1", "1.0^20160101", Greater),
            ("1.0^20160101^git1", "1.0^20160101^git1", Equal),
            ("1.0^20160102", "1.0^20160101^git1", Greater),
            ("1.0^20160101^git1", "1.0^20160102", Less),
            ("1.0~rc1^git1", "1.0~rc1^git1", Equal),
            ("1.0~rc1^git1", "1.0~rc1", Greater),
            ("1.0~rc1", "1.0~rc1^git1", Less),
            ("1.0^git1~pre", "1.0^git1~pre", Equal),
            ("1.0^git1", "1.0^git1~pre", Greater),
            ("1.0^git1~pre", "1.0^git1", Less),
        ];
        for (a, b, want) in cases {
            assert_eq!(rpmvercmp(a, b), want, "rpmvercmp({a:?}, {b:?})");
        }
    }

    #[test]
    fn epoch_version_release() {
        assert_eq!(cmp("1:1.0-1", "2.0-1"), Greater);
        assert_eq!(cmp("0:1.0-1", "1.0-1"), Equal);
        assert_eq!(cmp("1.0-1.el9", "1.0-2.el9"), Less);
        assert_eq!(cmp("3.0.7-27.el9", "3.0.7-28.el9"), Less);
        assert_eq!(cmp("3.0.7-27.el9", "3.0.8-1.el9"), Less);
        assert_eq!(cmp("1.0-1.el9_3.1", "1.0-1.el9_3.2"), Less);
        assert_eq!(cmp("1.0", "1.0-1"), Less);
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in ["", "-", "~", "1.0 1", "x:1.0", "1.0-", "1.0/2"] {
            assert!(Scheme::Rpm.validate(bad).is_err(), "{bad:?}");
        }
    }
}
