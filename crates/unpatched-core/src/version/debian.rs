//! Debian package versions: `[epoch:]upstream[-revision]`, compared with the
//! algorithm from the Debian policy manual (section 5.6.12) and dpkg.
//! `~` sorts before everything, even the end of the string; letters sort
//! before other characters.

use std::cmp::Ordering;

use super::cmp_digits;

#[derive(Debug, Clone)]
pub(super) struct Debian {
    epoch: String,
    upstream: String,
    revision: String,
}

fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

/// dpkg's `verrevcmp`.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = order(a.get(i).copied());
            let bc = order(b.get(j).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        let si = i;
        while i < a.len() && a[i].is_ascii_digit() {
            i += 1;
        }
        let sj = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        // Numeric runs; an empty run counts as zero.
        let na = std::str::from_utf8(&a[si..i]).unwrap_or("");
        let nb = std::str::from_utf8(&b[sj..j]).unwrap_or("");
        match cmp_digits(na, nb) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    Ordering::Equal
}

impl Debian {
    fn cmp_inner(&self, other: &Self) -> Ordering {
        cmp_digits(&self.epoch, &other.epoch)
            .then_with(|| verrevcmp(&self.upstream, &other.upstream))
            .then_with(|| verrevcmp(&self.revision, &other.revision))
    }
}

impl PartialEq for Debian {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_inner(other) == Ordering::Equal
    }
}
impl Eq for Debian {}
impl PartialOrd for Debian {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Debian {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_inner(other)
    }
}

pub(super) fn parse(input: &str) -> Result<Debian, String> {
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
    let (upstream, revision) = match rest.rfind('-') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if upstream.is_empty() {
        return Err("the upstream part is empty".into());
    }
    if !upstream.starts_with(|c: char| c.is_ascii_digit()) {
        return Err("the upstream version must start with a digit".into());
    }
    let ok = |t: &str| {
        t.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'~' | b'-' | b':'))
    };
    if !ok(upstream) || !ok(revision) {
        return Err("only letters, digits and . + ~ - : are allowed".into());
    }
    if rest.contains('-') && revision.is_empty() {
        return Err("the revision after '-' is empty".into());
    }
    Ok(Debian {
        epoch: epoch.to_string(),
        upstream: upstream.to_string(),
        revision: revision.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use std::cmp::Ordering::{Equal, Greater, Less};

    fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
        Scheme::Debian.compare(a, b).unwrap()
    }

    #[test]
    fn epoch_wins() {
        assert_eq!(cmp("1:1.0", "2.0"), Greater);
        assert_eq!(cmp("0:1.0", "1.0"), Equal);
        assert_eq!(cmp("1:1.0", "1:2.0"), Less);
    }

    #[test]
    fn tilde_sorts_before_everything() {
        assert_eq!(cmp("1.0~rc1", "1.0"), Less);
        assert_eq!(cmp("1.0~~", "1.0~"), Less);
        assert_eq!(cmp("1.0~", "1.0"), Less);
        assert_eq!(cmp("1.0~rc1-1", "1.0-1"), Less);
        assert_eq!(cmp("1.0-1~bpo1", "1.0-1"), Less);
    }

    #[test]
    fn letters_before_non_letters() {
        assert_eq!(cmp("1.0a", "1.0+"), Less);
        assert_eq!(cmp("1.0a", "1.0."), Less);
        assert_eq!(cmp("1.0", "1.0a"), Less);
        assert_eq!(cmp("1.0+dfsg", "1.0"), Greater);
    }

    #[test]
    fn numbers_are_numeric() {
        assert_eq!(cmp("1.9", "1.10"), Less);
        assert_eq!(cmp("1.001", "1.1"), Equal);
        assert_eq!(cmp("1.0-9", "1.0-10"), Less);
    }

    #[test]
    fn revisions() {
        assert_eq!(cmp("3.0.11-1~deb12u1", "3.0.11-1~deb12u2"), Less);
        assert_eq!(cmp("3.0.11-1~deb12u2", "3.0.11-1"), Less);
        assert_eq!(cmp("3.0.11-1", "3.0.11-1+b1"), Less);
        assert_eq!(cmp("3.0.11", "3.0.11-1"), Less);
        assert_eq!(cmp("3.0.11-1~deb12u1", "3.0.12-1~deb12u1"), Less);
        // A missing revision is the same as revision 0.
        assert_eq!(cmp("1.0", "1.0-0"), Equal);
    }

    #[test]
    fn last_hyphen_splits_revision() {
        assert_eq!(cmp("1.0-1-2", "1.0-1-10"), Less);
        assert_eq!(cmp("1.0-1-2", "1.0-2-1"), Less);
    }

    #[test]
    fn dpkg_ordering_chain() {
        let sorted = [
            "1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a", "1.0+b1", "1.1", "1:0.1",
        ];
        for w in sorted.windows(2) {
            assert_eq!(cmp(w[0], w[1]), Less, "{} < {}", w[0], w[1]);
        }
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in ["", "a1.0", "x:1.0", ":1.0", "1.0-", "1.0 1", "1.0_1", "-1"] {
            assert!(Scheme::Debian.validate(bad).is_err(), "{bad:?}");
        }
    }
}
