//! Alpine apk versions: `1.2.3a_rc1-r4`.
//!
//! Number parts, then an optional letter, then suffixes, then an optional
//! `-rN` package revision. Suffix order: `_alpha < _beta < _pre < _rc <
//! (none) < _cvs < _svn < _git < _hg < _p`.

use std::cmp::Ordering;
use std::sync::LazyLock;

use regex::Regex;

use super::cmp_digits;

static SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<nums>[0-9]+(?:\.[0-9]+)*)(?P<letter>[a-z])?(?P<suffixes>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*)(?:-r(?P<rev>[0-9]+))?$",
    )
    .expect("apk version regex is valid")
});

static SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)([0-9]*)").expect("suffix regex is valid")
});

/// Rank of a suffix; a missing suffix ranks 4 (between `_rc` and `_cvs`).
const NO_SUFFIX: u8 = 4;

fn suffix_rank(s: &str) -> u8 {
    match s {
        "alpha" => 0,
        "beta" => 1,
        "pre" => 2,
        "rc" => 3,
        "cvs" => 5,
        "svn" => 6,
        "git" => 7,
        "hg" => 8,
        _ => 9, // "p"
    }
}

#[derive(Debug, Clone)]
pub(super) struct Apk {
    /// Number parts without leading zeros.
    nums: Vec<String>,
    letter: Option<u8>,
    /// (rank, number without leading zeros)
    suffixes: Vec<(u8, String)>,
    revision: String,
}

fn cmp_num_lists(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        match cmp_digits(x, y) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    // The longer list is newer: 1.0 > 1
    a.len().cmp(&b.len())
}

impl Apk {
    fn cmp_inner(&self, other: &Self) -> Ordering {
        cmp_num_lists(&self.nums, &other.nums)
            .then_with(|| self.letter.cmp(&other.letter))
            .then_with(|| {
                let n = self.suffixes.len().max(other.suffixes.len());
                let none = (NO_SUFFIX, String::new());
                for i in 0..n {
                    let a = self.suffixes.get(i).unwrap_or(&none);
                    let b = other.suffixes.get(i).unwrap_or(&none);
                    let o = a.0.cmp(&b.0).then_with(|| cmp_digits(&a.1, &b.1));
                    if o != Ordering::Equal {
                        return o;
                    }
                }
                Ordering::Equal
            })
            .then_with(|| cmp_digits(&self.revision, &other.revision))
    }
}

impl PartialEq for Apk {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_inner(other) == Ordering::Equal
    }
}
impl Eq for Apk {}
impl PartialOrd for Apk {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Apk {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_inner(other)
    }
}

pub(super) fn parse(input: &str) -> Result<Apk, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("the version is empty".into());
    }
    let s = match s.strip_prefix('v') {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => s,
    };
    let caps = SHAPE.captures(s).ok_or_else(|| {
        "expected numbers like 1.2.3, an optional letter, optional suffixes (_rc1, _p2) and an optional -rN"
            .to_string()
    })?;
    let nums = caps["nums"]
        .split('.')
        .map(|n| n.trim_start_matches('0').to_string())
        .collect();
    let letter = caps.name("letter").map(|m| m.as_str().as_bytes()[0]);
    let suffixes = SUFFIX
        .captures_iter(&caps["suffixes"])
        .map(|c| (suffix_rank(&c[1]), c[2].trim_start_matches('0').to_string()))
        .collect();
    let revision = caps.name("rev").map_or(String::new(), |m| {
        m.as_str().trim_start_matches('0').to_string()
    });
    Ok(Apk {
        nums,
        letter,
        suffixes,
        revision,
    })
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use std::cmp::Ordering::{Equal, Greater, Less};

    fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
        Scheme::Apk.compare(a, b).unwrap()
    }

    #[test]
    fn suffix_order() {
        let order = [
            "1.0_alpha",
            "1.0_beta",
            "1.0_pre",
            "1.0_rc",
            "1.0",
            "1.0_cvs",
            "1.0_svn",
            "1.0_git",
            "1.0_hg",
            "1.0_p1",
        ];
        for w in order.windows(2) {
            assert_eq!(cmp(w[0], w[1]), Less, "{} < {}", w[0], w[1]);
        }
    }

    #[test]
    fn suffix_numbers() {
        assert_eq!(cmp("1.0_rc1", "1.0_rc2"), Less);
        assert_eq!(cmp("1.0_rc2", "1.0_rc10"), Less);
        assert_eq!(cmp("1.0_p1", "1.0_p2"), Less);
        assert_eq!(cmp("1.0_rc", "1.0_rc0"), Equal);
    }

    #[test]
    fn revisions() {
        assert_eq!(cmp("1.2.3-r0", "1.2.3"), Equal);
        assert_eq!(cmp("1.2.3-r1", "1.2.3-r2"), Less);
        assert_eq!(cmp("1.2.3-r9", "1.2.3-r10"), Less);
        assert_eq!(cmp("1.2.3-r10", "1.2.4-r0"), Less);
        assert_eq!(cmp("3.0.12-r0", "3.0.12-r1"), Less);
    }

    #[test]
    fn numbers_and_letters() {
        assert_eq!(cmp("1.9", "1.10"), Less);
        assert_eq!(cmp("1.0", "1"), Greater);
        assert_eq!(cmp("1.1.1", "1.1.1a"), Less);
        assert_eq!(cmp("1.1.1a", "1.1.1w"), Less);
        assert_eq!(cmp("1.1.1w", "1.1.2"), Less);
        assert_eq!(cmp("1.1.1w-r5", "1.1.1w_p1"), Less);
        assert_eq!(cmp("v1.2", "1.2"), Equal);
    }

    #[test]
    fn suffix_chain_with_revision() {
        assert_eq!(cmp("2.0_rc1-r3", "2.0"), Less);
        assert_eq!(cmp("2.0_p1_rc1", "2.0_p1"), Less);
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "", "abc", "1..2", "1.2_foo", "1.2-r", "1.2-rx", "1.2 3", "1.2_", "-r1",
        ] {
            assert!(Scheme::Apk.validate(bad).is_err(), "{bad:?}");
        }
    }
}
