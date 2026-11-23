//! Dotted versions: `7.2.5`, `2.4.58a`, `8.0.1-build1234`, `1.1.1w`,
//! `10.0.19045.3803`. Also used for calendar versions.
//!
//! A version is a list of components. Components are runs of digits, runs of
//! letters, or one of a few pre-release words (`rc`, `beta`, ...). Missing
//! components count as `0`, so `7.2` equals `7.2.0`. A letter suffix sorts
//! after the plain number (`1.1.1 < 1.1.1a < 1.1.1w < 1.1.2`); a pre-release
//! word sorts before it (`1.0-rc1 < 1.0`).

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Comp {
    /// Pre-release word, by rank.
    Pre(u8),
    /// Number without leading zeros: (length, digits).
    Num(usize, String),
    Alpha(String),
}

impl Comp {
    fn zero() -> Comp {
        Comp::Num(0, String::new())
    }
}

#[derive(Debug, Clone)]
pub(super) struct Dotted(Vec<Comp>);

impl Dotted {
    fn cmp_inner(&self, other: &Self) -> Ordering {
        let zero = Comp::zero();
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let a = self.0.get(i).unwrap_or(&zero);
            let b = other.0.get(i).unwrap_or(&zero);
            match a.cmp(b) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl PartialEq for Dotted {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_inner(other) == Ordering::Equal
    }
}
impl Eq for Dotted {}
impl PartialOrd for Dotted {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Dotted {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_inner(other)
    }
}

fn pre_rank(word: &str) -> Option<u8> {
    match word {
        "dev" | "snapshot" | "nightly" => Some(0),
        "alpha" => Some(1),
        "beta" => Some(2),
        "pre" | "preview" => Some(3),
        "rc" => Some(4),
        _ => None,
    }
}

pub(super) fn parse(input: &str) -> Result<Dotted, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("the version is empty".into());
    }
    let s = match s.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => s,
    };
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        return Err("a version must start with a digit".into());
    }
    let mut comps = Vec::new();
    for seg in s.split(['.', '-', '_', '+']) {
        if seg.is_empty() {
            return Err("empty component (two separators in a row, or one at the end)".into());
        }
        let bytes = seg.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let digit = bytes[i].is_ascii_digit();
            if !digit && !bytes[i].is_ascii_alphabetic() {
                return Err(format!("unexpected character {:?}", bytes[i] as char));
            }
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit() || bytes[i].is_ascii_alphabetic())
                && bytes[i].is_ascii_digit() == digit
            {
                i += 1;
            }
            let run = &seg[start..i];
            if digit {
                let t = run.trim_start_matches('0');
                comps.push(Comp::Num(t.len(), t.to_string()));
            } else {
                let lower = run.to_ascii_lowercase();
                match pre_rank(&lower) {
                    Some(r) => comps.push(Comp::Pre(r)),
                    None => comps.push(Comp::Alpha(lower)),
                }
            }
        }
    }
    Ok(Dotted(comps))
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use std::cmp::Ordering::{Equal, Greater, Less};

    fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
        Scheme::Dotted.compare(a, b).unwrap()
    }

    #[test]
    fn plain_numbers() {
        assert_eq!(cmp("7.2.5", "7.2.5"), Equal);
        assert_eq!(cmp("7.2.5", "7.2.10"), Less);
        assert_eq!(cmp("10.0.19045.3803", "10.0.19045.3693"), Greater);
        assert_eq!(cmp("15.4", "15.10"), Less);
    }

    #[test]
    fn trailing_zeros_are_equal() {
        assert_eq!(cmp("7.2", "7.2.0"), Equal);
        assert_eq!(cmp("7", "7.0.0.0"), Equal);
        assert_eq!(cmp("7.2.0.1", "7.2"), Greater);
    }

    #[test]
    fn leading_v_and_zeros() {
        assert_eq!(cmp("v7.2.5", "7.2.5"), Equal);
        assert_eq!(cmp("V1.0", "1.0"), Equal);
        assert_eq!(cmp("2024.04", "2024.4"), Equal);
        assert_eq!(cmp("2024.10.1", "2024.9.30"), Greater);
    }

    #[test]
    fn letter_suffixes() {
        assert_eq!(cmp("1.1.1", "1.1.1a"), Less);
        assert_eq!(cmp("1.1.1a", "1.1.1w"), Less);
        assert_eq!(cmp("1.1.1w", "1.1.2"), Less);
        assert_eq!(cmp("2.4.58", "2.4.58a"), Less);
        assert_eq!(cmp("2.4.58a", "2.4.59"), Less);
    }

    #[test]
    fn build_suffixes() {
        assert_eq!(cmp("8.0.1", "8.0.1-build1234"), Less);
        assert_eq!(cmp("8.0.1-build2", "8.0.1-build10"), Less);
        assert_eq!(cmp("8.0.1-build1234", "8.0.2"), Less);
    }

    #[test]
    fn pre_release_words_sort_first() {
        assert_eq!(cmp("1.0-rc1", "1.0"), Less);
        assert_eq!(cmp("1.0-alpha", "1.0-beta"), Less);
        assert_eq!(cmp("1.0-beta2", "1.0-rc1"), Less);
        assert_eq!(cmp("1.0-rc2", "1.0-RC10"), Less);
        assert_eq!(cmp("1.0-dev", "1.0-alpha"), Less);
    }

    #[test]
    fn case_is_ignored_for_letters() {
        assert_eq!(cmp("1.1.1W", "1.1.1w"), Equal);
    }

    #[test]
    fn huge_numbers_do_not_overflow() {
        assert_eq!(
            cmp(
                "1.99999999999999999999999999",
                "1.100000000000000000000000000"
            ),
            Less
        );
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "", "   ", "abc", "v", ".1", "1..2", "1.2.", "1.2 3", "1.2/3", "-1", "1.2$",
        ] {
            assert!(Scheme::Dotted.compare(bad, "1.0").is_err(), "{bad:?}");
            assert!(Scheme::Calver.validate(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn calver_compares_like_dotted() {
        assert_eq!(
            Scheme::Calver.compare("2024.10.1", "2024.9.1").unwrap(),
            Greater
        );
    }
}
