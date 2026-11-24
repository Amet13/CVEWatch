//! Semantic Versioning 2.0.0, lenient: a leading `v` is dropped and missing
//! minor or patch parts count as `0` (`1.2` is `1.2.0`). Build metadata
//! (`+...`) never changes the order.

use std::cmp::Ordering;

use super::cmp_digits;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Num(String),
    Alpha(String),
}

impl Ord for Ident {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Ident::Num(a), Ident::Num(b)) => cmp_digits(a, b),
            (Ident::Num(_), Ident::Alpha(_)) => Ordering::Less,
            (Ident::Alpha(_), Ident::Num(_)) => Ordering::Greater,
            (Ident::Alpha(a), Ident::Alpha(b)) => a.cmp(b),
        }
    }
}
impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub(super) struct Semver {
    /// Numeric core, at least three parts (padded with zeros).
    core: Vec<String>,
    pre: Vec<Ident>,
}

impl Semver {
    fn cmp_inner(&self, other: &Self) -> Ordering {
        let n = self.core.len().max(other.core.len());
        for i in 0..n {
            let a = self.core.get(i).map_or("0", String::as_str);
            let b = other.core.get(i).map_or("0", String::as_str);
            match cmp_digits(a, b) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.pre.cmp(&other.pre),
        }
    }
}

impl PartialEq for Semver {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_inner(other) == Ordering::Equal
    }
}
impl Eq for Semver {}
impl PartialOrd for Semver {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Semver {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_inner(other)
    }
}

pub(super) fn parse(input: &str) -> Result<Semver, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("the version is empty".into());
    }
    let s = match s.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => s,
    };
    let (rest, build) = match s.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (s, None),
    };
    if let Some(b) = build {
        let ok = !b.is_empty()
            && b.split('.').all(|id| {
                !id.is_empty() && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            });
        if !ok {
            return Err("invalid build metadata after '+'".into());
        }
    }
    let (core_text, pre_text) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let mut core: Vec<String> = Vec::new();
    for part in core_text.split('.') {
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) {
            return Err(format!(
                "{core_text:?} is not a number like 1.2.3 (digits separated by dots)"
            ));
        }
        core.push(part.trim_start_matches('0').to_string());
    }
    while core.len() < 3 {
        core.push(String::new());
    }
    let mut pre = Vec::new();
    if let Some(p) = pre_text {
        if p.is_empty() {
            return Err("empty pre-release after '-'".into());
        }
        for id in p.split('.') {
            if id.is_empty() || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
                return Err(format!("invalid pre-release identifier {id:?}"));
            }
            if id.bytes().all(|c| c.is_ascii_digit()) {
                pre.push(Ident::Num(id.to_string()));
            } else {
                pre.push(Ident::Alpha(id.to_string()));
            }
        }
    }
    Ok(Semver { core, pre })
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use std::cmp::Ordering::{Equal, Greater, Less};

    fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
        Scheme::Semver.compare(a, b).unwrap()
    }

    #[test]
    fn spec_precedence_example() {
        // https://semver.org/#spec-item-11
        let order = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for w in order.windows(2) {
            assert_eq!(cmp(w[0], w[1]), Less, "{} < {}", w[0], w[1]);
            assert_eq!(cmp(w[1], w[0]), Greater);
        }
    }

    #[test]
    fn core_is_numeric() {
        assert_eq!(cmp("1.9.0", "1.10.0"), Less);
        assert_eq!(cmp("2.0.0", "1.99.99"), Greater);
        assert_eq!(cmp("1.0.0", "1.0.1"), Less);
    }

    #[test]
    fn build_metadata_is_ignored() {
        assert_eq!(cmp("1.0.0+a", "1.0.0+b"), Equal);
        assert_eq!(cmp("1.0.0-rc.1+x", "1.0.0-rc.1"), Equal);
        assert_eq!(cmp("1.0.0+999", "1.0.1"), Less);
    }

    #[test]
    fn lenient_forms() {
        assert_eq!(cmp("1.2", "1.2.0"), Equal);
        assert_eq!(cmp("1", "1.0.0"), Equal);
        assert_eq!(cmp("v1.2.3", "1.2.3"), Equal);
        assert_eq!(cmp("v2", "1.9.9"), Greater);
        assert_eq!(cmp("1.2.3.4", "1.2.3"), Greater);
    }

    #[test]
    fn numeric_identifiers_compare_numerically() {
        assert_eq!(cmp("1.0.0-2", "1.0.0-10"), Less);
        assert_eq!(cmp("1.0.0-1", "1.0.0-a"), Less);
        assert_eq!(cmp("1.0.0-a", "1.0.0-a.1"), Less);
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "",
            "x",
            "1.x.3",
            "1..3",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-a..b",
            "1.2.3-a_b",
            "-1.0",
            "1.2.3 4",
        ] {
            assert!(Scheme::Semver.validate(bad).is_err(), "{bad:?}");
        }
    }
}
