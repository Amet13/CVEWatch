//! Synology DSM versions: `major.minor[.patch]-build[-update]`.
//!
//! `7.2.1-69057` is DSM 7.2.1, build 69057. `7.2.1-69057-5` and
//! `7.2.1-69057 Update 5` are the same build with its 5th update. Reading
//! these as dotted numbers puts `7.2-64561` (a build of 7.2) after
//! `7.2.1-69057`, so the build number gets its own place in the order.
//!
//! The order is (major, minor, patch, build, update). A missing patch, build or
//! update counts as 0, so a bound such as `7.2` or `7.2.2` works as a start.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Synology {
    release: [u64; 3],
    build: u64,
    update: u64,
}

fn number(s: &str, what: &str) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("{what} {s:?} is not a number"));
    }
    s.parse::<u64>()
        .map_err(|_| format!("{what} {s:?} is too big"))
}

pub(super) fn parse(input: &str) -> Result<Synology, String> {
    let mut s = input.trim();
    if s.len() > 4 && s.is_char_boundary(4) && s[..4].eq_ignore_ascii_case("dsm ") {
        s = s[4..].trim_start();
    }
    if s.is_empty() {
        return Err("the version is empty".into());
    }
    // `7.2.1-69057 Update 5`
    let lower = s.to_ascii_lowercase();
    let (core, word_update) = match lower.rfind(" update ") {
        Some(i) => (s[..i].trim_end(), Some(s[i + " update ".len()..].trim())),
        None => (s, None),
    };
    let mut parts = core.split('-');
    let release = parts.next().unwrap_or("");
    let build = parts.next();
    let update = parts.next();
    if parts.next().is_some() {
        return Err("expected major.minor[.patch]-build[-update]".into());
    }
    let mut nums = [0u64; 3];
    let comps: Vec<&str> = release.split('.').collect();
    if !(2..=3).contains(&comps.len()) {
        return Err("expected major.minor or major.minor.patch before the build".into());
    }
    for (slot, c) in nums.iter_mut().zip(&comps) {
        *slot = number(c, "release number")?;
    }
    // NVD writes `6.2.4-25556.4` for build 25556, update 4.
    let (build, dotted_update) = match build.and_then(|b| b.split_once('.')) {
        Some((b, u)) => (Some(b), Some(u)),
        None => (build, None),
    };
    let update = update.or(dotted_update);
    let build = match build {
        Some(b) => number(b, "build")?,
        None => 0,
    };
    let update = match (update, word_update) {
        (Some(_), Some(_)) => return Err("the update is given twice".into()),
        (Some(u), None) | (None, Some(u)) => number(u, "update")?,
        (None, None) => 0,
    };
    if update > 0 && build == 0 {
        return Err("an update needs a build number (7.2.1-69057-5)".into());
    }
    Ok(Synology {
        release: nums,
        build,
        update,
    })
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use std::cmp::Ordering::{Equal, Greater, Less};

    fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
        Scheme::Synology.compare(a, b).unwrap()
    }

    #[test]
    fn the_build_is_not_a_patch_number() {
        // The reported bug: dotted read 7.2-64561 as 7.2.64561.
        assert_eq!(cmp("7.2.1-69057", "7.2-64561"), Greater);
        assert_eq!(cmp("7.2-64561", "7.2.1-69057"), Less);
        assert_eq!(cmp("7.2.1-69057", "7.2-64570-4"), Greater);
        assert_eq!(cmp("7.2.2-72806", "7.2.1-69057-6"), Greater);
    }

    #[test]
    fn updates_follow_the_build() {
        assert_eq!(cmp("7.2.1-69057", "7.2.1-69057-1"), Less);
        assert_eq!(cmp("7.2.1-69057-5", "7.2.1-69057-6"), Less);
        assert_eq!(cmp("7.2.1-69057-10", "7.2.1-69057-6"), Greater);
        assert_eq!(cmp("7.2.1-69057-6", "7.2.2-72806"), Less);
    }

    #[test]
    fn update_words_and_prefix() {
        assert_eq!(cmp("7.2.1-69057 Update 5", "7.2.1-69057-5"), Equal);
        assert_eq!(cmp("DSM 7.2.1-69057", "7.2.1-69057"), Equal);
        assert_eq!(cmp("7.2.1-69057 update 5", "7.2.1-69057-4"), Greater);
    }

    #[test]
    fn nvd_writes_the_update_after_a_dot() {
        assert_eq!(cmp("6.2.4-25556.4", "6.2.4-25556-4"), Equal);
        assert_eq!(cmp("6.2.4-25556.4", "6.2.4-25556"), Greater);
    }

    #[test]
    fn short_bounds_work_as_starts() {
        assert_eq!(cmp("7.2.1-69057", "7.2"), Greater);
        assert_eq!(cmp("7.2", "7.2.0"), Equal);
        assert_eq!(cmp("7.2.2-72806", "7.2.2"), Greater);
        assert_eq!(cmp("7.1.1-42962-6", "7.2"), Less);
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "",
            "7",
            "7.2.1.4-1",
            "seven",
            "7.2.1-abc",
            "7.2.1-1-2-3",
            "7.2.1 Update 5",
            "7.2.1-100 Update 5-6",
        ] {
            assert!(Scheme::Synology.validate(bad).is_err(), "{bad:?}");
        }
    }
}
