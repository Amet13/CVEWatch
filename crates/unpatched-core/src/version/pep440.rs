//! PEP 440 versions: epochs, pre/post/dev releases, local versions, and the
//! spelling variants the PEP normalises (`1.0-rc.1`, `1.0.RC1`, `1.0-1`).

use std::cmp::Ordering;
use std::sync::LazyLock;

use regex::Regex;

static SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)^
        v?
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
        (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
        (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
        (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
        $",
    )
    .expect("pep440 regex is valid")
});

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LocalPart {
    /// Letters sort before numbers.
    Alpha(String),
    Num(u128),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Pep440 {
    epoch: u128,
    /// Without trailing zeros.
    release: Vec<u128>,
    /// (stage, letter rank, number): a dev-only release sorts before any
    /// pre-release, a final release after all of them.
    pre: (u8, u8, u128),
    post: (u8, u128),
    dev: (u8, u128),
    local: Option<Vec<LocalPart>>,
}

fn num(text: &str) -> Result<u128, String> {
    text.parse::<u128>()
        .map_err(|_| format!("the number {text} is too large"))
}

fn opt_num(text: Option<&str>) -> Result<u128, String> {
    text.map_or(Ok(0), num)
}

pub(super) fn parse(input: &str) -> Result<Pep440, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("the version is empty".into());
    }
    let c = SHAPE
        .captures(s)
        .ok_or_else(|| "not a PEP 440 version (see peps.python.org/pep-0440)".to_string())?;
    let epoch = opt_num(c.name("epoch").map(|m| m.as_str()))?;
    let mut release = Vec::new();
    for part in c["release"].split('.') {
        release.push(num(part)?);
    }
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let post_num = c
        .name("post_n1")
        .or_else(|| c.name("post_n2"))
        .map(|m| m.as_str());
    let has_post = c.name("post").is_some();
    let has_dev = c.name("dev").is_some();
    let pre = match c.name("pre_l") {
        Some(l) => {
            let rank = match l.as_str().to_ascii_lowercase().as_str() {
                "a" | "alpha" => 0,
                "b" | "beta" => 1,
                _ => 2, // c, rc, pre, preview
            };
            (1, rank, opt_num(c.name("pre_n").map(|m| m.as_str()))?)
        }
        None if has_dev && !has_post => (0, 0, 0),
        None => (2, 0, 0),
    };
    let post = if has_post {
        (1, opt_num(post_num)?)
    } else {
        (0, 0)
    };
    let dev = if has_dev {
        (0, opt_num(c.name("dev_n").map(|m| m.as_str()))?)
    } else {
        (1, 0)
    };
    let local = match c.name("local") {
        Some(m) => {
            let mut parts = Vec::new();
            for seg in m.as_str().split(['-', '_', '.']) {
                if seg.bytes().all(|b| b.is_ascii_digit()) {
                    parts.push(LocalPart::Num(num(seg)?));
                } else {
                    parts.push(LocalPart::Alpha(seg.to_ascii_lowercase()));
                }
            }
            Some(parts)
        }
        None => None,
    };
    Ok(Pep440 {
        epoch,
        release,
        pre,
        post,
        dev,
        local,
    })
}

#[cfg(test)]
mod tests {
    use super::super::Scheme;
    use std::cmp::Ordering::{Equal, Greater, Less};

    fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
        Scheme::Pep440.compare(a, b).unwrap()
    }

    #[test]
    fn pep_example_ordering() {
        // From the PEP's "Summary of permitted suffixes and relative ordering".
        let order = [
            "1.dev0",
            "1.0.dev456",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a12.dev456",
            "1.0a12",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0rc1.dev456",
            "1.0rc1",
            "1.0",
            "1.0+abc.5",
            "1.0+abc.7",
            "1.0+5",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.1.dev1",
        ];
        for w in order.windows(2) {
            assert_eq!(cmp(w[0], w[1]), Less, "{} < {}", w[0], w[1]);
            assert_eq!(cmp(w[1], w[0]), Greater);
        }
    }

    #[test]
    fn epochs() {
        assert_eq!(cmp("1!1.0", "2.0"), Greater);
        assert_eq!(cmp("0!1.0", "1.0"), Equal);
        assert_eq!(cmp("1!1.0", "1!2.0"), Less);
    }

    #[test]
    fn trailing_zeros() {
        assert_eq!(cmp("1.0", "1.0.0"), Equal);
        assert_eq!(cmp("1.0.0.1", "1.0"), Greater);
    }

    #[test]
    fn normalisation() {
        assert_eq!(cmp("1.0-rc.1", "1.0rc1"), Equal);
        assert_eq!(cmp("1.0.RC1", "1.0rc1"), Equal);
        assert_eq!(cmp("1.0c1", "1.0rc1"), Equal);
        assert_eq!(cmp("1.0alpha1", "1.0a1"), Equal);
        assert_eq!(cmp("1.0-beta2", "1.0b2"), Equal);
        assert_eq!(cmp("1.0preview3", "1.0rc3"), Equal);
        assert_eq!(cmp("v1.0", "1.0"), Equal);
        assert_eq!(cmp("1.0-1", "1.0.post1"), Equal);
        assert_eq!(cmp("1.0-r2", "1.0.post2"), Equal);
        assert_eq!(cmp("1.0rev3", "1.0.post3"), Equal);
        assert_eq!(cmp("1.0.post", "1.0.post0"), Equal);
        assert_eq!(cmp("1.0a", "1.0a0"), Equal);
        assert_eq!(cmp("1.0.dev", "1.0.dev0"), Equal);
        assert_eq!(cmp("1.0+Ubuntu-1", "1.0+ubuntu.1"), Equal);
    }

    #[test]
    fn local_versions() {
        assert_eq!(cmp("1.0+abc", "1.0"), Greater);
        assert_eq!(cmp("1.0+abc", "1.0+1"), Less);
        assert_eq!(cmp("1.0+1.2", "1.0+1"), Greater);
        assert_eq!(cmp("1.0+10", "1.0+9"), Greater);
        assert_eq!(cmp("1.0+local", "1.1"), Less);
    }

    #[test]
    fn real_world_versions() {
        assert_eq!(cmp("2.31.0", "2.32.0"), Less);
        assert_eq!(cmp("2.32.0", "2.32.0.post1"), Less);
        assert_eq!(cmp("3.0.0rc1", "3.0.0"), Less);
        assert_eq!(cmp("42.0.5", "42.0.10"), Less);
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "",
            "abc",
            "1.0.x",
            "1..0",
            "1.0+",
            "1.0 1",
            "!1.0",
            "1.0-",
            "1.0.dev.rc",
            "99999999999999999999999999999999999999999",
        ] {
            assert!(Scheme::Pep440.validate(bad).is_err(), "{bad:?}");
        }
    }
}
