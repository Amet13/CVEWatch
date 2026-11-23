//! The unpatched product catalog: ids, CPE/CNA/KEV keys, version schemes.
//!
//! The data lives in `catalog/*.yml` and is compiled into
//! `src/catalog.generated.json` by `cargo xtask catalog build`. Never edit the
//! generated file by hand.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::NaiveDate;
pub use unpatched_core::CatalogEntry;

static ENTRIES: LazyLock<Vec<CatalogEntry>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("catalog.generated.json"))
        .expect("catalog.generated.json is invalid; run `cargo xtask catalog build`")
});

/// Lowercase id or alias to index in [`ENTRIES`].
static INDEX: LazyLock<HashMap<String, usize>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    for (i, e) in ENTRIES.iter().enumerate() {
        map.entry(e.id.to_lowercase()).or_insert(i);
    }
    // Ids win over aliases when both exist (`validate` reports that case).
    for (i, e) in ENTRIES.iter().enumerate() {
        for a in &e.aliases {
            map.entry(a.to_lowercase()).or_insert(i);
        }
    }
    map
});

/// Every product in the catalog, ordered by id.
pub fn all() -> &'static [CatalogEntry] {
    &ENTRIES
}

/// Find a product by id or alias, ignoring case.
pub fn get(id_or_alias: &str) -> Option<&'static CatalogEntry> {
    INDEX
        .get(id_or_alias.trim().to_lowercase().as_str())
        .map(|&i| &ENTRIES[i])
}

/// Find products matching `text`, best match first.
///
/// Every word of `text` must appear in the id, name, vendor or an alias.
/// Exact id and alias matches rank highest, then prefixes, then substrings.
pub fn search(text: &str) -> Vec<&'static CatalogEntry> {
    let lowered = text.trim().to_lowercase();
    let tokens: Vec<&str> = lowered.split_whitespace().collect();
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(u32, &'static CatalogEntry)> = ENTRIES
        .iter()
        .filter_map(|e| score(e, &lowered, &tokens).map(|s| (s, e)))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
    scored.into_iter().map(|(_, e)| e).collect()
}

fn score(e: &CatalogEntry, whole: &str, tokens: &[&str]) -> Option<u32> {
    let id = e.id.to_lowercase();
    let name = e.name.to_lowercase();
    let vendor = e.vendor.to_lowercase();
    let aliases: Vec<String> = e.aliases.iter().map(|a| a.to_lowercase()).collect();

    let mut total = 0;
    for t in tokens {
        let mut best = 0;
        let mut consider = |field: &str, exact: u32, prefix: u32, contains: u32| {
            if field == *t {
                best = best.max(exact);
            } else if field.starts_with(t) {
                best = best.max(prefix);
            } else if field.contains(t) {
                best = best.max(contains);
            }
        };
        consider(&id, 100, 70, 50);
        consider(&name, 90, 60, 40);
        for a in &aliases {
            consider(a, 95, 65, 40);
        }
        consider(&vendor, 30, 25, 20);
        if best == 0 {
            return None;
        }
        total += best;
    }
    // Typing the whole id or alias beats everything else.
    if id == whole || aliases.iter().any(|a| a == whole) {
        total += 1000;
    }
    Some(total)
}

/// Check entries for mistakes. Returns one message per problem; empty means fine.
pub fn validate(entries: &[CatalogEntry]) -> Vec<String> {
    validate_at(entries, chrono::Utc::now().date_naive())
}

/// Like [`validate`], with an explicit "today" (for tests).
pub fn validate_at(entries: &[CatalogEntry], today: NaiveDate) -> Vec<String> {
    let mut problems = Vec::new();

    let mut ids: HashMap<&str, usize> = HashMap::new();
    for e in entries {
        *ids.entry(e.id.as_str()).or_default() += 1;
    }

    // Lowercase alias or id -> owner id, to find clashes across entries.
    let mut names: HashMap<String, &str> = HashMap::new();
    for e in entries {
        names.entry(e.id.to_lowercase()).or_insert(&e.id);
    }

    for e in entries {
        let id = e.id.as_str();
        if ids[id] > 1 {
            problems.push(format!("{id}: duplicate id"));
        }
        if !valid_id(id) {
            problems.push(format!("{id}: id must be lowercase [a-z0-9-]+"));
        }
        if e.name.trim().is_empty() {
            problems.push(format!("{id}: name is empty"));
        }
        if e.vendor.trim().is_empty() {
            problems.push(format!("{id}: vendor is empty"));
        }
        if e.keys.cpe.is_empty() && e.keys.cna.is_empty() && e.keys.kev.is_empty() {
            problems.push(format!("{id}: match keys are empty"));
        }
        for c in &e.keys.cpe {
            if let Some(why) = bad_cpe(c) {
                problems.push(format!("{id}: cpe {c:?}: {why}"));
            }
        }
        for c in &e.keys.cna {
            if c.vendor.trim().is_empty() || c.product.trim().is_empty() {
                problems.push(format!("{id}: cna key has an empty vendor or product"));
            }
        }
        for k in &e.keys.kev {
            if k.vendor_project.trim().is_empty() || k.product.trim().is_empty() {
                problems.push(format!(
                    "{id}: kev key has an empty vendorProject or product"
                ));
            }
        }
        if e.checked > today {
            problems.push(format!("{id}: checked date {} is in the future", e.checked));
        }
        if let Some(slug) = &e.eol
            && (slug.is_empty() || slug.chars().any(|c| c.is_whitespace() || c.is_uppercase()))
        {
            problems.push(format!("{id}: eol slug {slug:?} is not a lowercase slug"));
        }
        for a in &e.aliases {
            let key = a.to_lowercase();
            if key.trim().is_empty() {
                problems.push(format!("{id}: empty alias"));
                continue;
            }
            match names.get(&key) {
                Some(owner) if *owner == id && key == e.id.to_lowercase() => {
                    problems.push(format!("{id}: alias {a:?} repeats the id"));
                }
                Some(owner) if *owner == id => {
                    problems.push(format!("{id}: alias {a:?} is listed twice"));
                }
                Some(owner) => {
                    problems.push(format!("{id}: alias {a:?} is already used by {owner}"));
                }
                None => {
                    names.insert(key, id);
                }
            }
        }
    }
    problems.sort();
    problems.dedup();
    problems
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Why a `vendor:product` CPE key is not acceptable, if it is not.
fn bad_cpe(cpe: &str) -> Option<&'static str> {
    let mut parts = cpe.split(':');
    let (Some(vendor), Some(product), None) = (parts.next(), parts.next(), parts.next()) else {
        return Some("must be vendor:product");
    };
    if vendor.is_empty() || product.is_empty() {
        return Some("vendor or product is empty");
    }
    if cpe.chars().any(char::is_uppercase) {
        return Some("must be lowercase");
    }
    if cpe
        .chars()
        .any(|c| matches!(c, '*' | '?') || c.is_whitespace())
    {
        return Some("must not contain wildcards or spaces");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use unpatched_core::Scheme;
    use unpatched_core::catalog::{CnaKey, KevKey, MatchKeys, ProductKind};

    fn entry(id: &str) -> CatalogEntry {
        CatalogEntry {
            id: id.into(),
            name: id.to_uppercase(),
            vendor: "Acme".into(),
            kind: ProductKind::App,
            versioning: Scheme::Dotted,
            keys: MatchKeys {
                cpe: vec![format!("acme:{id}")],
                cna: vec![CnaKey {
                    vendor: "Acme".into(),
                    product: id.into(),
                }],
                kev: vec![],
            },
            eol: None,
            aliases: vec![],
            homepage: None,
            checked: NaiveDate::from_ymd_opt(2026, 11, 23).unwrap(),
        }
    }

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 23).unwrap()
    }

    #[test]
    fn good_entries_have_no_problems() {
        let mut a = entry("alpha");
        a.aliases = vec!["the alpha".into()];
        assert_eq!(
            validate_at(&[a, entry("beta")], today()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn finds_duplicate_ids_and_aliases() {
        let mut a = entry("alpha");
        a.aliases = vec!["shared".into(), "beta".into()];
        let mut b = entry("beta");
        b.aliases = vec!["SHARED".into()];
        let p = validate_at(&[a, b, entry("beta")], today());
        assert!(p.iter().any(|m| m.contains("beta: duplicate id")), "{p:?}");
        assert!(
            p.iter()
                .any(|m| m.contains("alias \"SHARED\" is already used by alpha")),
            "{p:?}"
        );
        assert!(p.iter().any(|m| m.contains("alias \"beta\"")), "{p:?}");
    }

    #[test]
    fn rejects_bad_ids() {
        let p = validate_at(&[entry("Alpha"), entry("al_pha"), entry("")], today());
        assert_eq!(
            p.iter()
                .filter(|m| m.contains("id must be lowercase"))
                .count(),
            3,
            "{p:?}"
        );
    }

    #[test]
    fn rejects_bad_cpe() {
        for bad in [
            "acme",
            "acme:*",
            "Acme:app",
            "acme:app:1.0",
            ":app",
            "acme:ap?",
        ] {
            let mut e = entry("alpha");
            e.keys.cpe = vec![bad.into()];
            let p = validate_at(&[e], today());
            assert!(p.iter().any(|m| m.contains("cpe")), "{bad}: {p:?}");
        }
    }

    #[test]
    fn rejects_empty_keys_and_future_date() {
        let mut e = entry("alpha");
        e.keys = MatchKeys::default();
        e.checked = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap();
        let p = validate_at(&[e], today());
        assert!(
            p.iter().any(|m| m.contains("match keys are empty")),
            "{p:?}"
        );
        assert!(p.iter().any(|m| m.contains("in the future")), "{p:?}");
    }

    #[test]
    fn empty_cna_or_kev_strings_are_problems() {
        let mut e = entry("alpha");
        e.keys.cna.push(CnaKey {
            vendor: String::new(),
            product: "x".into(),
        });
        e.keys.kev.push(KevKey {
            vendor_project: "x".into(),
            product: " ".into(),
        });
        let p = validate_at(&[e], today());
        assert!(p.iter().any(|m| m.contains("cna key")), "{p:?}");
        assert!(p.iter().any(|m| m.contains("kev key")), "{p:?}");
    }

    #[test]
    fn generated_catalog_is_valid_and_sorted() {
        let all = all();
        assert_eq!(validate(all), Vec::<String>::new());
        assert!(
            all.windows(2).all(|w| w[0].id < w[1].id),
            "ids must be sorted"
        );
    }

    #[test]
    fn get_is_case_insensitive_and_knows_aliases() {
        for e in all() {
            assert_eq!(get(&e.id.to_uppercase()).map(|x| &x.id), Some(&e.id));
            for a in &e.aliases {
                assert_eq!(get(a).map(|x| &x.id), Some(&e.id), "alias {a}");
            }
        }
        assert!(get("no-such-product").is_none());
    }

    #[test]
    fn search_ranks_exact_before_partial() {
        let hits = search("fortios");
        assert_eq!(hits.first().map(|e| e.id.as_str()), Some("fortios"));
        assert!(search("").is_empty());
        assert!(search("zzzzzz-nothing").is_empty());
        // Every word must match.
        assert!(search("fortios zzzzzz").is_empty());
    }

    #[test]
    fn catalog_has_the_core_products() {
        for id in ["fortios", "nextcloud", "openssh", "linux-kernel"] {
            assert!(get(id).is_some(), "missing {id}");
        }
    }
}
