//! Small helpers shared by the source modules.

use chrono::NaiveDate;
use unpatched_core::{CatalogEntry, Constraint};

/// Read the date at the start of an ISO timestamp (`2024-02-09T08:14:25.954Z`).
pub(crate) fn date_prefix(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s.get(..10)?, "%Y-%m-%d").ok()
}

/// A CVE id in its usual spelling (`CVE-2024-21762`), upper-cased. Returns
/// `None` for anything else.
pub(crate) fn normalize_cve(s: &str) -> Option<String> {
    let up = s.trim().to_ascii_uppercase();
    let rest = up.strip_prefix("CVE-")?;
    let (year, num) = rest.split_once('-')?;
    let ok = year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && num.len() >= 4
        && num.bytes().all(|b| b.is_ascii_digit());
    ok.then_some(up)
}

/// Push a constraint unless an equal one is already there.
pub(crate) fn push_unique(list: &mut Vec<Constraint>, c: Constraint) {
    if !list.contains(&c) {
        list.push(c);
    }
}

/// A catalog id with the description starts that a CNA key needs.
pub type DescribedKey = (String, Vec<String>);

/// Lookup tables from names used by the sources to catalog product ids.
/// Built from the catalog so `nvd` and `cve_org` can label ranges with the
/// product id instead of the source's own names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatalogIndex {
    /// `vendor:product` (CPE) to catalog ids.
    pub cpe: std::collections::HashMap<String, Vec<String>>,
    /// (CNA vendor, CNA product) to catalog ids.
    pub cna: std::collections::HashMap<(String, String), Vec<String>>,
    /// (CNA vendor, CNA product) to (catalog id, lower-case description starts).
    /// These keys only count when the CVE description starts with one of the
    /// texts (see `CnaKey::summary_starts`).
    pub cna_described: std::collections::HashMap<(String, String), Vec<DescribedKey>>,
}

impl CatalogIndex {
    pub fn from_catalog(entries: &[CatalogEntry]) -> Self {
        let mut idx = Self::default();
        for e in entries {
            for key in &e.keys.cpe {
                add(idx.cpe.entry(key.to_ascii_lowercase()).or_default(), &e.id);
            }
            for k in &e.keys.cna {
                let key = (k.vendor.clone(), k.product.clone());
                if k.summary_starts.is_empty() {
                    add(idx.cna.entry(key).or_default(), &e.id);
                } else {
                    idx.cna_described.entry(key).or_default().push((
                        e.id.clone(),
                        k.summary_starts
                            .iter()
                            .map(|s| s.trim().to_lowercase())
                            .collect(),
                    ));
                }
            }
        }
        idx
    }
}

fn add(list: &mut Vec<String>, id: &str) {
    if !list.iter().any(|x| x == id) {
        list.push(id.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_cves() {
        assert_eq!(
            date_prefix("2024-02-09T08:14:25.954Z"),
            NaiveDate::from_ymd_opt(2024, 2, 9)
        );
        assert_eq!(date_prefix("2024"), None);
        assert_eq!(
            normalize_cve(" cve-2024-21762 ").as_deref(),
            Some("CVE-2024-21762")
        );
        assert_eq!(normalize_cve("OSVDB-5970"), None);
        assert_eq!(normalize_cve("CVE-24-1"), None);
    }
}
