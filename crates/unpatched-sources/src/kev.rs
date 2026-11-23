//! CISA Known Exploited Vulnerabilities (public domain).

use chrono::NaiveDate;
use serde::Deserialize;
use unpatched_core::KevEntry;

use crate::error::{Result, SourceError};
use crate::http::Http;
use crate::util::normalize_cve;

pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// The whole catalog: its own facts plus one entry per CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct KevCatalog {
    pub catalog_version: String,
    /// What the file says its count is.
    pub count: u64,
    pub date_released: Option<String>,
    pub entries: Vec<(String, KevEntry)>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCatalog {
    catalog_version: String,
    #[serde(default)]
    count: u64,
    #[serde(default)]
    date_released: Option<String>,
    vulnerabilities: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    vendor_project: String,
    product: String,
    date_added: String,
    #[serde(default)]
    required_action: String,
    #[serde(default)]
    due_date: Option<String>,
    #[serde(default)]
    known_ransomware_campaign_use: String,
}

fn date(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok()
}

pub fn parse_kev(bytes: &[u8]) -> Result<KevCatalog> {
    let raw: RawCatalog =
        serde_json::from_slice(bytes).map_err(|e| SourceError::parse("the CISA KEV file", e))?;
    let mut entries = Vec::with_capacity(raw.vulnerabilities.len());
    for v in raw.vulnerabilities {
        let id = normalize_cve(&v.cve_id).ok_or_else(|| {
            SourceError::parse("the CISA KEV file", format!("bad CVE id {:?}", v.cve_id))
        })?;
        let date_added = date(&v.date_added).ok_or_else(|| {
            SourceError::parse(
                "the CISA KEV file",
                format!("bad dateAdded {:?} for {id}", v.date_added),
            )
        })?;
        entries.push((
            id,
            KevEntry {
                date_added,
                due_date: v.due_date.as_deref().and_then(date),
                known_ransomware: v
                    .known_ransomware_campaign_use
                    .eq_ignore_ascii_case("known"),
                required_action: v.required_action,
                vendor_project: v.vendor_project,
                product: v.product,
            },
        ));
    }
    Ok(KevCatalog {
        catalog_version: raw.catalog_version,
        count: raw.count,
        date_released: raw.date_released,
        entries,
    })
}

pub fn fetch_kev(http: &Http) -> Result<KevCatalog> {
    parse_kev(&http.get(KEV_URL)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fixture;

    #[test]
    fn parses_fixture() {
        let kev = parse_kev(&fixture("kev/known_exploited_vulnerabilities.json")).unwrap();
        assert_eq!(kev.catalog_version, "2026.11.23");
        assert_eq!(kev.entries.len(), 7);
        let (id, e) = kev
            .entries
            .iter()
            .find(|(id, _)| id == "CVE-2024-21762")
            .unwrap();
        assert_eq!(id, "CVE-2024-21762");
        assert_eq!(e.vendor_project, "Fortinet");
        assert_eq!(e.product, "FortiOS");
        assert_eq!(e.date_added, NaiveDate::from_ymd_opt(2024, 2, 9).unwrap());
        assert!(!e.required_action.is_empty());
        assert!(e.due_date.is_some());
    }

    #[test]
    fn ransomware_flag() {
        let kev = parse_kev(&fixture("kev/known_exploited_vulnerabilities.json")).unwrap();
        assert!(kev.entries.iter().any(|(_, e)| e.known_ransomware));
        assert!(kev.entries.iter().any(|(_, e)| !e.known_ransomware));
    }

    #[test]
    fn empty_due_date_is_none() {
        let json = r#"{"catalogVersion":"v","count":1,"vulnerabilities":[{"cveID":"CVE-2020-0001","vendorProject":"V","product":"P","dateAdded":"2021-01-02","requiredAction":"","dueDate":"","knownRansomwareCampaignUse":"Unknown"}]}"#;
        let kev = parse_kev(json.as_bytes()).unwrap();
        assert_eq!(kev.entries[0].1.due_date, None);
    }

    #[test]
    fn bad_input_says_what_to_do() {
        let err = parse_kev(b"<html>").unwrap_err().to_string();
        assert!(
            err.contains("CISA KEV") && err.contains("report a bug"),
            "{err}"
        );
    }
}
