//! endoflife.date: release cycles and end-of-life dates (MIT).

use serde::Deserialize;
use unpatched_core::EolCycle;

use crate::error::{Result, SourceError};
use crate::http::Http;
use crate::util::date_prefix;

pub const EOL_API: &str = "https://endoflife.date/api";

/// A value that endoflife.date writes as a date, a boolean, or leaves out.
#[derive(Deserialize, Debug, Default)]
#[serde(untagged)]
enum DateOrBool {
    Bool(bool),
    Text(String),
    #[default]
    Missing,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCycle {
    cycle: serde_json::Value,
    #[serde(default)]
    release_date: Option<String>,
    #[serde(default)]
    eol: Option<DateOrBool>,
    #[serde(default)]
    latest: Option<String>,
    #[serde(default)]
    lts: Option<DateOrBool>,
}

fn cycle_name(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Parse the JSON of one product (`/api/<slug>.json`).
pub fn parse_eol(bytes: &[u8]) -> Result<Vec<EolCycle>> {
    let raw: Vec<RawCycle> = serde_json::from_slice(bytes)
        .map_err(|e| SourceError::parse("an endoflife.date answer", e))?;
    raw.into_iter()
        .map(|c| {
            let cycle = cycle_name(&c.cycle).ok_or_else(|| {
                SourceError::parse(
                    "an endoflife.date answer",
                    format!("cycle {:?} is not text or a number", c.cycle),
                )
            })?;
            let (eol, eol_reached) = match c.eol.unwrap_or_default() {
                DateOrBool::Bool(b) => (None, b),
                DateOrBool::Text(s) => (date_prefix(&s), false),
                DateOrBool::Missing => (None, false),
            };
            let lts = match c.lts.unwrap_or_default() {
                DateOrBool::Bool(b) => b,
                // A date here is when the cycle became LTS: it is an LTS cycle.
                DateOrBool::Text(s) => !s.is_empty(),
                DateOrBool::Missing => false,
            };
            Ok(EolCycle {
                cycle,
                release_date: c.release_date.as_deref().and_then(date_prefix),
                eol,
                eol_reached,
                latest: c.latest.filter(|l| !l.is_empty()),
                lts,
            })
        })
        .collect()
}

/// Parse `/api/all.json`: the list of product slugs.
pub fn parse_all_products(bytes: &[u8]) -> Result<Vec<String>> {
    serde_json::from_slice(bytes)
        .map_err(|e| SourceError::parse("the endoflife.date product list", e))
}

pub fn fetch_eol(http: &Http, slug: &str) -> Result<Vec<EolCycle>> {
    fetch_eol_at(http, EOL_API, slug)
}

pub fn fetch_all_products(http: &Http) -> Result<Vec<String>> {
    parse_all_products(&http.get(&format!("{EOL_API}/all.json"))?)
}

pub(crate) fn fetch_eol_at(http: &Http, base: &str, slug: &str) -> Result<Vec<EolCycle>> {
    let ok = !slug.is_empty()
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if !ok {
        return Err(SourceError::NotFound {
            what: format!("endoflife.date product {slug:?}"),
        });
    }
    match http.get_optional(&format!("{base}/{slug}.json"))? {
        Some(b) => parse_eol(&b),
        None => Err(SourceError::NotFound {
            what: format!("endoflife.date product {slug:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TestServer, fixture};
    use chrono::NaiveDate;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn nextcloud() {
        let c = parse_eol(&fixture("endoflife/nextcloud.json")).unwrap();
        assert!(!c.is_empty());
        assert!(c.iter().all(|c| !c.cycle.is_empty()));
        assert!(c.iter().any(|c| c.eol.is_some()));
    }

    #[test]
    fn nodejs_lts_can_be_a_date() {
        let c = parse_eol(&fixture("endoflife/nodejs.json")).unwrap();
        let c26 = c.iter().find(|c| c.cycle == "26").unwrap();
        assert!(c26.lts);
        assert_eq!(c26.eol, Some(d(2029, 4, 30)));
        assert_eq!(c26.latest.as_deref(), Some("26.13.1"));
        let c25 = c.iter().find(|c| c.cycle == "25").unwrap();
        assert!(!c25.lts);
    }

    #[test]
    fn eol_true_false_and_missing() {
        let json = br#"[
          {"cycle":"1","eol":true,"latest":"1.9"},
          {"cycle":2,"eol":false},
          {"cycle":"3","eol":"2030-01-31","releaseDate":"2024-01-31","lts":true},
          {"cycle":"4"}
        ]"#;
        let c = parse_eol(json).unwrap();
        assert_eq!((c[0].eol, c[0].eol_reached), (None, true));
        assert_eq!(c[1].cycle, "2");
        assert_eq!(
            (c[1].eol, c[1].eol_reached, c[1].latest.clone()),
            (None, false, None)
        );
        assert_eq!(c[2].eol, Some(d(2030, 1, 31)));
        assert_eq!(c[2].release_date, Some(d(2024, 1, 31)));
        assert!(c[2].lts);
        assert_eq!((c[3].eol, c[3].eol_reached, c[3].lts), (None, false, false));
    }

    #[test]
    fn windows_and_ubuntu_parse() {
        for f in ["windows", "ubuntu", "postgresql"] {
            let c = parse_eol(&fixture(&format!("endoflife/{f}.json"))).unwrap();
            assert!(!c.is_empty(), "{f}");
        }
        let u = parse_eol(&fixture("endoflife/ubuntu.json")).unwrap();
        assert!(u.iter().any(|c| c.cycle == "26.04" && c.lts));
    }

    #[test]
    fn all_products() {
        let p = parse_all_products(&fixture("endoflife/all.json")).unwrap();
        assert!(p.contains(&"almalinux".to_owned()));
    }

    #[test]
    fn fetch_and_missing_product() {
        let srv = TestServer::start(|req| {
            if req.path == "/api/nextcloud.json" {
                (200, br#"[{"cycle":"30","eol":"2026-01-01"}]"#.to_vec())
            } else {
                (404, Vec::new())
            }
        });
        let http = Http::new().unwrap();
        let base = srv.url("/api");
        assert_eq!(fetch_eol_at(&http, &base, "nextcloud").unwrap().len(), 1);
        assert!(matches!(
            fetch_eol_at(&http, &base, "nope"),
            Err(SourceError::NotFound { .. })
        ));
        assert!(fetch_eol_at(&http, &base, "../x").is_err());
    }
}
