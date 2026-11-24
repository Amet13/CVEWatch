//! `unpatched db sources`: ask every source for one known item.

use chrono::Utc;
use unpatched_core::{SourceId, SourceStatus};
use unpatched_sources::{Http, cve_org, endoflife, epss, exploits, kev, nvd, osv};

const LOG4J: &str = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

fn check(source: SourceId, f: impl FnOnce() -> Result<(u64, String), String>) -> SourceStatus {
    let (ok, records, note) = match f() {
        Ok((n, note)) => (true, n, note),
        Err(e) => (false, 0, e),
    };
    SourceStatus {
        source,
        fetched_at: Utc::now(),
        records,
        ok,
        note: Some(note),
    }
}

/// One live probe per source. Never fails as a whole: each result says
/// whether that source answered with what we expect.
pub fn sources_health(http: &Http) -> Vec<SourceStatus> {
    let e = |e: unpatched_sources::SourceError| e.to_string();
    vec![
        check(SourceId::Kev, || {
            let k = kev::fetch_kev(http).map_err(e)?;
            if !k.entries.iter().any(|(id, _)| id == "CVE-2021-44228") {
                return Err("the KEV list does not contain CVE-2021-44228".into());
            }
            Ok((k.entries.len() as u64, "contains CVE-2021-44228".into()))
        }),
        check(SourceId::Epss, || {
            let s = epss::fetch_epss_one(http, "CVE-2021-44228")
                .map_err(e)?
                .ok_or("the EPSS API has no score for CVE-2021-44228")?;
            Ok((1, format!("CVE-2021-44228 scores {}", s.score)))
        }),
        check(SourceId::Nvd, || {
            let bytes = http
                .get(&format!("{}/nvdcve-2.0-modified.meta", nvd::NVD_FEED_BASE))
                .map_err(e)?;
            let meta = nvd::parse_nvd_meta(&String::from_utf8_lossy(&bytes)).map_err(e)?;
            Ok((1, format!("modified feed {}", meta.last_modified)))
        }),
        check(SourceId::CveOrg, || {
            let r = cve_org::fetch_record(http, "CVE-2021-44228").map_err(e)?;
            Ok((1, format!("{} fetched", r.id)))
        }),
        check(SourceId::Osv, || {
            let found = osv::query_batch(http, &[LOG4J.to_owned()]).map_err(e)?;
            let n = found.values().map(Vec::len).sum::<usize>();
            if n == 0 {
                return Err(format!("OSV knows no vulnerability for {LOG4J}"));
            }
            Ok((
                n as u64,
                format!("{n} vulnerabilities for log4j-core 2.14.1"),
            ))
        }),
        check(SourceId::Endoflife, || {
            let c = endoflife::fetch_eol(http, "nextcloud").map_err(e)?;
            if c.is_empty() {
                return Err("endoflife.date returned no cycles for nextcloud".into());
            }
            Ok((c.len() as u64, "nextcloud parsed".into()))
        }),
        check(SourceId::ExploitDb, || {
            let list = exploits::fetch_exploitdb(http).map_err(e)?;
            if list.is_empty() {
                return Err("the Exploit-DB index has no CVE rows".into());
            }
            Ok((list.len() as u64, "index parsed".into()))
        }),
    ]
}
