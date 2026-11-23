//! Fetch one item from each source and print a summary. Needs the network.
//!
//!     cargo run -p unpatched-sources --example smoke
//!
//! Not a test: tests never use the network.

use std::collections::HashSet;

use unpatched_sources::nvd::{NvdFeed, fetch_nvd_feed};
use unpatched_sources::{Http, cve_org, endoflife, epss, exploits, kev, osv};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http = Http::new()?;

    let k = kev::fetch_kev(&http)?;
    let one = k.entries.iter().find(|(id, _)| id == "CVE-2024-21762");
    println!(
        "kev: version {}, {} entries (file says {}); CVE-2024-21762 -> {:?}",
        k.catalog_version,
        k.entries.len(),
        k.count,
        one.map(|(_, e)| (&e.vendor_project, &e.product, e.date_added))
    );

    let e = epss::fetch_epss(&http)?;
    println!(
        "epss: model {}, date {}, {} scores",
        e.model_version,
        e.score_date,
        e.scores.len()
    );
    println!(
        "epss api: CVE-2024-21762 -> {:?}",
        epss::fetch_epss_one(&http, "CVE-2024-21762")?
    );

    let keys: HashSet<String> = ["fortinet:fortios".to_owned()].into();
    let mut total = 0u64;
    let mut hits = Vec::new();
    let (meta, info) = fetch_nvd_feed(&http, NvdFeed::Modified, |mut r| {
        total += 1;
        r.cpe_ranges.retain(|c| keys.contains(&c.vendor_product));
        if !r.cpe_ranges.is_empty() {
            hits.push(r);
        }
    })?;
    println!(
        "nvd modified: {} records, checksum ok ({}), last modified {}; {} touch fortinet:fortios{}",
        info.records,
        &meta.sha256[..12],
        meta.last_modified,
        hits.len(),
        hits.first()
            .map(|r| format!(" (e.g. {}: {:?})", r.id, r.cpe_ranges[0].constraint))
            .unwrap_or_default()
    );
    assert_eq!(total, info.records);

    let rec = cve_org::fetch_record(&http, "CVE-2024-21762")?;
    println!(
        "cve.org: {} {:?}, {} affected entries, ssvc {:?}/{:?}, cvss {:?}",
        rec.id,
        rec.state,
        rec.cna_affected.len(),
        rec.ssvc_exploitation,
        rec.ssvc_automatable,
        rec.cvss.as_ref().map(|c| c.score)
    );
    if let Some(a) = rec.cna_affected.first() {
        println!(
            "  {} {}: {} constraints",
            a.vendor,
            a.product,
            a.constraints.len()
        );
    }

    let purls = vec![
        "pkg:pypi/django@3.2.0".to_owned(),
        "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm".to_owned(),
    ];
    let found = osv::query_batch(&http, &purls)?;
    for p in &purls {
        let v = &found[p];
        println!(
            "osv: {p} -> {} vulnerabilities, e.g. {:?}",
            v.len(),
            v.first().map(|v| (&v.id, v.ranges[0].constraints.len()))
        );
    }

    let cycles = endoflife::fetch_eol(&http, "nextcloud")?;
    println!(
        "endoflife: nextcloud {} cycles, newest {:?}; {} products in all.json",
        cycles.len(),
        cycles.first().map(|c| (&c.cycle, c.eol)),
        endoflife::fetch_all_products(&http)?.len()
    );

    let edb = exploits::fetch_exploitdb(&http)?;
    println!(
        "exploit-db: {} CVE links; CVE-2024-4577 -> {} exploits",
        edb.len(),
        edb.iter().filter(|(c, _)| c == "CVE-2024-4577").count()
    );
    let msf = exploits::fetch_metasploit(&http)?;
    println!(
        "metasploit: {} CVE links; CVE-2021-44228 -> {} modules",
        msf.len(),
        msf.iter().filter(|(c, _)| c == "CVE-2021-44228").count()
    );
    Ok(())
}
