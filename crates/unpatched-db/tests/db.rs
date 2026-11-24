//! Build a database from the frozen fixtures (no network), open it, and check
//! what the matcher would see.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use unpatched_core::{Bucket, CatalogEntry, Config, Dataset, SourceId, SsvcExploitation, evaluate};
use unpatched_db::{BuildOptions, Db, DbError, SCHEMA_VERSION, build};
use unpatched_sources::Http;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn catalog() -> Vec<CatalogEntry> {
    let text = std::fs::read_to_string(fixtures().join("db/catalog.yml")).unwrap();
    serde_norway::from_str(&text).unwrap()
}

fn built_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 23, 12, 0, 0).unwrap()
}

fn opts(out: &Path) -> BuildOptions {
    BuildOptions {
        cvelist: Some(fixtures().join("db/cvelist")),
        out: out.to_path_buf(),
        offline_fixtures: Some(fixtures()),
        built_at: Some(built_at()),
        ..BuildOptions::default()
    }
}

fn build_to(out: &Path) -> unpatched_db::BuildSummary {
    build(&opts(out), &catalog(), &Http::new().unwrap()).unwrap()
}

fn fixture_db() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("db.sqlite");
    build_to(&out);
    let db = Db::open(&out).unwrap();
    (dir, db)
}

#[test]
fn summary_counts() {
    let dir = tempfile::tempdir().unwrap();
    let s = build_to(&dir.path().join("db.sqlite"));
    assert_eq!(s.products, 7);
    assert_eq!(s.verified_products, 6);
    assert_eq!(s.kev, 7);
    assert_eq!(s.epss, 8);
    assert!(s.vulns >= 5, "{s:?}");
    assert!(s.sources.iter().all(|x| x.ok), "{:?}", s.sources);
    assert!(s.raw_bytes > 0 && s.raw_bytes == s.out_bytes);
}

#[test]
fn fortios_has_ranges_from_both_sources() {
    let (_dir, db) = fixture_db();
    let vulns = db.vulns_for_product("fortios");
    let v = vulns
        .iter()
        .find(|v| v.id == "CVE-2024-21762")
        .expect("CVE-2024-21762");
    let sources: Vec<SourceId> = v
        .ranges
        .iter()
        .filter(|r| r.product == "fortios")
        .map(|r| r.source)
        .collect();
    assert!(sources.contains(&SourceId::CveOrg), "{sources:?}");
    assert!(sources.contains(&SourceId::Nvd), "{sources:?}");
    assert!(!v.summary.is_empty());
    assert!(v.cvss.is_some());
    // One vulnerability per id, even though two sources know it.
    assert_eq!(vulns.iter().filter(|x| x.id == v.id).count(), 1);
    assert_eq!(db.vuln("cve-2024-21762").unwrap().id, "CVE-2024-21762");
    assert!(db.vuln("CVE-1999-0000").is_none());
}

#[test]
fn signals_combine_all_tables() {
    let (_dir, db) = fixture_db();
    let s = db.signals("CVE-2024-21762");
    let kev = s.kev.expect("in KEV");
    assert_eq!(kev.vendor_project, "Fortinet");
    let epss = s.epss.expect("has EPSS");
    assert!(epss.score > 0.0 && epss.score <= 1.0);
    assert_eq!(s.ssvc_exploitation, Some(SsvcExploitation::Active));
    assert!(s.ssvc_automatable.is_some());

    let log4j = db.signals("CVE-2021-44228");
    assert!(!log4j.exploits.is_empty(), "exploit refs: {log4j:?}");
    assert!(
        log4j
            .exploits
            .iter()
            .any(|e| e.source == SourceId::Metasploit)
    );

    let none = db.signals("CVE-1999-9999");
    assert!(none.kev.is_none() && none.epss.is_none() && none.exploits.is_empty());
}

#[test]
fn eol_and_product_lookup() {
    let (_dir, db) = fixture_db();
    let cycles = db.eol_cycles("nextcloud");
    assert!(!cycles.is_empty());
    assert!(db.eol_cycles("fortios").is_empty());

    assert_eq!(db.product("fortios").unwrap().id, "fortios");
    assert_eq!(db.product("FortiGate").unwrap().id, "fortios");
    assert_eq!(db.product("FORTIOS").unwrap().name, "FortiOS");
    assert!(db.product("nope").is_none());
    assert_eq!(db.product_ids().len(), 7);
}

#[test]
fn verified_flag() {
    let (_dir, db) = fixture_db();
    for id in [
        "fortios",
        "nextcloud",
        "ivanti-connect-secure",
        "citrix-netscaler",
        "apache-httpd",
        "linux-kernel",
    ] {
        assert!(db.product_verified(id), "{id} should be verified");
    }
    assert!(!db.product_verified("synology-dsm"));
    assert!(!db.product_verified("not-in-catalog"));
}

#[test]
fn info_has_sources() {
    let (_dir, db) = fixture_db();
    let info = db.info();
    assert_eq!(info.schema_version, SCHEMA_VERSION);
    assert_eq!(info.built_at, built_at());
    assert!(
        info.sources
            .iter()
            .any(|s| s.source == SourceId::Kev && s.ok)
    );
    assert_eq!(Dataset::info(&db), Some(info));
}

#[test]
fn zst_round_trip_reuses_the_unpacked_file() {
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("raw.sqlite");
    let zst = dir.path().join("unpatched-db.sqlite.zst");
    let a = build_to(&raw);
    let b = build_to(&zst);
    assert!(
        b.out_bytes < a.out_bytes,
        "{} vs {}",
        b.out_bytes,
        a.out_bytes
    );

    let from_raw = Db::open(&raw).unwrap();
    let from_zst = Db::open(&zst).unwrap();
    assert_eq!(from_raw.vuln_ids(), from_zst.vuln_ids());
    assert_eq!(from_raw.product_ids(), from_zst.product_ids());
    let first = from_zst.file().to_path_buf();
    assert!(first.to_string_lossy().ends_with(".sqlite"));
    assert_ne!(first, zst);

    let again = Db::open(&zst).unwrap();
    assert_eq!(again.file(), first);
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    build_to(&path);
    {
        let c = Connection::open(&path).unwrap();
        c.execute(
            "UPDATE meta SET value = '2' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
    }
    let err = Db::open(&path).unwrap_err();
    assert!(
        matches!(err, DbError::NewerSchema { found: 2, .. }),
        "{err}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("needs a newer unpatched") && msg.contains("unpatched db update"),
        "{msg}"
    );
}

#[test]
fn garbage_and_missing_files_say_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.sqlite");
    std::fs::write(
        &junk,
        b"definitely not sqlite, just some text that is long enough",
    )
    .unwrap();
    let err = Db::open(&junk).unwrap_err();
    assert!(matches!(err, DbError::NotADatabase { .. }), "{err}");
    assert!(err.to_string().contains("unpatched db update"));
    assert!(Db::open(&dir.path().join("missing.sqlite")).is_err());
}

#[test]
fn kev_failure_fails_the_build_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let off = dir.path().join("off");
    std::fs::create_dir_all(off.join("nvd")).unwrap();
    std::fs::copy(
        fixtures().join("nvd/nvdcve-2.0-slice.json"),
        off.join("nvd/nvdcve-2.0-slice.json"),
    )
    .unwrap();
    let out = dir.path().join("out.sqlite");
    let mut o = opts(&out);
    o.offline_fixtures = Some(off);
    let err = build(&o, &catalog(), &Http::new().unwrap()).unwrap_err();
    assert!(matches!(err, DbError::RequiredSource { .. }), "{err}");
    assert!(!out.exists());
}

#[test]
fn optional_source_failure_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let off = dir.path().join("off");
    for rel in [
        "kev/known_exploited_vulnerabilities.json",
        "nvd/nvdcve-2.0-slice.json",
    ] {
        let to = off.join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(fixtures().join(rel), to).unwrap();
    }
    let out = dir.path().join("out.sqlite");
    let mut o = opts(&out);
    o.offline_fixtures = Some(off);
    o.cvelist = None;
    let s = build(&o, &catalog(), &Http::new().unwrap()).unwrap();
    let epss = s
        .sources
        .iter()
        .find(|x| x.source == SourceId::Epss)
        .unwrap();
    assert!(!epss.ok && epss.note.is_some());
    assert!(!s.sources.iter().any(|x| x.source == SourceId::CveOrg));
    let db = Db::open(&out).unwrap();
    assert!(
        db.info()
            .sources
            .iter()
            .any(|x| x.source == SourceId::Epss && !x.ok)
    );
    // NVD alone still gives FortiOS ranges.
    assert!(
        db.vulns_for_product("fortios")
            .iter()
            .any(|v| v.id == "CVE-2024-21762")
    );
}

#[test]
fn end_to_end_fortios_now_finding() {
    let (_dir, db) = fixture_db();
    let cfg: Config = serde_norway::from_str(
        "version: 1\nstack:\n  - product: fortios\n    version: 7.2.5\n    exposure: internet\n",
    )
    .unwrap();
    let report = evaluate(
        &cfg,
        &db,
        &HashMap::new(),
        built_at() + chrono::Duration::days(1),
    );
    let f = report
        .findings
        .iter()
        .find(|f| f.vuln.as_deref() == Some("CVE-2024-21762"))
        .unwrap_or_else(|| panic!("no finding: {report:#?}"));
    assert_eq!(f.bucket, Bucket::Now);
    assert!(f.fixed_in.is_some(), "{f:?}");
    assert!(f.signals.kev.is_some());
}

#[test]
fn committed_smoke_db_is_current() {
    let smoke = fixtures().join("smoke/unpatched-db.sqlite");
    let committed =
        Db::open(&smoke).expect("run `cargo run -p unpatched-db --example build_fixture_db`");
    let (_dir, fresh) = fixture_db();
    assert_eq!(committed.vuln_ids(), fresh.vuln_ids());
    assert_eq!(committed.product_ids(), fresh.product_ids());
    assert_eq!(committed.info().built_at, fresh.info().built_at);
    assert!(std::fs::metadata(&smoke).unwrap().len() < 1_000_000);
}

#[test]
fn strict_build_passes_when_every_source_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("db.sqlite");
    let o = BuildOptions {
        strict: true,
        ..opts(&out)
    };
    build(&o, &catalog(), &Http::new().unwrap()).unwrap();
    assert!(out.is_file());
}

#[test]
fn strict_build_writes_nothing_when_a_source_failed() {
    let dir = tempfile::tempdir().unwrap();
    // Fixtures without the EPSS files: that source fails, the rest is fine.
    let fx = dir.path().join("fixtures");
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_owned();
        if name == "epss" || !path.is_dir() {
            continue;
        }
        let dest = fx.join(&name);
        std::fs::create_dir_all(&dest).unwrap();
        copy_dir(&path, &dest);
    }
    let out = dir.path().join("db.sqlite");
    let loose = BuildOptions {
        offline_fixtures: Some(fx.clone()),
        ..opts(&out)
    };
    let sum = build(&loose, &catalog(), &Http::new().unwrap()).unwrap();
    assert!(sum.sources.iter().any(|s| !s.ok), "{:?}", sum.sources);
    std::fs::remove_file(&out).unwrap();

    let strict = BuildOptions {
        strict: true,
        ..loose
    };
    let err = build(&strict, &catalog(), &Http::new().unwrap()).unwrap_err();
    assert!(err.to_string().contains("--strict"), "{err}");
    assert!(!out.exists());
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let dest = to.join(path.file_name().unwrap());
        if path.is_dir() {
            std::fs::create_dir_all(&dest).unwrap();
            copy_dir(&path, &dest);
        } else {
            std::fs::copy(&path, &dest).unwrap();
        }
    }
}

#[test]
fn unknown_source_in_a_range_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    build_to(&path);
    {
        let c = Connection::open(&path).unwrap();
        let n = c
            .execute(
                "UPDATE ranges SET source = 'future-feed' WHERE rowid = (SELECT MIN(rowid) FROM ranges)",
                [],
            )
            .unwrap();
        assert_eq!(n, 1);
    }
    let err = Db::open(&path).unwrap_err();
    assert!(matches!(err, DbError::UnknownSource { .. }), "{err}");
    let msg = err.to_string();
    assert!(
        msg.contains("needs a newer unpatched") && msg.contains("future-feed"),
        "{msg}"
    );
}
