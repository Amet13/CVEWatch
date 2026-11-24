use std::collections::HashMap;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};

use super::memory::MemoryDataset;
use super::*;
use crate::catalog::{MatchKeys, ProductKind};
use crate::model::{Cvss, Epss, ExploitRef, KevEntry, Reference, SourceStatus};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 23, 6, 0, 0).unwrap()
}

fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

fn entry(id: &str, scheme: Scheme) -> CatalogEntry {
    CatalogEntry {
        id: id.into(),
        name: id.to_uppercase(),
        vendor: "Acme".into(),
        kind: ProductKind::Appliance,
        versioning: scheme,
        keys: MatchKeys::default(),
        eol: None,
        aliases: vec![],
        homepage: None,
        checked: date(2026, 11, 1),
    }
}

fn bound(v: &str, inclusive: bool) -> Bound {
    Bound {
        version: v.into(),
        inclusive,
    }
}

/// `start <= v < end`
fn between(start: &str, end: &str) -> Constraint {
    Constraint::Range {
        start: Some(bound(start, true)),
        end: Some(bound(end, false)),
    }
}

fn range(source: SourceId, product: &str, constraints: Vec<Constraint>) -> AffectedRange {
    AffectedRange {
        source,
        product: product.into(),
        constraints,
        unaffected: vec![],
        raw: String::new(),
    }
}

fn vuln(id: &str, ranges: Vec<AffectedRange>) -> Vulnerability {
    Vulnerability {
        id: id.into(),
        aliases: vec![],
        summary: format!("Problem in {id}"),
        published: Some(date(2026, 1, 1)),
        modified: None,
        status: VulnStatus::Published,
        cvss: None,
        ranges,
        references: vec![],
    }
}

/// A vulnerability in `fortios` affecting `7.2.0 <= v < 7.2.6`, per CVE.org.
fn fortios_vuln(id: &str) -> Vulnerability {
    vuln(
        id,
        vec![range(
            SourceId::CveOrg,
            "fortios",
            vec![between("7.2.0", "7.2.6")],
        )],
    )
}

fn kev() -> KevEntry {
    KevEntry {
        date_added: date(2026, 2, 1),
        due_date: None,
        known_ransomware: false,
        required_action: "Apply updates".into(),
        vendor_project: "Acme".into(),
        product: "FortiOS".into(),
    }
}

fn exploit() -> ExploitRef {
    ExploitRef {
        source: SourceId::ExploitDb,
        id: "12345".into(),
        url: None,
    }
}

fn epss(score: f64) -> Epss {
    Epss {
        score,
        percentile: 0.9,
        date: date(2026, 11, 22),
    }
}

fn fresh_info() -> DbInfo {
    DbInfo {
        schema_version: 1,
        built_at: Utc.with_ymd_and_hms(2026, 11, 23, 2, 41, 0).unwrap(),
        sources: vec![SourceStatus {
            source: SourceId::CveOrg,
            fetched_at: Utc.with_ymd_and_hms(2026, 11, 23, 2, 0, 0).unwrap(),
            records: 100,
            ok: true,
            note: None,
        }],
    }
}

fn base_data() -> MemoryDataset {
    MemoryDataset::new()
        .with_product(entry("fortios", Scheme::Dotted))
        .with_info(fresh_info())
}

fn config(stack: Vec<StackItem>) -> Config {
    Config {
        version: 1,
        stack,
        ignore: vec![],
        thresholds: Thresholds::default(),
        notify: crate::config::Notify::default(),
        digest: "monday".into(),
    }
}

fn item(product: &str, version: &str, exposure: Exposure) -> StackItem {
    StackItem {
        product: Some(product.into()),
        purl: None,
        version: Some(version.into()),
        exposure,
        name: None,
    }
}

fn run(config: &Config, data: &MemoryDataset) -> Report {
    evaluate(config, data, &HashMap::new(), now())
}

fn one(config: &Config, data: &MemoryDataset) -> Finding {
    let r = run(config, data);
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
    r.findings.into_iter().next().unwrap()
}

fn with_cvss(mut v: Vulnerability, score: f64) -> Vulnerability {
    v.cvss = Some(Cvss {
        version: "3.1".into(),
        score,
        vector: None,
    });
    v
}

fn fortios_cfg(version: &str, exposure: Exposure) -> Config {
    config(vec![item("fortios", version, exposure)])
}

// ---- buckets and rules ----

#[test]
fn kev_means_now() {
    let data = base_data()
        .with_vuln(fortios_vuln("CVE-2026-0001"))
        .with_signals(
            "CVE-2026-0001",
            Signals {
                kev: Some(kev()),
                ..Signals::default()
            },
        );
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.bucket, Bucket::Now);
    assert_eq!(f.verdict, Verdict::Affected);
    assert_eq!(f.rules, vec![RuleId::Kev]);
    assert_eq!(f.fixed_in.as_deref(), Some("7.2.6"));
    assert_eq!(f.key, "fortios/CVE-2026-0001");
    assert_eq!(f.product, "fortios");
    assert_eq!(f.product_name, "FORTIOS");
    assert_eq!(f.vuln.as_deref(), Some("CVE-2026-0001"));
    assert_eq!(f.evidence.len(), 1);
    assert_eq!(f.evidence[0].verdict, Verdict::Affected);
    assert!(
        f.evidence[0].detail.contains("7.2.5"),
        "{}",
        f.evidence[0].detail
    );
}

#[test]
fn ssvc_active_means_now() {
    let data = base_data()
        .with_vuln(fortios_vuln("CVE-2026-0002"))
        .with_signals(
            "CVE-2026-0002",
            Signals {
                ssvc_exploitation: Some(SsvcExploitation::Active),
                ..Signals::default()
            },
        );
    let f = one(&fortios_cfg("7.2.0", Exposure::Internal), &data);
    assert_eq!((f.bucket, f.rules), (Bucket::Now, vec![RuleId::SsvcActive]));
}

#[test]
fn ssvc_poc_is_not_enough() {
    let data = base_data()
        .with_vuln(fortios_vuln("CVE-2026-0002"))
        .with_signals(
            "CVE-2026-0002",
            Signals {
                ssvc_exploitation: Some(SsvcExploitation::Poc),
                ..Signals::default()
            },
        );
    let f = one(&fortios_cfg("7.2.0", Exposure::Internal), &data);
    assert_eq!(f.bucket, Bucket::Fyi);
}

#[test]
fn exploit_matters_only_when_internet_facing() {
    let signals = Signals {
        exploits: vec![exploit()],
        ..Signals::default()
    };
    let data = base_data()
        .with_vuln(fortios_vuln("CVE-2026-0003"))
        .with_signals("CVE-2026-0003", signals);
    let f = one(&fortios_cfg("7.2.1", Exposure::Internet), &data);
    assert_eq!(f.bucket, Bucket::Now);
    assert_eq!(f.rules, vec![RuleId::ExploitExposed]);
    let f = one(&fortios_cfg("7.2.1", Exposure::Internal), &data);
    assert_eq!(f.bucket, Bucket::Fyi);
    assert_eq!(f.rules, vec![RuleId::Affected]);
}

#[test]
fn epss_cvss_and_exposure_mean_week() {
    let mut v = fortios_vuln("CVE-2026-0004");
    v.cvss = Some(Cvss {
        version: "3.1".into(),
        score: 9.8,
        vector: None,
    });
    let data = base_data().with_vuln(v).with_signals(
        "CVE-2026-0004",
        Signals {
            epss: Some(epss(0.5)),
            ..Signals::default()
        },
    );
    let f = one(&fortios_cfg("7.2.1", Exposure::Internet), &data);
    assert_eq!(f.bucket, Bucket::Week);
    assert_eq!(f.rules, vec![RuleId::Epss, RuleId::Cvss, RuleId::Exposed]);
    assert!(f.cvss.is_some());

    // Each alone is enough.
    let only_epss = base_data().with_vuln(fortios_vuln("CVE-1")).with_signals(
        "CVE-1",
        Signals {
            epss: Some(epss(0.05)),
            ..Signals::default()
        },
    );
    let f = one(&fortios_cfg("7.2.1", Exposure::Internal), &only_epss);
    assert_eq!((f.bucket, f.rules), (Bucket::Week, vec![RuleId::Epss]));

    let mut v = fortios_vuln("CVE-2");
    v.cvss = Some(Cvss {
        version: "3.1".into(),
        score: 9.0,
        vector: None,
    });
    let f = one(
        &fortios_cfg("7.2.1", Exposure::Internal),
        &base_data().with_vuln(v),
    );
    assert_eq!((f.bucket, f.rules), (Bucket::Week, vec![RuleId::Cvss]));

    // Exposure alone is not enough; it needs CVSS at or above `cvss_week_exposed`.
    let f = one(
        &fortios_cfg("7.2.1", Exposure::Internet),
        &base_data().with_vuln(with_cvss(fortios_vuln("CVE-3"), 7.0)),
    );
    assert_eq!((f.bucket, f.rules), (Bucket::Week, vec![RuleId::Exposed]));
}

#[test]
fn internet_alone_is_not_week() {
    let cfg = fortios_cfg("7.2.1", Exposure::Internet);
    // No CVSS.
    let f = one(&cfg, &base_data().with_vuln(fortios_vuln("CVE-3")));
    assert_eq!((f.bucket, f.rules), (Bucket::Fyi, vec![RuleId::Affected]));
    // Below the exposed threshold.
    let v = with_cvss(fortios_vuln("CVE-3"), 6.9);
    let f = one(&cfg, &base_data().with_vuln(v));
    assert_eq!(f.bucket, Bucket::Fyi);
    // At the threshold but not internet-facing.
    let v = with_cvss(fortios_vuln("CVE-3"), 8.0);
    let f = one(
        &fortios_cfg("7.2.1", Exposure::Internal),
        &base_data().with_vuln(v),
    );
    assert_eq!(f.bucket, Bucket::Fyi);
    // The threshold is configurable.
    let mut cfg = cfg;
    cfg.thresholds.cvss_week_exposed = 5.0;
    let v = with_cvss(fortios_vuln("CVE-3"), 6.9);
    let f = one(&cfg, &base_data().with_vuln(v));
    assert_eq!((f.bucket, f.rules), (Bucket::Week, vec![RuleId::Exposed]));
}

#[test]
fn thresholds_come_from_config() {
    let data = base_data().with_vuln(fortios_vuln("CVE-1")).with_signals(
        "CVE-1",
        Signals {
            epss: Some(epss(0.02)),
            ..Signals::default()
        },
    );
    let mut cfg = fortios_cfg("7.2.1", Exposure::Internal);
    assert_eq!(one(&cfg, &data).bucket, Bucket::Fyi);
    cfg.thresholds.epss_week = 0.01;
    assert_eq!(one(&cfg, &data).bucket, Bucket::Week);
}

#[test]
fn plain_affected_is_fyi() {
    let f = one(
        &fortios_cfg("7.2.3", Exposure::Internal),
        &base_data().with_vuln(fortios_vuln("CVE-9")),
    );
    assert_eq!((f.bucket, f.rules), (Bucket::Fyi, vec![RuleId::Affected]));
}

// ---- verdicts ----

#[test]
fn outside_the_range_is_not_affected_and_counted() {
    let data = base_data().with_vuln(fortios_vuln("CVE-9"));
    for v in ["7.1.9", "7.2.6", "7.4.0"] {
        let r = run(&fortios_cfg(v, Exposure::Internet), &data);
        assert!(r.findings.is_empty(), "{v}");
        assert_eq!(r.summary.not_affected, 1, "{v}");
    }
}

#[test]
fn unaffected_constraints_win() {
    let mut r = range(SourceId::CveOrg, "fortios", vec![between("7.0.0", "8.0.0")]);
    r.unaffected = vec![Constraint::Exact {
        version: "7.2.5".into(),
    }];
    let data = base_data().with_vuln(vuln("CVE-9", vec![r]));
    let out = run(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert!(out.findings.is_empty());
    assert_eq!(out.summary.not_affected, 1);
    let out = run(&fortios_cfg("7.2.4", Exposure::Internal), &data);
    assert_eq!(out.findings.len(), 1);
}

#[test]
fn unknown_with_signals_is_reported() {
    let data = base_data()
        .with_vuln(vuln(
            "CVE-2026-7",
            vec![range(SourceId::Nvd, "fortios", vec![])],
        ))
        .with_signals(
            "CVE-2026-7",
            Signals {
                kev: Some(kev()),
                ..Signals::default()
            },
        );
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.verdict, Verdict::Unknown);
    assert_eq!(f.bucket, Bucket::Unknown);
    assert_eq!(f.rules, vec![RuleId::UnknownNoRanges, RuleId::Kev]);
    assert_eq!(f.fixed_in, None);
}

#[test]
fn unknown_without_urgency_is_dropped_and_not_counted() {
    let data = base_data().with_vuln(vuln(
        "CVE-2026-7",
        vec![range(SourceId::Nvd, "fortios", vec![])],
    ));
    let r = run(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert!(r.findings.is_empty());
    assert_eq!(r.summary, Summary::default());
    // Internet-facing alone is not urgent either.
    let r = run(&fortios_cfg("7.2.5", Exposure::Internet), &data);
    assert!(r.findings.is_empty());
    // Internet-facing and severe makes it a `week` candidate, so it is kept.
    let data = base_data().with_vuln(with_cvss(
        vuln("CVE-2026-7", vec![range(SourceId::Nvd, "fortios", vec![])]),
        8.1,
    ));
    let r = run(&fortios_cfg("7.2.5", Exposure::Internet), &data);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].bucket, Bucket::Unknown);
}

#[test]
fn unparseable_item_version_is_unknown_with_a_note() {
    let data = base_data().with_vuln(with_cvss(fortios_vuln("CVE-1"), 8.0));
    let r = run(&fortios_cfg("not-a-version", Exposure::Internet), &data);
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.verdict, Verdict::Unknown);
    assert_eq!(f.bucket, Bucket::Unknown);
    assert_eq!(f.rules[0], RuleId::UnknownVersion);
    assert!(f.evidence[0].detail.contains("cannot compare"));
    assert_eq!(r.notes.len(), 1);
}

#[test]
fn unparseable_bound_in_data_is_unknown() {
    let data = base_data().with_vuln(with_cvss(
        vuln(
            "CVE-1",
            vec![range(
                SourceId::CveOrg,
                "fortios",
                vec![between("7.2.0", "seven")],
            )],
        ),
        8.0,
    ));
    let f = one(&fortios_cfg("7.2.5", Exposure::Internet), &data);
    assert_eq!(f.verdict, Verdict::Unknown);
    assert_eq!(f.rules[0], RuleId::UnknownVersion);
}

#[test]
fn sources_disagreeing_report_a_conflict() {
    let data = base_data().with_vuln(vuln(
        "CVE-2026-5",
        vec![
            range(SourceId::CveOrg, "fortios", vec![between("7.2.0", "7.2.6")]),
            range(SourceId::Nvd, "fortios", vec![between("7.0.0", "7.2.4")]),
        ],
    ));
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.verdict, Verdict::Affected);
    assert_eq!(f.rules, vec![RuleId::Affected, RuleId::Conflict]);
    assert_eq!(f.evidence.len(), 2);
    assert_eq!(f.evidence[0].source, SourceId::CveOrg);
    assert_eq!(f.evidence[0].verdict, Verdict::Affected);
    assert_eq!(f.evidence[1].source, SourceId::Nvd);
    assert_eq!(f.evidence[1].verdict, Verdict::NotAffected);
}

#[test]
fn all_sources_agreeing_not_affected_is_not_affected() {
    let data = base_data().with_vuln(vuln(
        "CVE-2026-5",
        vec![
            range(SourceId::CveOrg, "fortios", vec![between("7.2.0", "7.2.6")]),
            range(SourceId::Nvd, "fortios", vec![between("7.2.0", "7.2.6")]),
            // A source without data does not block the verdict.
            range(SourceId::Osv, "fortios", vec![]),
        ],
    ));
    let r = run(&fortios_cfg("7.3.0", Exposure::Internet), &data);
    assert!(r.findings.is_empty());
    assert_eq!(r.summary.not_affected, 1);
}

#[test]
fn not_affected_plus_unparseable_source_is_unknown() {
    let data = base_data().with_vuln(with_cvss(
        vuln(
            "CVE-2026-5",
            vec![
                range(SourceId::CveOrg, "fortios", vec![between("7.2.0", "7.2.6")]),
                range(SourceId::Nvd, "fortios", vec![between("a", "b")]),
            ],
        ),
        8.0,
    ));
    let r = run(&fortios_cfg("7.3.0", Exposure::Internet), &data);
    assert_eq!(r.summary.not_affected, 0);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].verdict, Verdict::Unknown);
}

#[test]
fn ranges_for_other_products_are_ignored() {
    let data = base_data().with_vuln(vuln(
        "CVE-1",
        vec![
            range(SourceId::CveOrg, "fortios", vec![between("7.2.0", "7.2.6")]),
            range(SourceId::Nvd, "fortiproxy", vec![Constraint::All]),
        ],
    ));
    let f = one(&fortios_cfg("7.2.1", Exposure::Internal), &data);
    assert_eq!(f.evidence.len(), 1);
}

#[test]
fn rejected_skipped_and_disputed_marked() {
    let mut rejected = fortios_vuln("CVE-R");
    rejected.status = VulnStatus::Rejected;
    let mut disputed = fortios_vuln("CVE-D");
    disputed.status = VulnStatus::Disputed;
    let data = base_data().with_vuln(rejected).with_vuln(disputed);
    let r = run(&fortios_cfg("7.2.1", Exposure::Internal), &data);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].vuln.as_deref(), Some("CVE-D"));
    assert!(r.findings[0].title.ends_with(" (disputed)"));
    assert_eq!(r.summary.not_affected, 0);
}

// ---- upgrade targets ----

#[test]
fn fixed_in_is_the_smallest_end_above_the_version() {
    let data = base_data().with_vuln(vuln(
        "CVE-1",
        vec![
            range(
                SourceId::CveOrg,
                "fortios",
                vec![between("7.0.0", "7.0.14"), between("7.2.0", "7.2.9")],
            ),
            range(SourceId::Nvd, "fortios", vec![between("7.2.0", "7.2.7")]),
        ],
    ));
    let f = one(&fortios_cfg("7.2.1", Exposure::Internal), &data);
    assert_eq!(f.fixed_in.as_deref(), Some("7.2.7"));
}

#[test]
fn inclusive_end_alone_gives_no_fixed_version_but_a_hint() {
    let data = base_data().with_vuln(vuln(
        "CVE-1",
        vec![range(
            SourceId::CveOrg,
            "fortios",
            vec![Constraint::Range {
                start: None,
                end: Some(bound("7.2.5", true)),
            }],
        )],
    ));
    let f = one(&fortios_cfg("7.2.1", Exposure::Internal), &data);
    assert_eq!(f.fixed_in, None);
    assert!(f.evidence[0].detail.contains("up to and including 7.2.5"));
}

#[test]
fn latest_in_cycle_comes_from_the_longest_matching_cycle() {
    let cycle = |c: &str, latest: &str| EolCycle {
        cycle: c.into(),
        release_date: None,
        eol: None,
        eol_reached: false,
        latest: Some(latest.into()),
        lts: false,
    };
    let data = base_data().with_vuln(fortios_vuln("CVE-1")).with_eol(
        "fortios",
        vec![
            cycle("7", "7.6.0"),
            cycle("7.2", "7.2.9"),
            cycle("7.20", "7.20.1"),
        ],
    );
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.latest_in_cycle.as_deref(), Some("7.2.9"));
    // Already on the latest: nothing to say.
    let data = base_data()
        .with_vuln(vuln(
            "CVE-1",
            vec![range(SourceId::CveOrg, "fortios", vec![Constraint::All])],
        ))
        .with_eol("fortios", vec![cycle("7.2", "7.2.5")]);
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.latest_in_cycle, None);
}

#[test]
fn single_component_cycles_match() {
    let cycles = vec![EolCycle {
        cycle: "29".into(),
        release_date: None,
        eol: None,
        eol_reached: false,
        latest: Some("29.0.9".into()),
        lts: false,
    }];
    assert_eq!(
        find_cycle(&cycles, "29.0.3").map(|c| c.cycle.as_str()),
        Some("29")
    );
    assert_eq!(
        find_cycle(&cycles, "v29").map(|c| c.cycle.as_str()),
        Some("29")
    );
    assert!(find_cycle(&cycles, "290.0").is_none());
    assert!(find_cycle(&cycles, "2.9").is_none());
}

// ---- EOL ----

fn eol_cycle(cycle: &str, eol: Option<NaiveDate>, reached: bool) -> EolCycle {
    EolCycle {
        cycle: cycle.into(),
        release_date: None,
        eol,
        eol_reached: reached,
        latest: None,
        lts: false,
    }
}

#[test]
fn eol_by_date_today_counts() {
    for (eol, expect) in [
        (date(2026, 11, 22), true),
        (date(2026, 11, 23), true),
        (date(2026, 11, 24), false),
    ] {
        let data = base_data().with_eol("fortios", vec![eol_cycle("7.2", Some(eol), false)]);
        let r = run(&fortios_cfg("7.2.5", Exposure::Internal), &data);
        assert_eq!(r.findings.len(), usize::from(expect), "{eol}");
        if expect {
            let f = &r.findings[0];
            assert_eq!(f.bucket, Bucket::Eol);
            assert_eq!(f.rules, vec![RuleId::Eol]);
            assert_eq!(f.vuln, None);
            assert_eq!(f.key, "fortios/eol");
            assert_eq!(r.summary.eol, 1);
        }
    }
}

#[test]
fn eol_reached_flag_without_a_date() {
    let data = base_data().with_eol("fortios", vec![eol_cycle("7.2", None, true)]);
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.bucket, Bucket::Eol);
    assert!(f.evidence[0].detail.contains("unknown date"));
}

#[test]
fn eol_is_one_finding_per_item_not_per_cve() {
    let data = base_data()
        .with_vuln(fortios_vuln("CVE-1"))
        .with_vuln(fortios_vuln("CVE-2"))
        .with_eol(
            "fortios",
            vec![eol_cycle("7.2", Some(date(2025, 1, 1)), true)],
        );
    let r = run(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(
        r.findings
            .iter()
            .filter(|f| f.bucket == Bucket::Eol)
            .count(),
        1
    );
    assert_eq!(r.findings.len(), 3);
    // Sorted: EOL before FYI.
    assert_eq!(r.findings[0].bucket, Bucket::Eol);
}

// ---- products, data health ----

#[test]
fn unknown_product_is_a_note_not_a_panic() {
    let cfg = config(vec![
        item("nope", "1.0", Exposure::Internal),
        item("fortios", "7.2.1", Exposure::Internal),
    ]);
    let r = run(&cfg, &base_data().with_vuln(fortios_vuln("CVE-1")));
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.notes.len(), 1);
    assert!(r.notes[0].contains("stack[0]") && r.notes[0].contains("nope"));
}

#[test]
fn unverified_product_is_flagged() {
    let data = base_data().with_unverified("fortios");
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.key, "fortios/unverified");
    assert_eq!(f.bucket, Bucket::Unknown);
    assert_eq!(f.rules, vec![RuleId::UnverifiedProduct]);
    assert_eq!(f.vuln, None);
}

#[test]
fn stale_data_is_a_note_and_a_finding() {
    let mut info = fresh_info();
    info.built_at = Utc.with_ymd_and_hms(2026, 11, 19, 2, 41, 0).unwrap();
    let data = base_data().with_info(info);
    let r = run(&config(vec![]), &data);
    assert_eq!(r.notes.len(), 1);
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.key, "data/stale");
    assert_eq!(f.item, "database");
    assert_eq!(f.rules, vec![RuleId::StaleData]);
    assert_eq!(f.bucket, Bucket::Unknown);

    // Exactly at the threshold is still fresh.
    let mut info = fresh_info();
    info.built_at = now() - Duration::days(3);
    let r = run(&config(vec![]), &base_data().with_info(info));
    assert!(r.findings.is_empty() && r.notes.is_empty());
}

#[test]
fn missing_db_info_is_noted() {
    let mut data = base_data();
    data.info = None;
    let r = run(&config(vec![]), &data);
    assert_eq!(r.notes.len(), 1);
    assert!(r.db.is_none());
}

// ---- ignores ----

fn ignore(cve: &str, product: Option<&str>, until: NaiveDate) -> Ignore {
    Ignore {
        cve: cve.into(),
        product: product.map(Into::into),
        reason: "app disabled".into(),
        until,
    }
}

#[test]
fn active_ignore_moves_the_finding() {
    let data = base_data().with_vuln(fortios_vuln("CVE-2026-0001"));
    let mut cfg = fortios_cfg("7.2.5", Exposure::Internal);
    cfg.ignore = vec![ignore("cve-2026-0001", None, date(2026, 11, 23))];
    let r = run(&cfg, &data);
    assert!(r.findings.is_empty());
    assert_eq!(r.ignored.len(), 1);
    assert_eq!(r.summary.ignored, 1);
    assert_eq!(r.summary.fyi, 0);
    let f = &r.ignored[0];
    assert_eq!(f.rules[0], RuleId::Ignored);
    let why = f.ignored.as_ref().unwrap();
    assert_eq!(why.reason, "app disabled");
    assert_eq!(why.until, date(2026, 11, 23));
}

#[test]
fn expired_ignore_keeps_the_finding_with_a_rule() {
    let data = base_data().with_vuln(fortios_vuln("CVE-2026-0001"));
    let mut cfg = fortios_cfg("7.2.5", Exposure::Internal);
    cfg.ignore = vec![ignore("CVE-2026-0001", None, date(2026, 11, 22))];
    let r = run(&cfg, &data);
    assert!(r.ignored.is_empty());
    let f = &r.findings[0];
    assert_eq!(f.rules, vec![RuleId::Affected, RuleId::IgnoreExpired]);
    assert!(f.ignored.is_none());
}

#[test]
fn a_newer_ignore_beats_an_expired_one() {
    let data = base_data().with_vuln(fortios_vuln("CVE-2026-0001"));
    let mut cfg = fortios_cfg("7.2.5", Exposure::Internal);
    cfg.ignore = vec![
        ignore("CVE-2026-0001", None, date(2026, 1, 1)),
        ignore("CVE-2026-0001", None, date(2027, 1, 1)),
    ];
    let r = run(&cfg, &data);
    assert_eq!(r.ignored.len(), 1);
    assert_eq!(
        r.ignored[0].ignored.as_ref().unwrap().until,
        date(2027, 1, 1)
    );
}

#[test]
fn ignore_matches_aliases_and_product_or_name() {
    let mut v = fortios_vuln("GHSA-aaaa-bbbb-cccc");
    v.aliases = vec!["CVE-2026-0042".into()];
    let data = base_data().with_vuln(v);
    let mut named = item("fortios", "7.2.5", Exposure::Internal);
    named.name = Some("Office firewall".into());
    let mut cfg = config(vec![named]);

    cfg.ignore = vec![ignore("CVE-2026-0042", Some("fortios"), date(2027, 1, 1))];
    assert_eq!(run(&cfg, &data).ignored.len(), 1);
    cfg.ignore = vec![ignore(
        "CVE-2026-0042",
        Some("Office Firewall"),
        date(2027, 1, 1),
    )];
    assert_eq!(run(&cfg, &data).ignored.len(), 1);
    cfg.ignore = vec![ignore("CVE-2026-0042", Some("nextcloud"), date(2027, 1, 1))];
    let r = run(&cfg, &data);
    assert!(r.ignored.is_empty());
    assert_eq!(r.findings.len(), 1);
}

#[test]
fn ignoring_one_instance_leaves_the_other() {
    let data = base_data().with_vuln(fortios_vuln("CVE-1"));
    let mut a = item("fortios", "7.2.5", Exposure::Internal);
    a.name = Some("Office".into());
    let mut b = item("fortios", "7.2.4", Exposure::Internal);
    b.name = Some("Lab".into());
    let mut cfg = config(vec![a, b]);
    cfg.ignore = vec![ignore("CVE-1", Some("lab"), date(2027, 1, 1))];
    let r = run(&cfg, &data);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].item, "Office");
    assert_eq!(r.findings[0].key, "office/CVE-1");
    assert_eq!(r.ignored[0].key, "lab/CVE-1");
}

// ---- keys and sorting ----

#[test]
fn slugs() {
    assert_eq!(slug("Office firewall"), "office-firewall");
    assert_eq!(slug("pkg:deb/debian/openssl"), "pkg-deb-debian-openssl");
    assert_eq!(slug("  --A  B--"), "a-b");
    assert_eq!(slug("???"), "item");
}

#[test]
fn duplicate_items_get_distinct_keys() {
    let data = base_data().with_vuln(fortios_vuln("CVE-1"));
    let cfg = config(vec![
        item("fortios", "7.2.5", Exposure::Internal),
        item("fortios", "7.2.4", Exposure::Internal),
    ]);
    let r = run(&cfg, &data);
    let mut keys: Vec<_> = r.findings.iter().map(|f| f.key.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["fortios-2/CVE-1", "fortios/CVE-1"]);
}

#[test]
fn findings_are_sorted_by_bucket_item_vuln() {
    let data = base_data()
        .with_vuln(fortios_vuln("CVE-B"))
        .with_vuln(fortios_vuln("CVE-A"))
        .with_vuln(fortios_vuln("CVE-C"))
        .with_signals(
            "CVE-C",
            Signals {
                kev: Some(kev()),
                ..Signals::default()
            },
        );
    let r = run(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    let ids: Vec<_> = r.findings.iter().map(|f| f.vuln.clone().unwrap()).collect();
    assert_eq!(ids, vec!["CVE-C", "CVE-A", "CVE-B"]);
    assert_eq!((r.summary.now, r.summary.fyi), (1, 2));
}

// ---- purl items ----

fn purl_item(purl: &str) -> StackItem {
    StackItem {
        product: None,
        purl: Some(purl.into()),
        version: None,
        exposure: Exposure::Internal,
        name: None,
    }
}

#[test]
fn purl_items_use_package_vulns_and_the_purl_scheme() {
    let purl = "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm";
    let v = vuln(
        "CVE-2026-0100",
        vec![range(
            SourceId::Osv,
            "purl:pkg:deb/debian/openssl",
            vec![Constraint::Range {
                start: None,
                end: Some(bound("3.0.11-1~deb12u2", false)),
            }],
        )],
    );
    let mut pv = HashMap::new();
    pv.insert(purl.to_string(), vec![v]);
    let r = evaluate(&config(vec![purl_item(purl)]), &base_data(), &pv, now());
    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.verdict, Verdict::Affected);
    assert_eq!(f.fixed_in.as_deref(), Some("3.0.11-1~deb12u2"));
    assert_eq!(f.version, "3.0.11-1~deb12u1");
    assert_eq!(f.product, "pkg:deb/debian/openssl");
    assert_eq!(f.item, "pkg:deb/debian/openssl");
    assert_eq!(f.product_name, "pkg:deb/debian/openssl");
    assert_eq!(f.key, "pkg-deb-debian-openssl/CVE-2026-0100");

    // A fixed build is not affected (Debian ordering: ~deb12u2 > ~deb12u1).
    let fixed = purl.replace("deb12u1", "deb12u2");
    let mut pv2 = HashMap::new();
    pv2.insert(fixed.clone(), pv.remove(purl).unwrap());
    let r = evaluate(&config(vec![purl_item(&fixed)]), &base_data(), &pv2, now());
    assert!(r.findings.is_empty());
    assert_eq!(r.summary.not_affected, 1);
}

#[test]
fn purl_without_results_has_no_findings() {
    let r = run(
        &config(vec![purl_item("pkg:pypi/requests@2.31.0")]),
        &base_data(),
    );
    assert!(r.findings.is_empty());
    assert!(r.notes.is_empty());
}

#[test]
fn purl_percent_encoding_and_parts() {
    let p = parse_purl("pkg:npm/%40scope/name@1.0.0%2Bbuild?x=1#sub").unwrap();
    assert_eq!(p.ptype, "npm");
    assert_eq!(p.version, "1.0.0+build");
    assert_eq!(p.bare, "pkg:npm/%40scope/name");
    assert!(parse_purl("deb/openssl").is_none());
    assert!(parse_purl("pkg:openssl").is_none());
}

// ---- report shape ----

#[test]
fn empty_stack_gives_an_empty_report() {
    let r = run(&config(vec![]), &base_data());
    assert_eq!(r.format, REPORT_FORMAT);
    assert_eq!(r.generated_at, now());
    assert_eq!(r.summary, Summary::default());
    assert!(r.findings.is_empty() && r.ignored.is_empty() && r.notes.is_empty());
    assert!(r.db.is_some());
}

// ---- memory dataset ----

#[test]
fn memory_dataset_loads_from_json_and_yaml() {
    let data = base_data()
        .with_vuln(fortios_vuln("CVE-1"))
        .with_signals("CVE-1", Signals::default())
        .with_eol("fortios", vec![eol_cycle("7.2", None, false)])
        .with_unverified("other");
    let json = serde_json::to_string(&data).unwrap();
    assert_eq!(MemoryDataset::from_json(&json).unwrap(), data);
    let yaml = serde_norway::to_string(&data).unwrap();
    assert_eq!(MemoryDataset::from_yaml(&yaml).unwrap(), data);
    assert!(MemoryDataset::from_yaml("products: []\nvulns: []\n").is_ok());
    assert!(MemoryDataset::from_yaml("bogus: 1").is_err());
}

#[test]
fn memory_dataset_finds_products_by_alias() {
    let mut e = entry("nextcloud", Scheme::Dotted);
    e.aliases = vec!["nc".into()];
    let data = MemoryDataset::new().with_product(e);
    assert_eq!(data.product("NC").unwrap().id, "nextcloud");
    assert!(data.product("x").is_none());
    assert!(data.product_verified("nextcloud"));
    assert_eq!(data.signals("CVE-0"), Signals::default());
}

// ---- snapshots ----

fn rich_dataset() -> MemoryDataset {
    let mut exploited = fortios_vuln("CVE-2026-0001");
    exploited.summary = "Heap overflow in the SSL VPN portal".into();
    exploited.cvss = Some(Cvss {
        version: "3.1".into(),
        score: 9.8,
        vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
    });
    exploited.references = vec![Reference {
        url: "https://example.com/advisory/1".into(),
        tags: vec!["vendor-advisory".into()],
    }];
    let mut disagree = vuln(
        "CVE-2026-0002",
        vec![
            range(SourceId::CveOrg, "fortios", vec![between("7.2.0", "7.2.8")]),
            range(SourceId::Nvd, "fortios", vec![between("7.0.0", "7.2.3")]),
        ],
    );
    disagree.summary = "Path traversal in the admin API".into();
    let mut nodata = vuln(
        "CVE-2026-0003",
        vec![range(SourceId::Nvd, "fortios", vec![])],
    );
    nodata.summary = "Brand new, not analysed yet".into();
    let mut old = vuln(
        "CVE-2020-0009",
        vec![range(
            SourceId::CveOrg,
            "fortios",
            vec![between("6.0.0", "6.4.0")],
        )],
    );
    old.summary = "Old bug, already fixed here".into();
    let mut nextcloud_vuln = vuln(
        "CVE-2026-0050",
        vec![range(
            SourceId::CveOrg,
            "nextcloud",
            vec![Constraint::Range {
                start: None,
                end: Some(bound("29.0.4", false)),
            }],
        )],
    );
    nextcloud_vuln.summary = "Share link bypass".into();

    let mut nc = entry("nextcloud", Scheme::Dotted);
    nc.kind = ProductKind::App;
    MemoryDataset::new()
        .with_info(fresh_info())
        .with_product(entry("fortios", Scheme::Dotted))
        .with_product(nc)
        .with_vuln(exploited)
        .with_vuln(disagree)
        .with_vuln(nodata)
        .with_vuln(old)
        .with_vuln(nextcloud_vuln)
        .with_signals(
            "CVE-2026-0001",
            Signals {
                kev: Some(kev()),
                epss: Some(epss(0.91)),
                exploits: vec![exploit()],
                ..Signals::default()
            },
        )
        .with_signals(
            "CVE-2026-0003",
            Signals {
                epss: Some(epss(0.30)),
                ..Signals::default()
            },
        )
        .with_eol(
            "fortios",
            vec![EolCycle {
                cycle: "7.2".into(),
                release_date: Some(date(2022, 3, 31)),
                eol: Some(date(2025, 9, 30)),
                eol_reached: true,
                latest: Some("7.2.11".into()),
                lts: false,
            }],
        )
        .with_eol(
            "nextcloud",
            vec![EolCycle {
                cycle: "29".into(),
                release_date: Some(date(2024, 4, 1)),
                eol: Some(date(2027, 1, 1)),
                eol_reached: false,
                latest: Some("29.0.9".into()),
                lts: false,
            }],
        )
}

#[test]
fn snapshot_full_report() {
    let mut office = item("fortios", "7.2.5", Exposure::Internet);
    office.name = Some("Office firewall".into());
    let mut cfg = config(vec![
        office,
        item("nextcloud", "29.0.3", Exposure::Internal),
        item("nope", "1.0", Exposure::Internal),
    ]);
    cfg.ignore = vec![ignore(
        "CVE-2026-0050",
        Some("nextcloud"),
        date(2027, 1, 31),
    )];
    insta::assert_json_snapshot!(run(&cfg, &rich_dataset()));
}

#[test]
fn snapshot_quiet_report() {
    let cfg = config(vec![
        item("fortios", "7.4.3", Exposure::Internal),
        item("nextcloud", "29.0.9", Exposure::Internal),
    ]);
    insta::assert_json_snapshot!(run(&cfg, &rich_dataset()));
}

// ---- weak "all versions" evidence ----

fn ivanti_like(version: &str, nvd: Vec<Constraint>) -> (Config, MemoryDataset) {
    let mut cna = range(SourceId::CveOrg, "fortios", vec![Constraint::All]);
    cna.unaffected = vec![
        Constraint::Exact {
            version: "25.1.3".into(),
        },
        Constraint::Exact {
            version: "22.7.14".into(),
        },
    ];
    let data = base_data()
        .with_vuln(vuln(
            "CVE-2026-9",
            vec![cna, range(SourceId::Nvd, "fortios", nvd)],
        ))
        .with_signals(
            "CVE-2026-9",
            Signals {
                kev: Some(kev()),
                ..Signals::default()
            },
        );
    (fortios_cfg(version, Exposure::Internet), data)
}

#[test]
fn weak_all_versions_does_not_beat_a_specific_not_affected() {
    let (cfg, data) = ivanti_like("22.7.2", vec![between("25.1.0", "25.1.3")]);
    let f = one(&cfg, &data);
    assert_eq!(f.verdict, Verdict::Unknown);
    assert_eq!(f.bucket, Bucket::Unknown);
    assert_eq!(f.rules, vec![RuleId::Conflict, RuleId::Kev]);
    assert_eq!(f.fixed_in, None);
    assert_eq!(f.evidence[0].verdict, Verdict::Affected);
    assert!(f.evidence[0].detail.contains("weak"), "{:?}", f.evidence);
    assert_eq!(f.evidence[1].verdict, Verdict::NotAffected);
}

#[test]
fn weak_all_versions_alone_is_still_affected() {
    let (cfg, data) = ivanti_like("22.7.2", vec![]);
    let f = one(&cfg, &data);
    assert_eq!(f.verdict, Verdict::Affected);
    assert_eq!(f.bucket, Bucket::Now);
}

#[test]
fn specific_affected_beats_everything() {
    // NVD has a specific range containing the version; the CNA is weak; a
    // third source says not affected. Specific affected wins, with a conflict.
    let cna = range(SourceId::CveOrg, "fortios", vec![Constraint::All]);
    let data = base_data().with_vuln(vuln(
        "CVE-2026-9",
        vec![
            cna,
            range(SourceId::Nvd, "fortios", vec![between("7.2.0", "7.2.6")]),
            range(SourceId::Osv, "fortios", vec![between("7.0.0", "7.1.0")]),
        ],
    ));
    let f = one(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(f.verdict, Verdict::Affected);
    assert_eq!(f.rules, vec![RuleId::Affected, RuleId::Conflict]);
}

// ---- fixed_after ----

#[test]
fn inclusive_end_gives_fixed_after() {
    let inclusive = |end: &str| Constraint::Range {
        start: Some(bound("8.6", true)),
        end: Some(bound(end, true)),
    };
    let data = base_data().with_vuln(vuln(
        "CVE-2026-8",
        vec![
            range(SourceId::Nvd, "fortios", vec![inclusive("9.8")]),
            range(SourceId::CveOrg, "fortios", vec![inclusive("9.7")]),
        ],
    ));
    let f = one(&fortios_cfg("9.6", Exposure::Internal), &data);
    assert_eq!(f.fixed_in, None);
    assert_eq!(f.fixed_after.as_deref(), Some("9.8"));
    // A known fix wins, and fixed_after is then not set.
    let data = base_data().with_vuln(vuln(
        "CVE-2026-8",
        vec![
            range(SourceId::Nvd, "fortios", vec![inclusive("9.8")]),
            range(SourceId::CveOrg, "fortios", vec![between("8.6", "9.7")]),
        ],
    ));
    let f = one(&fortios_cfg("9.6", Exposure::Internal), &data);
    assert_eq!(f.fixed_in.as_deref(), Some("9.7"));
    assert_eq!(f.fixed_after, None);
}

// ---- item summaries ----

fn fix_vuln(id: &str, start: &str, fixed: &str) -> Vulnerability {
    vuln(
        id,
        vec![range(
            SourceId::CveOrg,
            "fortios",
            vec![between(start, fixed)],
        )],
    )
}

#[test]
fn item_summary_recommends_one_upgrade() {
    let cycle = |c: &str| EolCycle {
        cycle: c.into(),
        release_date: None,
        eol: None,
        eol_reached: false,
        latest: None,
        lts: false,
    };
    let data = base_data()
        .with_eol("fortios", vec![cycle("7.2"), cycle("7.4")])
        .with_vuln(fix_vuln("CVE-1", "7.0.0", "7.2.7"))
        .with_vuln(fix_vuln("CVE-2", "7.0.0", "7.2.9"))
        // Only fixed in the next cycle: not in the recommendation's cycle.
        .with_vuln(fix_vuln("CVE-3", "7.0.0", "7.4.2"))
        .with_vuln(vuln(
            "CVE-4",
            vec![range(SourceId::CveOrg, "fortios", vec![Constraint::All])],
        ))
        .with_signals(
            "CVE-1",
            Signals {
                kev: Some(kev()),
                ..Signals::default()
            },
        );
    let r = run(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    assert_eq!(r.items.len(), 1);
    let i = &r.items[0];
    assert_eq!(i.key, "fortios");
    assert_eq!(i.upgrade_to.as_deref(), Some("7.2.9"));
    assert_eq!(i.fixes, 2);
    assert_eq!(i.of, 4);
    assert_eq!(i.unfixed, 1);
    assert!(!i.eol);
    assert_eq!(i.counts.now, 1);
    assert_eq!(i.counts.fyi, 3);
}

#[test]
fn item_summary_falls_back_to_the_largest_fix() {
    // No cycle data: same major.minor. Nothing fits 7.2, so the largest fix.
    let data = base_data()
        .with_vuln(fix_vuln("CVE-1", "7.0.0", "7.4.2"))
        .with_vuln(fix_vuln("CVE-2", "7.0.0", "7.4.10"));
    let r = run(&fortios_cfg("7.2.5", Exposure::Internal), &data);
    let i = &r.items[0];
    assert_eq!(i.upgrade_to.as_deref(), Some("7.4.10"));
    assert_eq!((i.fixes, i.of), (2, 2));
}

#[test]
fn item_summary_without_fixes_or_findings() {
    let r = run(
        &fortios_cfg("7.4.3", Exposure::Internal),
        &base_data().with_vuln(fix_vuln("CVE-1", "7.0.0", "7.2.7")),
    );
    let i = &r.items[0];
    assert_eq!(
        (i.upgrade_to.clone(), i.fixes, i.of, i.unfixed),
        (None, 0, 0, 0)
    );
    assert_eq!(i.counts.total(), 0);
}
