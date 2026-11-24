//! A hand-built report that covers every bucket. Only compiled for tests.

use chrono::{NaiveDate, TimeZone, Utc};
use unpatched_core::config::Exposure;
use unpatched_core::report::{Evidence, IgnoredBecause};
use unpatched_core::rules::RuleId;
use unpatched_core::{
    Bucket, BucketCounts, Cvss, DbInfo, Epss, ExploitRef, Finding, ItemSummary, KevEntry, Report,
    Signals, SourceId, SourceStatus, SsvcExploitation, Summary, Verdict,
};

pub fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

/// The catalog's display name for the products the fixtures use.
fn display_name(product: &str) -> String {
    match product {
        "fortios" => "FortiOS",
        "nextcloud" => "Nextcloud",
        "postgresql" => "PostgreSQL",
        "home-assistant" => "Home Assistant",
        "redis" => "Redis",
        other => other,
    }
    .into()
}

pub fn base(key: &str, item: &str, product: &str, version: &str, bucket: Bucket) -> Finding {
    Finding {
        key: key.into(),
        item: item.into(),
        product: product.into(),
        product_name: display_name(product),
        version: version.into(),
        exposure: Exposure::Internal,
        vuln: None,
        title: String::new(),
        verdict: Verdict::Affected,
        bucket,
        rules: vec![],
        fixed_in: None,
        fixed_after: None,
        latest_in_cycle: None,
        cvss: None,
        signals: Signals::default(),
        evidence: vec![],
        references: vec![],
        ignored: None,
    }
}

pub fn fortios() -> Finding {
    Finding {
        exposure: Exposure::Internet,
        vuln: Some("CVE-2024-21762".into()),
        title: "Out-of-bounds write in sslvpnd allows remote code execution".into(),
        rules: vec![RuleId::Kev, RuleId::Exposed],
        fixed_in: Some("7.2.7".into()),
        latest_in_cycle: Some("7.2.11".into()),
        cvss: Some(Cvss {
            version: "3.1".into(),
            score: 9.8,
            vector: None,
        }),
        signals: Signals {
            kev: Some(KevEntry {
                date_added: date(2024, 2, 9),
                due_date: Some(date(2024, 2, 16)),
                known_ransomware: true,
                required_action: "Apply updates".into(),
                vendor_project: "Fortinet".into(),
                product: "FortiOS".into(),
            }),
            epss: Some(Epss {
                score: 0.9412,
                percentile: 0.9991,
                date: date(2026, 11, 22),
            }),
            ssvc_exploitation: Some(SsvcExploitation::Active),
            ssvc_automatable: Some(true),
            exploits: vec![ExploitRef {
                source: SourceId::Metasploit,
                id: "fortios_sslvpnd".into(),
                url: None,
            }],
        },
        evidence: vec![
            Evidence {
                source: SourceId::CveOrg,
                verdict: Verdict::Affected,
                detail: "affected 7.2.0 to 7.2.6 (CNA Fortinet)".into(),
            },
            Evidence {
                source: SourceId::Nvd,
                verdict: Verdict::Affected,
                detail: "cpe:2.3:o:fortinet:fortios up to (excluding) 7.2.7".into(),
            },
        ],
        references: vec!["https://fortiguard.fortinet.com/psirt/FG-IR-24-015".into()],
        ..base(
            "office-firewall/CVE-2024-21762",
            "Office firewall",
            "fortios",
            "7.2.5",
            Bucket::Now,
        )
    }
}

pub fn nextcloud(id: &str, fixed: &str) -> Finding {
    Finding {
        exposure: Exposure::Internet,
        vuln: Some(id.into()),
        title: format!("Improper access control in Nextcloud Server ({id})"),
        rules: vec![RuleId::Epss, RuleId::Exposed],
        fixed_in: Some(fixed.into()),
        cvss: Some(Cvss {
            version: "3.1".into(),
            score: 7.5,
            vector: None,
        }),
        signals: Signals {
            epss: Some(Epss {
                score: 0.0731,
                percentile: 0.91,
                date: date(2026, 11, 22),
            }),
            ..Signals::default()
        },
        evidence: vec![Evidence {
            source: SourceId::CveOrg,
            verdict: Verdict::Affected,
            detail: "affected 29.0.0 to 29.0.7 (CNA GitHub_M)".into(),
        }],
        ..base(
            &format!("nextcloud/{id}"),
            "nextcloud",
            "nextcloud",
            "29.0.3",
            Bucket::Week,
        )
    }
}

pub fn postgres_eol() -> Finding {
    Finding {
        title: "postgresql 13.12 is past end of life: the 13 release cycle no longer gets security fixes".into(),
        rules: vec![RuleId::Eol],
        evidence: vec![Evidence {
            source: SourceId::Endoflife,
            verdict: Verdict::Affected,
            detail: "release cycle 13 reached end of life on 2025-11-13 (endoflife.date)".into(),
        }],
        ..base(
            "postgresql/eol",
            "postgresql",
            "postgresql",
            "13.12",
            Bucket::Eol,
        )
    }
}

pub fn home_assistant() -> Finding {
    Finding {
        vuln: Some("CVE-2026-0042".into()),
        title: "Authentication bypass in Home Assistant".into(),
        verdict: Verdict::Unknown,
        rules: vec![RuleId::UnknownNoRanges],
        evidence: vec![Evidence {
            source: SourceId::CveOrg,
            verdict: Verdict::Unknown,
            detail: "no version data".into(),
        }],
        ..base(
            "home-assistant/CVE-2026-0042",
            "home-assistant",
            "home-assistant",
            "2024.10.1",
            Bucket::Unknown,
        )
    }
}

pub fn redis_fyi() -> Finding {
    Finding {
        vuln: Some("CVE-2025-1111".into()),
        title: "Denial of service in redis streams".into(),
        rules: vec![RuleId::Affected],
        fixed_in: Some("7.2.4".into()),
        cvss: Some(Cvss {
            version: "3.1".into(),
            score: 5.3,
            vector: None,
        }),
        references: vec!["https://example.com/redis-advisory".into()],
        ..base(
            "redis/CVE-2025-1111",
            "redis",
            "redis",
            "7.2.1",
            Bucket::Fyi,
        )
    }
}

pub fn ignored_finding() -> Finding {
    Finding {
        vuln: Some("CVE-2025-2222".into()),
        title: "Something in nextcloud we accepted".into(),
        rules: vec![RuleId::Ignored],
        ignored: Some(IgnoredBecause {
            reason: "app disabled".into(),
            until: date(2027, 1, 31),
        }),
        ..base(
            "nextcloud/CVE-2025-2222",
            "nextcloud",
            "nextcloud",
            "29.0.3",
            Bucket::Week,
        )
    }
}

fn summarize(findings: &[Finding], ignored: usize, not_affected: usize) -> Summary {
    let count = |b: Bucket| findings.iter().filter(|f| f.bucket == b).count();
    Summary {
        now: count(Bucket::Now),
        week: count(Bucket::Week),
        eol: count(Bucket::Eol),
        unknown: count(Bucket::Unknown),
        fyi: count(Bucket::Fyi),
        ignored,
        not_affected,
    }
}

/// The per-item recommendations, built the simple way: the largest `fixed_in`.
fn items_for(findings: &[Finding]) -> Vec<ItemSummary> {
    let mut keys: Vec<&str> = Vec::new();
    for f in findings {
        if !keys.contains(&f.item_key()) {
            keys.push(f.item_key());
        }
    }
    keys.into_iter()
        .map(|key| {
            let mine: Vec<&Finding> = findings.iter().filter(|f| f.item_key() == key).collect();
            let mut counts = BucketCounts::default();
            for f in &mine {
                match f.bucket {
                    Bucket::Now => counts.now += 1,
                    Bucket::Week => counts.week += 1,
                    Bucket::Eol => counts.eol += 1,
                    Bucket::Unknown => counts.unknown += 1,
                    Bucket::Fyi => counts.fyi += 1,
                }
            }
            let affected: Vec<&&Finding> = mine
                .iter()
                .filter(|f| f.vuln.is_some() && f.verdict == Verdict::Affected)
                .collect();
            let upgrade_to = affected
                .iter()
                .filter_map(|f| f.fixed_in.clone())
                .max_by(|a, b| crate::render::loose_cmp(a, b));
            let fixes = upgrade_to.as_ref().map_or(0, |u| {
                affected
                    .iter()
                    .filter(|f| {
                        f.fixed_in.as_ref().is_some_and(|v| {
                            crate::render::loose_cmp(v, u) != std::cmp::Ordering::Greater
                        })
                    })
                    .count()
            });
            let first = mine[0];
            ItemSummary {
                key: key.into(),
                item: first.item.clone(),
                product: first.product.clone(),
                product_name: first.product_name.clone(),
                version: first.version.clone(),
                exposure: first.exposure,
                counts,
                upgrade_to,
                fixes,
                of: affected.len(),
                eol: mine.iter().any(|f| f.bucket == Bucket::Eol),
                unfixed: affected
                    .iter()
                    .filter(|f| f.fixed_in.is_none() && f.fixed_after.is_none())
                    .count(),
            }
        })
        .collect()
}

pub fn report(findings: Vec<Finding>) -> Report {
    let built = Utc.with_ymd_and_hms(2026, 11, 22, 2, 41, 0).unwrap();
    Report {
        format: 1,
        generated_at: Utc.with_ymd_and_hms(2026, 11, 23, 6, 17, 0).unwrap(),
        db: Some(DbInfo {
            schema_version: 1,
            built_at: built,
            sources: vec![SourceStatus {
                source: SourceId::Kev,
                fetched_at: built,
                records: 1200,
                ok: true,
                note: None,
            }],
        }),
        summary: summarize(&findings, 0, 1412),
        items: items_for(&findings),
        findings,
        ignored: vec![],
        notes: vec![],
    }
}

/// Every bucket, one ignored finding, one note.
pub fn sample_report() -> Report {
    let findings = vec![
        fortios(),
        nextcloud("CVE-2026-1001", "29.0.8"),
        nextcloud("CVE-2026-1002", "29.0.6"),
        postgres_eol(),
        home_assistant(),
        redis_fyi(),
    ];
    let mut r = report(findings);
    r.ignored = vec![ignored_finding()];
    r.summary.ignored = 1;
    r.notes =
        vec!["The catalog entry for home-assistant has not been verified for 40 days.".into()];
    r
}
