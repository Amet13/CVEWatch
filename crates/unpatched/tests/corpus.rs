//! Runs every `corpus/<case>/case.yml` through `evaluate` and compares the result.
//! The corpus is the spec: see `corpus/README.md`.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use unpatched_core::matching::memory::MemoryDataset;
use unpatched_core::rules::{RuleId, all_rules};
use unpatched_core::{Bucket, Config, Finding, Verdict, Vulnerability, evaluate};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    description: String,
    now: DateTime<Utc>,
    config: String,
    data: serde_norway::Value,
    /// OSV-shaped results for `purl` stack items, by the purl as written in `config`.
    #[serde(default)]
    packages: HashMap<String, Vec<Vulnerability>>,
    #[serde(default)]
    expect: Vec<Expect>,
    #[serde(default)]
    expect_ignored: Vec<Expect>,
    #[serde(default)]
    absent: Vec<String>,
    #[serde(default)]
    notes_contain: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    key: String,
    bucket: Bucket,
    verdict: Verdict,
    /// The exact rule ids, in order. Not checked when left out.
    rules: Option<Vec<RuleId>>,
    /// A version, or `none` for "no fixed version". Not checked when left out.
    fixed_in: Option<String>,
    latest_in_cycle: Option<String>,
    title_contains: Option<String>,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn case_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .expect("corpus/ exists")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn load(dir: &std::path::Path) -> Result<Case, String> {
    let text = std::fs::read_to_string(dir.join("case.yml"))
        .map_err(|e| format!("cannot read case.yml: {e}"))?;
    serde_norway::from_str(&text).map_err(|e| format!("case.yml: {e}"))
}

fn check_expect(e: &Expect, f: &Finding, problems: &mut Vec<String>) {
    let mut bad = |what: &str, want: String, got: String| {
        problems.push(format!("{}: {what}: expected {want}, got {got}", e.key));
    };
    if f.bucket != e.bucket {
        bad(
            "bucket",
            format!("{:?}", e.bucket),
            format!("{:?}", f.bucket),
        );
    }
    if f.verdict != e.verdict {
        bad(
            "verdict",
            format!("{:?}", e.verdict),
            format!("{:?}", f.verdict),
        );
    }
    if let Some(r) = &e.rules
        && *r != f.rules
    {
        let codes = |v: &[RuleId]| v.iter().map(|r| r.code()).collect::<Vec<_>>().join(", ");
        bad("rules", codes(r), codes(&f.rules));
    }
    for (what, want, got) in [
        ("fixed_in", &e.fixed_in, &f.fixed_in),
        ("latest_in_cycle", &e.latest_in_cycle, &f.latest_in_cycle),
    ] {
        match want.as_deref() {
            None => {}
            Some("none") if got.is_none() => {}
            Some(w) if got.as_deref() == Some(w) => {}
            Some(w) => bad(what, w.to_owned(), format!("{got:?}")),
        }
    }
    if let Some(t) = &e.title_contains
        && !f.title.contains(t.as_str())
    {
        bad(
            "title",
            format!("to contain {t:?}"),
            format!("{:?}", f.title),
        );
    }
}

/// Run one case; returns what is wrong, and the rule ids and buckets it expects.
fn run_case(case: &Case) -> Result<Vec<String>, String> {
    let config = Config::from_yaml(&case.config).map_err(|e| format!("config: {e}"))?;
    let data: MemoryDataset =
        serde_norway::from_value(case.data.clone()).map_err(|e| format!("data: {e}"))?;
    let report = evaluate(&config, &data, &case.packages, case.now);
    let mut problems = Vec::new();

    for (label, expected, actual) in [
        ("findings", &case.expect, &report.findings),
        ("ignored", &case.expect_ignored, &report.ignored),
    ] {
        for e in expected {
            match actual.iter().find(|f| f.key == e.key) {
                Some(f) => check_expect(e, f, &mut problems),
                None => problems.push(format!("{}: expected in {label}, but it is missing", e.key)),
            }
        }
        let want: BTreeSet<&str> = expected.iter().map(|e| e.key.as_str()).collect();
        for f in actual {
            if !want.contains(f.key.as_str()) {
                problems.push(format!(
                    "{}: unexpected in {label} ({:?}, {:?}, rules {:?})",
                    f.key,
                    f.bucket,
                    f.verdict,
                    f.rules.iter().map(|r| r.code()).collect::<Vec<_>>()
                ));
            }
        }
    }
    for key in &case.absent {
        if report
            .findings
            .iter()
            .chain(&report.ignored)
            .any(|f| &f.key == key)
        {
            problems.push(format!("{key}: must be absent, but it is reported"));
        }
    }
    for text in &case.notes_contain {
        if !report.notes.iter().any(|n| n.contains(text.as_str())) {
            problems.push(format!(
                "notes: none contains {text:?}; notes are {:?}",
                report.notes
            ));
        }
    }
    Ok(problems)
}

#[test]
fn every_case_gives_the_expected_findings() {
    let mut failures = Vec::new();
    let mut n = 0;
    for dir in case_dirs() {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        n += 1;
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            failures.push(format!(
                "{name}: the folder name must be lowercase kebab-case"
            ));
        }
        match load(&dir).and_then(|c| {
            if c.description.trim().is_empty() {
                return Err("description is empty".into());
            }
            run_case(&c)
        }) {
            Ok(problems) => failures.extend(problems.into_iter().map(|p| format!("{name}: {p}"))),
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    assert!(
        n >= 40,
        "the corpus has only {n} cases; it must have at least 40"
    );
    assert!(
        failures.is_empty(),
        "{} problem(s) in the corpus:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

#[test]
fn the_corpus_covers_every_rule_and_bucket() {
    let mut rules: BTreeSet<RuleId> = BTreeSet::new();
    let mut buckets: BTreeSet<Bucket> = BTreeSet::new();
    let mut verdicts: BTreeSet<Verdict> = BTreeSet::new();
    for dir in case_dirs() {
        let case = load(&dir).expect("case loads");
        for e in case.expect.iter().chain(&case.expect_ignored) {
            rules.extend(e.rules.iter().flatten());
            buckets.insert(e.bucket);
            verdicts.insert(e.verdict);
        }
    }
    let missing: Vec<&str> = all_rules()
        .iter()
        .map(|r| r.id)
        .filter(|r| !rules.contains(r))
        .map(RuleId::code)
        .collect();
    assert!(
        missing.is_empty(),
        "no corpus case expects these rules: {missing:?}"
    );
    for b in [
        Bucket::Now,
        Bucket::Week,
        Bucket::Eol,
        Bucket::Unknown,
        Bucket::Fyi,
    ] {
        assert!(buckets.contains(&b), "no corpus case expects bucket {b:?}");
    }
    assert!(verdicts.contains(&Verdict::Affected) && verdicts.contains(&Verdict::Unknown));
}
