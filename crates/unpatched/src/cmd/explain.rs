//! `unpatched explain`: the evidence behind a verdict.

use std::collections::HashMap;
use std::fmt::Write as _;

use chrono::{NaiveDate, Utc};
use unpatched_core::config::StackItem;
use unpatched_core::rules::{RuleId, all_rules};
use unpatched_core::version::constraint_matches;
use unpatched_core::{
    Bucket, CatalogEntry, Config, Constraint, Dataset, DbInfo, EolCycle, Finding, KevEntry, Report,
    Signals, Verdict, Vulnerability, evaluate,
};
use unpatched_db::Db;
use unpatched_notify::render::{action, bucket_emoji, bucket_label, source_name, subject, why};

use super::out;
use crate::ctx::{Ctx, load_config, read_config_text};
use crate::error::{Failure, Res};

pub fn run(ctx: &Ctx, target: &str) -> Res<u8> {
    let t = target.trim();
    if let Some(rule) = find_rule(t) {
        out(&explain_rule(rule));
        return Ok(0);
    }
    if t.contains('/') {
        return explain_key(ctx, t);
    }
    if t.contains('-') && t.chars().any(|c| c.is_ascii_digit()) {
        return explain_vuln(ctx, t, None);
    }
    Err(Failure::usage(
        format!("{t:?} is not a rule id, a vulnerability id or a finding key"),
        "Use a rule like UNP-KEV, a CVE like CVE-2024-21762, or a key from a report like office-firewall/CVE-2024-21762.",
    ))
}

// ------------------------------------------------------------------ rules

fn find_rule(t: &str) -> Option<RuleId> {
    let up = t.to_ascii_uppercase();
    let full = if up.starts_with("UNP-") {
        up
    } else {
        format!("UNP-{up}")
    };
    all_rules()
        .into_iter()
        .map(|r| r.id)
        .find(|id| id.code() == full)
}

fn effect(id: RuleId) -> &'static str {
    match id {
        RuleId::Kev | RuleId::SsvcActive | RuleId::ExploitExposed => {
            "puts an affected finding in: Fix today (now)"
        }
        RuleId::Epss | RuleId::Cvss => {
            "puts an affected finding in: This week (week), unless a Fix today rule applies"
        }
        RuleId::Exposed => {
            "puts an affected, internet-facing finding with CVSS at or above cvss_week_exposed in: This week (week), unless a Fix today rule applies"
        }
        RuleId::Affected => "puts an affected finding in: FYI (fyi)",
        RuleId::Eol => "makes the finding: End of life (eol), one per stack item",
        RuleId::UnknownNoRanges | RuleId::UnknownVersion => {
            "makes the verdict unknown; shown when the signals would make it Fix today or This week"
        }
        RuleId::Conflict => {
            "is added when sources disagree; it makes the verdict unknown when the only \"affected\" comes from a source that says all versions"
        }
        RuleId::UnverifiedProduct => {
            "makes a finding in: Unknown, so an empty result is never read as safe"
        }
        RuleId::Ignored => "moves the finding to the ignored list",
        RuleId::IgnoreExpired => "is added when an ignore entry ran out",
        RuleId::StaleData => "makes a finding in: Unknown about the database itself",
    }
}

fn explain_rule(id: RuleId) -> String {
    let info = all_rules()
        .into_iter()
        .find(|r| r.id == id)
        .expect("every rule id is listed");
    format!(
        "{}: {}\n\n{}\n\nThis rule {}.\n",
        id.code(),
        info.title,
        info.explanation,
        effect(id)
    )
}

// ------------------------------------------------------------------ vulnerabilities

fn describe(c: &Constraint) -> String {
    match c {
        Constraint::All => "all versions".into(),
        Constraint::Exact { version } => format!("exactly {version}"),
        Constraint::Range { start, end } => {
            let mut parts = Vec::new();
            if let Some(s) = start {
                parts.push(format!(
                    "{} {}",
                    if s.inclusive { ">=" } else { ">" },
                    s.version
                ));
            }
            if let Some(e) = end {
                parts.push(format!(
                    "{} {}",
                    if e.inclusive { "<=" } else { "<" },
                    e.version
                ));
            }
            if parts.is_empty() {
                "all versions".into()
            } else {
                parts.join(" and ")
            }
        }
    }
}

fn describe_all(cs: &[Constraint]) -> String {
    if cs.is_empty() {
        "no usable version data".into()
    } else {
        cs.iter().map(describe).collect::<Vec<_>>().join(" or ")
    }
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Affected => "affected",
        Verdict::Fixed => "fixed",
        Verdict::NotAffected => "not affected",
        Verdict::Unknown => "unknown",
    }
}

fn product_label(id: &str) -> String {
    match unpatched_catalog::get(id) {
        Some(e) => format!("{id} ({})", e.name),
        None => id.to_owned(),
    }
}

fn vuln_text(v: &Vulnerability, sig: &Signals) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{}", v.id);
    if !v.summary.trim().is_empty() {
        let _ = writeln!(s, "  {}", v.summary.trim());
    }
    let mut facts = vec![format!("status: {:?}", v.status).to_lowercase()];
    if let Some(d) = v.published {
        facts.push(format!("published {d}"));
    }
    if let Some(d) = v.modified {
        facts.push(format!("modified {d}"));
    }
    let _ = writeln!(s, "  {}", facts.join(" · "));
    if let Some(c) = &v.cvss {
        let _ = writeln!(
            s,
            "  CVSS {}: {:.1} {}",
            c.version,
            c.score,
            c.vector.as_deref().unwrap_or("")
        );
    }
    if !v.aliases.is_empty() {
        let _ = writeln!(s, "  Also known as: {}", v.aliases.join(", "));
    }

    s.push_str("\nExploitation signals\n");
    let mut any = false;
    if let Some(k) = &sig.kev {
        any = true;
        let _ = write!(s, "  CISA KEV: added {}", k.date_added);
        if let Some(d) = k.due_date {
            let _ = write!(s, ", due {d}");
        }
        let _ = writeln!(
            s,
            ", ransomware use: {}",
            if k.known_ransomware {
                "known"
            } else {
                "not known"
            }
        );
    }
    if let Some(e) = &sig.epss {
        any = true;
        let _ = writeln!(
            s,
            "  EPSS: {:.1}% (percentile {:.0}) on {}",
            e.score * 100.0,
            e.percentile * 100.0,
            e.date
        );
    }
    if let Some(x) = sig.ssvc_exploitation {
        any = true;
        let _ = writeln!(
            s,
            "  SSVC exploitation: {x:?}, automatable: {}",
            sig.ssvc_automatable
                .map_or("unknown", |a| if a { "yes" } else { "no" })
                .to_lowercase()
        );
    }
    for e in &sig.exploits {
        any = true;
        let _ = writeln!(s, "  Public exploit: {} ({})", e.id, source_name(e.source));
    }
    if !any {
        s.push_str("  none known\n");
    }

    s.push_str("\nAffected versions, by source\n");
    if v.ranges.is_empty() {
        s.push_str("  no source has version data\n");
    }
    for r in &v.ranges {
        let _ = writeln!(
            s,
            "  {}: {} affects {}",
            source_name(r.source),
            product_label(r.product.strip_prefix("purl:").unwrap_or(&r.product)),
            describe_all(&r.constraints)
        );
        if !r.unaffected.is_empty() {
            let _ = writeln!(s, "    but not: {}", describe_all(&r.unaffected));
        }
        if !r.raw.trim().is_empty() {
            let _ = writeln!(s, "    source says: {}", one_line(&r.raw));
        }
    }
    if !v.references.is_empty() {
        s.push_str("\nReferences\n");
        for r in &v.references {
            let _ = writeln!(s, "  {}", r.url);
        }
    }
    s
}

/// The database with one vulnerability and nothing else, so one stack item
/// can be judged for it alone. With `force`, the vulnerability counts as
/// exploited, which keeps verdicts that would otherwise be dropped as not urgent.
struct One<'a> {
    db: &'a Db,
    vuln: &'a Vulnerability,
    force: bool,
}

impl Dataset for One<'_> {
    fn product(&self, id: &str) -> Option<CatalogEntry> {
        self.db.product(id)
    }
    fn vulns_for_product(&self, product_id: &str) -> Vec<Vulnerability> {
        if self.vuln.ranges.iter().any(|r| r.product == product_id) {
            vec![self.vuln.clone()]
        } else {
            Vec::new()
        }
    }
    fn signals(&self, vuln_id: &str) -> Signals {
        let mut s = self.db.signals(vuln_id);
        if self.force && s.kev.is_none() {
            s.kev = Some(KevEntry {
                date_added: NaiveDate::from_ymd_opt(2000, 1, 1).expect("valid date"),
                due_date: None,
                known_ransomware: false,
                required_action: String::new(),
                vendor_project: String::new(),
                product: String::new(),
            });
        }
        s
    }
    fn eol_cycles(&self, _: &str) -> Vec<EolCycle> {
        Vec::new()
    }
    fn product_verified(&self, _: &str) -> bool {
        true
    }
    fn info(&self) -> Option<DbInfo> {
        self.db.info().into()
    }
}

/// False when the vulnerability has no record about this item's product at
/// all, so a verdict ("not affected") would claim more than the data says.
fn is_concerned(db: &Db, item: &StackItem, v: &Vulnerability) -> bool {
    let Some(entry) = item.product.as_deref().and_then(|p| db.product(p)) else {
        return true;
    };
    v.ranges.iter().any(|r| r.product == entry.id)
}

fn item_label(item: &StackItem) -> String {
    item.name
        .clone()
        .or_else(|| item.product.clone())
        .or_else(|| item.purl.clone())
        .unwrap_or_default()
}

fn judge(db: &Db, config: &Config, item: &StackItem, v: &Vulnerability) -> String {
    let mut s = String::new();
    let one = Config {
        stack: vec![item.clone()],
        ..config.clone()
    };
    let now = Utc::now();
    let run = |force: bool| -> Report {
        evaluate(&one, &One { db, vuln: v, force }, &HashMap::new(), now)
    };
    let pick = |r: &Report| -> Option<(Finding, bool)> {
        r.findings
            .iter()
            .map(|f| (f, false))
            .chain(r.ignored.iter().map(|f| (f, true)))
            .find(|(f, _)| f.vuln.as_deref() == Some(v.id.as_str()))
            .map(|(f, ig)| (f.clone(), ig))
    };
    let real = run(false);
    if let Some((f, ignored)) = pick(&real) {
        s.push_str(&finding_lines(&f, ignored));
        return s;
    }
    let forced = run(true);
    if let Some((f, _)) = pick(&forced) {
        let _ = writeln!(
            s,
            "    Verdict: {}, but it is not reported: nothing says it is exploited and the scores are below your thresholds.",
            verdict_name(f.verdict)
        );
        for e in &f.evidence {
            let _ = writeln!(
                s,
                "    Evidence  {}: {}",
                source_name(e.source),
                one_line(&e.detail)
            );
        }
        return s;
    }
    for n in &real.notes {
        let _ = writeln!(s, "    Note: {n}");
    }
    let Some(entry) = item.product.as_deref().and_then(|p| db.product(p)) else {
        s.push_str("    Verdict: not checked (the product is not in the database).\n");
        return s;
    };
    let ranges: Vec<_> = v.ranges.iter().filter(|r| r.product == entry.id).collect();
    if ranges.is_empty() {
        s.push_str("    Verdict: not about this product (no source has a record for it).\n");
        return s;
    }
    if ranges.iter().all(|r| r.constraints.is_empty()) {
        s.push_str(
            "    Verdict: unknown. No source has usable version data for this product yet.\n",
        );
        return s;
    }
    let version = item.version.clone().unwrap_or_default();
    s.push_str("    Verdict: not affected, by every source that has data.\n");
    for r in ranges {
        let matched: Vec<bool> = r
            .constraints
            .iter()
            .map(|c| constraint_matches(&entry.versioning, c, &version).unwrap_or(false))
            .collect();
        let _ = writeln!(
            s,
            "    Evidence  {}: {version} is {} {}",
            source_name(r.source),
            if matched.iter().any(|m| *m) {
                "inside (but the source lists it as unaffected)"
            } else {
                "outside"
            },
            describe_all(&r.constraints)
        );
    }
    s
}

fn finding_lines(f: &Finding, ignored: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "    Verdict: {} · {} {}{}",
        verdict_name(f.verdict),
        bucket_emoji(f.bucket),
        bucket_label(f.bucket),
        if ignored { " (ignored on purpose)" } else { "" }
    );
    let rules: Vec<&str> = f.rules.iter().map(|r| r.code()).collect();
    let _ = writeln!(s, "    Rules:   {}", rules.join(", "));
    let _ = writeln!(s, "    Why:     {}", why(f));
    let _ = writeln!(s, "    Do:      {}", action(f));
    if let Some(i) = &f.ignored {
        let _ = writeln!(s, "    Ignored: {} (until {})", i.reason, i.until);
    }
    for e in &f.evidence {
        let _ = writeln!(
            s,
            "    Evidence {}: {} ({})",
            source_name(e.source),
            one_line(&e.detail),
            verdict_name(e.verdict)
        );
    }
    s
}

/// A source's own text on one line, cut to a readable length.
fn one_line(raw: &str) -> String {
    let joined = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() > 300 {
        let cut: String = joined.chars().take(297).collect();
        format!("{cut}...")
    } else {
        joined
    }
}

fn find_vuln(db: &Db, id: &str) -> Option<Vulnerability> {
    db.vuln(id)
        .or_else(|| db.vulns_by_alias(id).into_iter().next())
}

fn explain_vuln(ctx: &Ctx, id: &str, only_item: Option<&str>) -> Res<u8> {
    let db = ctx.open_db()?;
    let Some(v) = find_vuln(&db, id) else {
        return Err(Failure::data(
            format!("{id} is not in the database"),
            "It may be too new, rejected, or about a product that is not in the catalog. Run `unpatched db update` for the newest data.",
        ));
    };
    let sig = db.signals(&v.id);
    let mut s = vuln_text(&v, &sig);

    if ctx.config.is_file() {
        let config = load_config(&ctx.config)?;
        s.push_str("\nYour stack\n");
        let mut shown = false;
        let mut not_concerned: Vec<String> = Vec::new();
        for item in &config.stack {
            if only_item.is_some_and(|o| o != item_label(item)) {
                continue;
            }
            if !is_concerned(&db, item, &v) {
                not_concerned.push(item_label(item));
                continue;
            }
            shown = true;
            if item.product.is_none() {
                let _ = writeln!(
                    s,
                    "  {}: a package; `unpatched check` looks packages up in OSV, so they are not judged here.",
                    item_label(item)
                );
                continue;
            }
            let _ = writeln!(
                s,
                "  {} {}",
                item_label(item),
                item.version.as_deref().unwrap_or_default()
            );
            s.push_str(&judge(&db, &config, item, &v));
        }
        if !not_concerned.is_empty() {
            let n = not_concerned.len();
            let _ = writeln!(
                s,
                "  {n} other stack item{} not concerned: this vulnerability is not about {} ({}).",
                if n == 1 { " is" } else { "s are" },
                if n == 1 {
                    "its product"
                } else {
                    "their products"
                },
                not_concerned.join(", ")
            );
        } else if !shown {
            s.push_str("  (no stack item to judge)\n");
        }
    } else {
        let _ = writeln!(
            s,
            "\n({} not found: add --config <file> to see what this means for your stack.)",
            ctx.config.display()
        );
    }
    out(&s);
    Ok(0)
}

// ------------------------------------------------------------------ finding keys

fn explain_key(ctx: &Ctx, key: &str) -> Res<u8> {
    read_config_text(&ctx.config)?;
    let config = load_config(&ctx.config)?;
    let report = super::check::evaluate(ctx, &config, Utc::now(), true)?;
    let found = report
        .findings
        .iter()
        .map(|f| (f, false))
        .chain(report.ignored.iter().map(|f| (f, true)))
        .find(|(f, _)| f.key == key);
    let Some((f, ignored)) = found else {
        let keys: Vec<&str> = report
            .findings
            .iter()
            .take(5)
            .map(|f| f.key.as_str())
            .collect();
        return Err(Failure::usage(
            format!("there is no finding with the key {key:?} right now"),
            if keys.is_empty() {
                "`unpatched check` shows the current findings; there are none.".to_owned()
            } else {
                format!("Current keys include: {}", keys.join(", "))
            },
        ));
    };
    let mut s = String::new();
    let _ = writeln!(s, "{}", subject(f));
    let _ = writeln!(s, "  {}\n  key: {}", f.title, f.key);
    s.push_str(&finding_lines(f, ignored));
    if let Some(fix) = &f.fixed_in {
        let _ = writeln!(s, "    Fixed in: {fix}");
    } else if let Some(after) = &f.fixed_after {
        let _ = writeln!(s, "    Fixed in: a release after {after}");
    }
    for r in &f.rules {
        let info = all_rules()
            .into_iter()
            .find(|i| i.id == *r)
            .expect("listed");
        let _ = writeln!(s, "    {}: {}", r.code(), info.explanation);
    }
    out(&s);
    if f.bucket != Bucket::Eol
        && let Some(v) = &f.vuln
    {
        out("\n");
        return explain_vuln(ctx, v, Some(&f.item));
    }
    Ok(0)
}
