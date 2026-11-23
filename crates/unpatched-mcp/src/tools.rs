//! The tools: definitions (JSON Schema) and what each one does.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use unpatched_core::config::{Exposure, Notify, StackItem, Thresholds};
use unpatched_core::{
    AffectedRange, CatalogEntry, Config, Dataset, DbInfo, EolCycle, Finding, Report, Signals,
    Verdict, Vulnerability, evaluate, rules,
};
use unpatched_db::Db;
use unpatched_sources::Http;

use crate::ServerContext;

/// What a tool returns: a text summary and the structured result.
#[derive(Debug)]
pub struct Output {
    pub text: String,
    pub data: Value,
}

type ToolResult = Result<Output, String>;

const NAMES: [&str; 5] = [
    "check_stack",
    "is_affected",
    "explain",
    "search_catalog",
    "db_status",
];

pub fn is_tool(name: &str) -> bool {
    NAMES.contains(&name)
}

/// The `tools/list` answer. Every tool is read-only.
pub fn definitions() -> Value {
    let read_only = |title: &str, open_world: bool| {
        json!({
            "title": title,
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": open_world,
        })
    };
    json!([
        {
            "name": "check_stack",
            "title": "Check the stack",
            "description": "Check every item in unpatched.yml against the vulnerability database and return the report: findings sorted by urgency (now, week, eol, unknown, fyi) with verdict, rules, evidence and fixed_in. Package (purl) items are looked up in OSV unless the server runs offline.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "config_path": {
                        "type": "string",
                        "description": "Path to unpatched.yml. Defaults to the server's configured file."
                    }
                },
                "additionalProperties": false
            },
            "annotations": read_only("Check the stack", true)
        },
        {
            "name": "is_affected",
            "title": "Is this version affected?",
            "description": "Ask whether one product at one version is affected, without a config file. With `cve`, answer for that vulnerability only and always give a verdict (affected, not-affected or unknown) with evidence. Without `cve`, return all findings for the product. Use `search_catalog` to find the product id. Never guess the version: ask the user.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "product": {
                        "type": "string",
                        "description": "Catalog product id or alias, e.g. fortios."
                    },
                    "version": {
                        "type": "string",
                        "description": "The exact version that runs, e.g. 7.2.5."
                    },
                    "cve": {
                        "type": "string",
                        "description": "A CVE (or advisory) id to answer for, e.g. CVE-2024-21762."
                    },
                    "exposure": {
                        "type": "string",
                        "enum": ["internet", "internal"],
                        "description": "Whether the item is reachable from the internet. Default internal."
                    }
                },
                "required": ["product", "version"],
                "additionalProperties": false
            },
            "annotations": read_only("Is this version affected?", false)
        },
        {
            "name": "explain",
            "title": "Explain a CVE or a rule",
            "description": "Explain a vulnerability id (CVE or advisory id: summary, CVSS, affected ranges per source, exploitation signals) or a rule id such as UNP-KEV (what it means and why it puts a finding in a bucket).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "A CVE or advisory id (CVE-2024-21762) or a rule id (UNP-KEV)."
                    }
                },
                "required": ["id"],
                "additionalProperties": false
            },
            "annotations": read_only("Explain a CVE or a rule", false)
        },
        {
            "name": "search_catalog",
            "title": "Search the product catalog",
            "description": "Find catalog product ids by name, vendor or alias. Use the id in unpatched.yml. Returns the version scheme and the endoflife.date slug.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Words to look for, e.g. fortigate or nextcloud."
                    }
                },
                "required": ["text"],
                "additionalProperties": false
            },
            "annotations": read_only("Search the product catalog", false)
        },
        {
            "name": "db_status",
            "title": "Database status",
            "description": "When the vulnerability database was built, how old it is in hours, whether it is stale, and the state of each source. Run this before trusting a result.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "annotations": read_only("Database status", false)
        }
    ])
}

pub struct Tools {
    ctx: ServerContext,
    db: Option<Db>,
    http: Option<Http>,
}

impl std::fmt::Debug for Tools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tools")
            .field("ctx", &self.ctx)
            .finish_non_exhaustive()
    }
}

impl Tools {
    pub fn new(ctx: ServerContext) -> Self {
        Self {
            ctx,
            db: None,
            http: None,
        }
    }

    pub fn call(&mut self, name: &str, args: &Value) -> ToolResult {
        match name {
            "check_stack" => self.check_stack(args),
            "is_affected" => self.is_affected(args),
            "explain" => self.explain(args),
            "search_catalog" => search_catalog(args),
            "db_status" => self.db_status(args),
            other => Err(format!("unknown tool: {other}")),
        }
    }

    /// Open the database on first use and keep it.
    fn db(&mut self) -> Result<&Db, String> {
        if self.db.is_none() {
            let path = &self.ctx.db_path;
            if !path.is_file() {
                return Err(format!(
                    "The vulnerability database was not found at {}. Run `unpatched db update` \
                     to download it, then try again.",
                    path.display()
                ));
            }
            let db = Db::open(path).map_err(|e| {
                format!(
                    "Cannot open the database at {}: {e}. Run `unpatched db update` to replace it.",
                    path.display()
                )
            })?;
            self.db = Some(db);
        }
        Ok(self.db.as_ref().expect("opened above"))
    }

    fn check_stack(&mut self, args: &Value) -> ToolResult {
        #[derive(Deserialize)]
        struct Args {
            config_path: Option<String>,
        }
        let a: Args = parse_args(args)?;
        let path = a
            .config_path
            .filter(|p| !p.trim().is_empty())
            .map_or_else(|| self.ctx.config_path.clone(), Into::into);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "Cannot read {}: {e}. Pass `config_path`, or create unpatched.yml first.",
                path.display()
            )
        })?;
        let config = Config::from_yaml(&text)
            .map_err(|e| format!("{}: {e}. Fix the file and try again.", path.display()))?;
        let has_packages = config.stack.iter().any(|i| i.purl.is_some());
        let offline = self.ctx.offline;
        if has_packages && !offline && self.http.is_none() {
            self.http =
                Some(Http::new().map_err(|e| format!("Cannot start the HTTP client: {e}"))?);
        }
        let http = if offline { None } else { self.http.clone() };
        let db = self.db()?;
        let report = unpatched_db::run_check(&config, db, http.as_ref(), Utc::now())
            .map_err(|e| format!("The check failed: {e}. Retry, or run the server offline."))?;
        let mut text = report_summary(&report);
        let _ = write!(text, "\nConfig: {}", path.display());
        Ok(Output {
            text,
            data: to_value(&report)?,
        })
    }

    fn is_affected(&mut self, args: &Value) -> ToolResult {
        #[derive(Deserialize)]
        struct Args {
            product: String,
            version: String,
            cve: Option<String>,
            exposure: Option<Exposure>,
        }
        let a: Args = parse_args(args)?;
        let product = a.product.trim().to_owned();
        let version = a.version.trim().to_owned();
        if product.is_empty() || version.is_empty() {
            return Err("`product` and `version` must not be empty. Ask the user for the exact version; do not guess.".into());
        }
        let Some(entry) = unpatched_catalog::get(&product) else {
            return Err(unknown_product(&product));
        };
        let exposure = a.exposure.unwrap_or_default();
        let config = Config {
            version: 1,
            stack: vec![StackItem {
                product: Some(entry.id.clone()),
                purl: None,
                version: Some(version.clone()),
                exposure,
                name: None,
            }],
            ignore: Vec::new(),
            thresholds: Thresholds::default(),
            notify: Notify::default(),
            digest: "monday".into(),
        };
        let db = self.db()?;
        let now = Utc::now();
        match a.cve.map(|c| c.trim().to_owned()).filter(|c| !c.is_empty()) {
            None => {
                let report = unpatched_db::run_check(&config, db, None, now)
                    .map_err(|e| format!("The check failed: {e}"))?;
                let mut text = format!("{} {version} ({}).\n", entry.name, exposure_str(exposure));
                text.push_str(&report_summary(&report));
                let data = json!({
                    "product": entry.id,
                    "version": version,
                    "exposure": exposure_str(exposure),
                    "summary": report.summary,
                    "findings": report.findings,
                    "notes": report.notes,
                    "db": report.db,
                });
                Ok(Output { text, data })
            }
            Some(cve) => answer_for_cve(db, &config, entry, &version, exposure, &cve, now),
        }
    }

    fn explain(&mut self, args: &Value) -> ToolResult {
        #[derive(Deserialize)]
        struct Args {
            id: String,
        }
        let a: Args = parse_args(args)?;
        let id = a.id.trim();
        if id.is_empty() {
            return Err("`id` must not be empty.".into());
        }
        if id.to_ascii_uppercase().starts_with("UNP-") {
            return explain_rule(id);
        }
        let db = self.db()?;
        let Some(vuln) = find_vuln(db, id) else {
            return Err(format!(
                "{id} is not in the database. Check the id, or run `unpatched db update` if it is recent."
            ));
        };
        let signals = db.signals(&vuln.id);
        let mut text = format!("{}: {}\n", vuln.id, vuln.summary.trim());
        if let Some(c) = &vuln.cvss {
            let _ = writeln!(text, "CVSS {} {}", c.version, c.score);
        }
        for r in &vuln.ranges {
            let _ = writeln!(
                text,
                "- {} says for {}: {}",
                source_name(r),
                r.product,
                r.raw
            );
        }
        text.push_str(&signals_line(&signals));
        let mut by_source: BTreeMap<String, Vec<&AffectedRange>> = BTreeMap::new();
        for r in &vuln.ranges {
            by_source.entry(source_name(r)).or_default().push(r);
        }
        let data = json!({
            "kind": "vulnerability",
            "vulnerability": vuln,
            "ranges_by_source": by_source,
            "signals": signals,
        });
        Ok(Output { text, data })
    }

    fn db_status(&mut self, args: &Value) -> ToolResult {
        let _: Value = parse_args(args)?;
        let path = self.ctx.db_path.clone();
        let db = self.db()?;
        let info = db.info();
        let now = Utc::now();
        let minutes = (now - info.built_at).num_minutes().max(0);
        #[allow(clippy::cast_precision_loss)]
        let age_hours = (minutes as f64 / 60.0 * 10.0).round() / 10.0;
        let warn_days = Thresholds::default().stale_warn_days;
        let stale = minutes > i64::from(warn_days) * 24 * 60;
        let failing: Vec<String> = info
            .sources
            .iter()
            .filter(|s| !s.ok)
            .map(|s| format!("{:?}", s.source))
            .collect();
        let mut text = format!(
            "Database built {} ({age_hours} hours ago). {}",
            info.built_at.format("%Y-%m-%d %H:%M UTC"),
            if stale {
                format!("It is stale (older than {warn_days} days): run `unpatched db update`.")
            } else {
                "It is fresh.".to_owned()
            }
        );
        if !failing.is_empty() {
            let _ = write!(text, " Sources with problems: {}.", failing.join(", "));
        }
        let data = json!({
            "db_path": path,
            "schema_version": info.schema_version,
            "built_at": info.built_at,
            "age_hours": age_hours,
            "stale": stale,
            "stale_after_days": warn_days,
            "products": db.product_ids().len(),
            "sources": info.sources,
        });
        Ok(Output { text, data })
    }
}

fn search_catalog(args: &Value) -> ToolResult {
    #[derive(Deserialize)]
    struct Args {
        text: String,
    }
    const LIMIT: usize = 25;
    let a: Args = parse_args(args)?;
    if a.text.trim().is_empty() {
        return Err("`text` must not be empty.".into());
    }
    let found = unpatched_catalog::search(&a.text);
    let total = found.len();
    let results: Vec<Value> = found.iter().take(LIMIT).map(|e| product_json(e)).collect();
    let mut text = format!("{total} product(s) match {:?}.\n", a.text.trim());
    for e in found.iter().take(LIMIT) {
        let _ = writeln!(text, "- {} ({}, {})", e.id, e.name, e.vendor);
    }
    if total == 0 {
        text.push_str(
            "Nothing found. Try the vendor name or a shorter word. If the product is missing from the catalog, packages can still be checked with a purl.\n",
        );
    }
    Ok(Output {
        text,
        data: json!({ "total": total, "results": results }),
    })
}

fn product_json(e: &CatalogEntry) -> Value {
    json!({
        "id": e.id,
        "name": e.name,
        "vendor": e.vendor,
        "kind": e.kind,
        "versioning": e.versioning,
        "aliases": e.aliases,
        "eol": e.eol,
        "homepage": e.homepage,
    })
}

fn explain_rule(id: &str) -> ToolResult {
    let wanted = id.to_ascii_uppercase();
    let all = rules::all_rules();
    let Some(rule) = all.iter().find(|r| r.id.code() == wanted) else {
        let known: Vec<&str> = all.iter().map(|r| r.id.code()).collect();
        return Err(format!(
            "Unknown rule {id}. Known rules: {}.",
            known.join(", ")
        ));
    };
    Ok(Output {
        text: format!("{}: {}\n{}", rule.id.code(), rule.title, rule.explanation),
        data: json!({
            "kind": "rule",
            "rule": {
                "id": rule.id.code(),
                "title": rule.title,
                "explanation": rule.explanation,
            }
        }),
    })
}

/// A [`Dataset`] that serves one vulnerability, so the evaluator answers for it alone.
struct OneVuln<'a> {
    db: &'a Db,
    vuln: Vulnerability,
}

impl Dataset for OneVuln<'_> {
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
        self.db.signals(vuln_id)
    }
    fn eol_cycles(&self, product_id: &str) -> Vec<EolCycle> {
        self.db.eol_cycles(product_id)
    }
    fn product_verified(&self, product_id: &str) -> bool {
        self.db.product_verified(product_id)
    }
    fn info(&self) -> Option<DbInfo> {
        Some(self.db.info())
    }
}

fn answer_for_cve(
    db: &Db,
    config: &Config,
    entry: &CatalogEntry,
    version: &str,
    exposure: Exposure,
    cve: &str,
    now: DateTime<Utc>,
) -> ToolResult {
    let base = |verdict: &str, reason: &str| {
        json!({
            "product": entry.id,
            "version": version,
            "exposure": exposure_str(exposure),
            "cve": cve.to_ascii_uppercase(),
            "verdict": verdict,
            "reason": reason,
        })
    };
    let Some(vuln) = find_vuln(db, cve) else {
        let reason = format!(
            "{cve} is not in the database, so nothing can be said about {} {version}. \
             Check the id, or run `unpatched db update` if it is recent.",
            entry.name
        );
        let mut data = base("unknown", &reason);
        data["evidence"] = json!([]);
        return Ok(Output {
            text: format!("unknown. {reason}"),
            data,
        });
    };
    let ranges: Vec<&AffectedRange> = vuln
        .ranges
        .iter()
        .filter(|r| r.product == entry.id)
        .collect();
    let evidence_from_ranges = || -> Value {
        Value::Array(
            ranges
                .iter()
                .map(|r| json!({ "source": r.source, "detail": r.raw }))
                .collect(),
        )
    };
    if ranges.is_empty() {
        let reason = format!(
            "{} has no version data for {} in the database, so it cannot say whether {version} is affected. \
             That is not the same as not affected: check the vendor advisory.",
            vuln.id, entry.name
        );
        let mut data = base("unknown", &reason);
        data["vulnerability"] = json!(vuln.id);
        data["evidence"] = json!([]);
        return Ok(Output {
            text: format!("unknown. {reason}"),
            data,
        });
    }

    let single = OneVuln {
        db,
        vuln: vuln.clone(),
    };
    let report = evaluate(config, &single, &HashMap::new(), now);
    let finding = report
        .findings
        .iter()
        .chain(report.ignored.iter())
        .find(|f| f.vuln.as_deref() == Some(vuln.id.as_str()));
    let (verdict, reason, evidence) = if let Some(f) = finding {
        let reason = if f.verdict == Verdict::Affected {
            format!(
                "{} {version} is affected by {}.{}",
                entry.name,
                vuln.id,
                f.fixed_in
                    .as_ref()
                    .map(|v| format!(" The smallest fixed version is {v}."))
                    .unwrap_or_default()
            )
        } else {
            format!(
                "The sources do not give a clear answer for {} {version}; treat it as unknown.",
                entry.name
            )
        };
        (
            verdict_str(f.verdict),
            reason,
            serde_json::to_value(&f.evidence).map_err(|e| e.to_string())?,
        )
    } else if report.summary.not_affected > 0 {
        (
            "not-affected",
            format!(
                "Every source with version data says {} {version} is outside the affected versions of {}.",
                entry.name, vuln.id
            ),
            evidence_from_ranges(),
        )
    } else {
        (
            "unknown",
            format!(
                "The sources have no usable version data for {} {version} and {} (the version may not parse). \
                 That is not the same as not affected.",
                entry.name, vuln.id
            ),
            evidence_from_ranges(),
        )
    };
    let mut data = base(verdict, &reason);
    data["vulnerability"] = json!(vuln.id);
    data["title"] = json!(vuln.summary);
    data["evidence"] = evidence;
    data["ranges"] = json!(ranges);
    data["notes"] = json!(report.notes);
    if let Some(f) = finding {
        data["bucket"] = json!(f.bucket);
        data["rules"] = json!(f.rules);
        data["fixed_in"] = json!(f.fixed_in);
        data["latest_in_cycle"] = json!(f.latest_in_cycle);
        data["cvss"] = json!(f.cvss);
        data["signals"] = json!(f.signals);
        data["finding"] = json!(f);
    } else {
        data["signals"] = json!(db.signals(&vuln.id));
    }
    let mut text = format!("{verdict}. {reason}");
    for r in &ranges {
        let _ = write!(text, "\n- {}: {}", source_name(r), r.raw);
    }
    Ok(Output { text, data })
}

fn find_vuln(db: &Db, id: &str) -> Option<Vulnerability> {
    db.vuln(id)
        .or_else(|| db.vulns_by_alias(id).into_iter().next())
}

fn unknown_product(product: &str) -> String {
    let near: Vec<String> = unpatched_catalog::search(product)
        .iter()
        .take(5)
        .map(|e| e.id.clone())
        .collect();
    if near.is_empty() {
        format!(
            "{product:?} is not in the catalog. Use `search_catalog` to look for it. \
             For a package, check a purl in unpatched.yml instead."
        )
    } else {
        format!(
            "{product:?} is not a catalog product id. Did you mean: {}?",
            near.join(", ")
        )
    }
}

fn report_summary(report: &Report) -> String {
    let s = &report.summary;
    let mut text = format!(
        "{} finding(s): now {}, week {}, eol {}, unknown {}, fyi {}; {} ignored; {} checked and not affected.",
        report.findings.len(),
        s.now,
        s.week,
        s.eol,
        s.unknown,
        s.fyi,
        s.ignored,
        s.not_affected
    );
    for f in report.findings.iter().take(30) {
        let _ = write!(text, "\n- {}", finding_line(f));
    }
    if report.findings.len() > 30 {
        let _ = write!(text, "\n- ... and {} more", report.findings.len() - 30);
    }
    for n in &report.notes {
        let _ = write!(text, "\nNote: {n}");
    }
    text
}

fn finding_line(f: &Finding) -> String {
    let bucket = serde_json::to_value(f.bucket)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut line = format!(
        "[{bucket}] {} {}: {}",
        f.item,
        f.version,
        f.vuln.as_deref().unwrap_or(&f.title)
    );
    if f.vuln.is_some() {
        let _ = write!(line, " ({})", verdict_str(f.verdict));
    }
    if let Some(fix) = &f.fixed_in {
        let _ = write!(line, ", fixed in {fix}");
    }
    line
}

fn signals_line(s: &Signals) -> String {
    let mut parts = Vec::new();
    if let Some(k) = &s.kev {
        parts.push(format!("in CISA KEV since {}", k.date_added));
    }
    if let Some(e) = &s.epss {
        parts.push(format!("EPSS {:.3}", e.score));
    }
    if !s.exploits.is_empty() {
        parts.push(format!("{} public exploit(s)", s.exploits.len()));
    }
    if parts.is_empty() {
        "No exploitation signals recorded.".into()
    } else {
        format!("Signals: {}.", parts.join(", "))
    }
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Affected => "affected",
        Verdict::Fixed => "fixed",
        Verdict::NotAffected => "not-affected",
        Verdict::Unknown => "unknown",
    }
}

fn exposure_str(e: Exposure) -> &'static str {
    match e {
        Exposure::Internet => "internet",
        Exposure::Internal => "internal",
    }
}

fn source_name(r: &AffectedRange) -> String {
    serde_json::to_value(r.source)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn parse_args<T: for<'de> Deserialize<'de>>(args: &Value) -> Result<T, String> {
    serde_json::from_value(args.clone()).map_err(|e| format!("Invalid arguments: {e}."))
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| format!("Cannot encode the result: {e}"))
}
