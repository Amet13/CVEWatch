//! The tools: definitions (JSON Schema) and what each one does.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use unpatched_core::config::{ConfigError, Exposure, Notify, StackItem, Thresholds};
use unpatched_core::{
    AffectedRange, Bucket, CatalogEntry, Config, Dataset, DbInfo, EolCycle, Finding, Report,
    Signals, Verdict, Vulnerability, evaluate, rules,
};
use unpatched_db::Db;
use unpatched_notify::render::{
    action, bucket_word, counts_line, heartbeat, ignore_snippet, item_line, items_to_show, why,
};
use unpatched_sources::Http;

use crate::ServerContext;

/// What a tool returns: a text summary and the structured result.
#[derive(Debug)]
pub struct Output {
    pub text: String,
    pub data: Value,
}

type ToolResult = Result<Output, String>;

/// `check_stack` lists this many findings unless told otherwise.
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 1000;
/// A source's own text is cut to this many characters in messages.
const RAW_MAX: usize = 200;

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
            "description": "Check every item in unpatched.yml against the vulnerability database. Always returns `summary` (counts per bucket) and `items` (one per stack item, with the upgrade that fixes the most), plus `findings` sorted by urgency (now, week, eol, unknown, fyi) with verdict, rules and fixed_in. By default only now, week, eol and unknown findings come back, at most 50, without evidence: ask for more with `bucket`, `limit` and `include_evidence`. Package (purl) items are looked up in OSV unless the server runs offline.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "config_path": {
                        "type": "string",
                        "description": "Path to unpatched.yml. Only the server's configured file, or a file named unpatched*.yml or unpatched*.yaml under the server's working directory, is allowed. Defaults to the server's configured file."
                    },
                    "bucket": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["now", "week", "eol", "unknown", "fyi"] },
                        "description": "Which buckets to list findings from. Default: now, week, eol, unknown (not fyi)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1000,
                        "description": "At most this many findings (default 50). `summary` always has the full counts."
                    },
                    "include_evidence": {
                        "type": "boolean",
                        "description": "Add the evidence and reference links to each finding (large). Default false."
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
                    },
                    "include_raw": {
                        "type": "boolean",
                        "description": "Give each source's full text in the structured result. Default false: it is cut to about 200 characters."
                    }
                },
                "required": ["product", "version"],
                "additionalProperties": false
            },
            "annotations": read_only("Is this version affected?", false)
        },
        {
            "name": "explain",
            "title": "Explain a CVE, a rule or a finding",
            "description": "Explain a vulnerability id (CVE or advisory id: summary, CVSS, affected ranges per source, exploitation signals), a rule id such as UNP-KEV (what it means and why it puts a finding in a bucket), or a finding key from `check_stack` such as office-firewall/CVE-2024-21762 (judged with the server's configured unpatched.yml).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "A CVE or advisory id (CVE-2024-21762), a rule id (UNP-KEV) or a finding key (office-firewall/CVE-2024-21762)."
                    },
                    "include_raw": {
                        "type": "boolean",
                        "description": "Give each source's full text in the structured result. Default false: it is cut to about 200 characters."
                    }
                },
                "required": ["id"],
                "additionalProperties": false
            },
            "annotations": read_only("Explain a CVE, a rule or a finding", true)
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
        reject_unknown_arguments(name, args)?;
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

    /// Which config file a call may read: the server's own, or an
    /// `unpatched*.yml` under the server's working directory. Symbolic links
    /// are resolved first, so a link cannot point outside.
    fn resolve_config_path(&self, requested: Option<&str>) -> Result<PathBuf, String> {
        let Some(requested) = requested.map(str::trim).filter(|p| !p.is_empty()) else {
            return Ok(self.ctx.config_path.clone());
        };
        let cwd = std::env::current_dir()
            .and_then(std::fs::canonicalize)
            .map_err(|e| format!("Cannot find the server's working directory: {e}"))?;
        let not_allowed = || {
            format!(
                "`config_path` is not allowed. Use the server's configured file ({}), or a file named unpatched*.yml or unpatched*.yaml under {}. Leave out `config_path` to use the server's file.",
                self.ctx.config_path.display(),
                cwd.display()
            )
        };
        // Refuse by name before touching the file system, so a caller cannot
        // learn which other files exist.
        let is_own = Path::new(requested) == self.ctx.config_path;
        if !is_own && !named_like_a_config(Path::new(requested)) {
            return Err(not_allowed());
        }
        let Ok(wanted) = std::fs::canonicalize(requested) else {
            return Err(format!(
                "Cannot read {requested}: no such file. Leave out `config_path` to use the server's file ({}), or create it first.",
                self.ctx.config_path.display()
            ));
        };
        let own = std::fs::canonicalize(&self.ctx.config_path).ok();
        if own.as_ref() == Some(&wanted) {
            return Ok(wanted);
        }
        // Check the resolved path again: a link named unpatched.yml must not
        // lead to another file or out of the working directory.
        if named_like_a_config(&wanted) && wanted.starts_with(&cwd) {
            return Ok(wanted);
        }
        Err(not_allowed())
    }

    /// Read the config, check the stack, and give back the report.
    fn run_report(&mut self, config_path: Option<&str>) -> Result<(Report, PathBuf), String> {
        let path = self.resolve_config_path(config_path)?;
        let text = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "Cannot read {}: {e}. Pass `config_path`, or create unpatched.yml first.",
                path.display()
            )
        })?;
        let config = Config::from_yaml(&text).map_err(|e| config_error(&path, &e))?;
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
        Ok((report, path))
    }

    fn check_stack(&mut self, args: &Value) -> ToolResult {
        #[derive(Deserialize)]
        struct Args {
            config_path: Option<String>,
            bucket: Option<Vec<Bucket>>,
            limit: Option<usize>,
            include_evidence: Option<bool>,
        }
        let a: Args = parse_args(args)?;
        let buckets = a
            .bucket
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| vec![Bucket::Now, Bucket::Week, Bucket::Eol, Bucket::Unknown]);
        let limit = a.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(format!("`limit` must be between 1 and {MAX_LIMIT}."));
        }
        let evidence = a.include_evidence.unwrap_or(false);
        let (report, path) = self.run_report(a.config_path.as_deref())?;

        let matching: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| buckets.contains(&f.bucket))
            .collect();
        let shown: Vec<&Finding> = matching.iter().take(limit).copied().collect();
        let mut text = report_summary(&report, &shown, matching.len());
        let _ = write!(text, "\nConfig: {}", path.display());
        let findings: Vec<Value> = shown
            .iter()
            .map(|f| finding_json(f, evidence))
            .collect::<Result<_, _>>()?;
        let data = json!({
            "format": report.format,
            "generated_at": report.generated_at,
            "db": report.db,
            "summary": report.summary,
            "items": report.items,
            "findings": findings,
            "findings_matching": matching.len(),
            "findings_returned": shown.len(),
            "truncated": matching.len() > shown.len(),
            "buckets": buckets,
            "notes": report.notes,
        });
        Ok(Output { text, data })
    }

    fn is_affected(&mut self, args: &Value) -> ToolResult {
        #[derive(Deserialize)]
        struct Args {
            product: String,
            version: String,
            cve: Option<String>,
            exposure: Option<Exposure>,
            include_raw: Option<bool>,
        }
        let a: Args = parse_args(args)?;
        let raw = a.include_raw.unwrap_or(false);
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
                let shown: Vec<&Finding> = report.findings.iter().take(30).collect();
                text.push_str(&report_summary(&report, &shown, report.findings.len()));
                let findings: Vec<Value> = report
                    .findings
                    .iter()
                    .map(|f| finding_json(f, raw))
                    .collect::<Result<_, _>>()?;
                let data = json!({
                    "product": entry.id,
                    "version": version,
                    "exposure": exposure_str(exposure),
                    "summary": report.summary,
                    "items": report.items,
                    "findings": findings,
                    "notes": report.notes,
                    "db": report.db,
                });
                Ok(Output { text, data })
            }
            Some(cve) => {
                let ask = Ask {
                    entry,
                    version: &version,
                    exposure,
                    cve: &cve,
                    now,
                    raw,
                };
                answer_for_cve(db, &config, ask)
            }
        }
    }

    fn explain(&mut self, args: &Value) -> ToolResult {
        #[derive(Deserialize)]
        struct Args {
            id: String,
            include_raw: Option<bool>,
        }
        let a: Args = parse_args(args)?;
        let raw = a.include_raw.unwrap_or(false);
        let id = a.id.trim();
        if id.is_empty() {
            return Err("`id` must not be empty.".into());
        }
        if id.to_ascii_uppercase().starts_with("UNP-") {
            return explain_rule(id);
        }
        if id.contains('/') {
            return self.explain_finding(id);
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
                cut(&r.raw, RAW_MAX)
            );
        }
        text.push_str(&signals_line(&signals));
        let mut by_source: BTreeMap<String, Vec<AffectedRange>> = BTreeMap::new();
        let mut shown = vuln.clone();
        if !raw {
            for r in &mut shown.ranges {
                r.raw = cut(&r.raw, RAW_MAX);
            }
        }
        for r in &shown.ranges {
            by_source.entry(source_name(r)).or_default().push(r.clone());
        }
        let data = json!({
            "kind": "vulnerability",
            "vulnerability": shown,
            "ranges_by_source": by_source,
            "signals": signals,
        });
        Ok(Output { text, data })
    }

    /// A finding key from `check_stack`, judged with the server's config.
    fn explain_finding(&mut self, key: &str) -> ToolResult {
        let (report, _) = self.run_report(None)?;
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
            return Err(format!(
                "There is no finding with the key {key:?} right now. {}",
                if keys.is_empty() {
                    "`check_stack` shows the current findings; there are none.".to_owned()
                } else {
                    format!("Current keys include: {}.", keys.join(", "))
                }
            ));
        };
        let rules: Vec<&str> = f.rules.iter().map(|r| r.code()).collect();
        let mut text = format!(
            "{} ({}): {}\nVerdict: {} · {}{}\nRules: {}\nWhy: {}\nDo: {}\n",
            unpatched_notify::render::subject(f),
            f.key,
            cut(&f.title, RAW_MAX),
            verdict_str(f.verdict),
            bucket_word(f.bucket),
            if ignored { " (ignored on purpose)" } else { "" },
            rules.join(", "),
            why(f),
            action(f)
        );
        for e in &f.evidence {
            let _ = writeln!(
                text,
                "- {}: {} ({})",
                unpatched_notify::render::source_name(e.source),
                cut(&e.detail, RAW_MAX),
                verdict_str(e.verdict)
            );
        }
        let mut hint = None;
        if !ignored && let Some(cve) = &f.vuln {
            let snippet = ignore_snippet(cve);
            let _ = write!(
                text,
                "To accept this risk, add to unpatched.yml:\n{snippet}"
            );
            hint = Some(snippet);
        }
        let data = json!({
            "kind": "finding",
            "finding": finding_json(f, true)?,
            "ignored": ignored,
            "ignore_snippet": hint,
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

/// One question to `is_affected` about one CVE.
#[derive(Clone, Copy)]
struct Ask<'a> {
    entry: &'a CatalogEntry,
    version: &'a str,
    exposure: Exposure,
    cve: &'a str,
    now: DateTime<Utc>,
    raw: bool,
}

fn answer_for_cve(db: &Db, config: &Config, ask: Ask<'_>) -> ToolResult {
    let Ask {
        entry,
        version,
        exposure,
        cve,
        now,
        raw,
    } = ask;
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
                .map(|r| json!({ "source": r.source, "detail": if raw { r.raw.clone() } else { cut(&r.raw, RAW_MAX) } }))
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
    data["ranges"] = if raw {
        json!(ranges)
    } else {
        let cut_ranges: Vec<AffectedRange> = ranges
            .iter()
            .map(|r| AffectedRange {
                raw: cut(&r.raw, RAW_MAX),
                ..(*r).clone()
            })
            .collect();
        json!(cut_ranges)
    };
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
        let _ = write!(text, "\n- {}: {}", source_name(r), cut(&r.raw, RAW_MAX));
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

/// The text of a report: the counts, one line per stack item, then the findings shown.
fn report_summary(report: &Report, shown: &[&Finding], matching: usize) -> String {
    let mut text = format!("{}. {}", counts_line(report), heartbeat(report));
    if report.summary.ignored > 0 {
        let _ = write!(text, " {} ignored on purpose.", report.summary.ignored);
    }
    for i in items_to_show(report) {
        let _ = write!(text, "\n{}", item_line(i));
    }
    for f in shown.iter().take(30) {
        let _ = write!(text, "\n- {}", finding_line(f));
    }
    if matching > shown.len().min(30) {
        let _ = write!(
            text,
            "\n- ... and {} more (see structuredContent, or raise `limit`)",
            matching - shown.len().min(30)
        );
    }
    for n in &report.notes {
        let _ = write!(text, "\nNote: {n}");
    }
    text
}

fn finding_line(f: &Finding) -> String {
    let mut line = format!(
        "[{}] {} {}: {}",
        bucket_word(f.bucket),
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

/// One finding as JSON. Without `evidence` the evidence and reference lists
/// are left out and a long title is cut: they are what makes a report big.
fn finding_json(f: &Finding, evidence: bool) -> Result<Value, String> {
    let mut v = to_value(f)?;
    if !evidence && let Some(o) = v.as_object_mut() {
        o.remove("evidence");
        o.remove("references");
        if let Some(t) = f.title.chars().nth(300).map(|_| cut(&f.title, 300)) {
            o.insert("title".into(), Value::String(t));
        }
    }
    Ok(v)
}

/// `text` cut to `max` characters on one line, with an ellipsis when cut.
fn cut(text: &str, max: usize) -> String {
    let one: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() <= max {
        return one;
    }
    let head: String = one.chars().take(max.saturating_sub(1)).collect();
    format!("{}…", head.trim_end())
}

/// A config problem, told without echoing what the file says: a parse error
/// from the YAML library can quote the file's own text.
fn config_error(path: &Path, e: &ConfigError) -> String {
    let at = e
        .location()
        .map_or(String::new(), |(l, c)| format!(" at line {l} column {c}"));
    let what = match e {
        ConfigError::Parse(_) => "is not valid YAML".to_owned(),
        ConfigError::Format(_) => format!(
            "does not match the unpatched.yml format{}",
            e.hint().map_or(String::new(), |h| format!(". {h}"))
        ),
        ConfigError::Invalid(m) => {
            return format!(
                "{}: {}. Fix the file and try again.",
                path.display(),
                cut(m, 160)
            );
        }
    };
    format!(
        "{} {what}{at}. Fix the file and try again; the format is in the `unpatched.yml` JSON Schema (`unpatched schema config`).",
        path.display()
    )
}

/// Refuse arguments the tool does not declare (its schema says
/// `additionalProperties: false`, and a typo should not pass quietly).
fn reject_unknown_arguments(name: &str, args: &Value) -> Result<(), String> {
    let Some(given) = args.as_object() else {
        return Ok(());
    };
    let defs = definitions();
    let Some(props) = defs
        .as_array()
        .and_then(|a| a.iter().find(|t| t["name"] == name))
        .and_then(|t| t["inputSchema"]["properties"].as_object())
    else {
        return Ok(());
    };
    let unknown: Vec<&str> = given
        .keys()
        .map(String::as_str)
        .filter(|k| !props.contains_key(*k))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    let accepted: Vec<&str> = props.keys().map(String::as_str).collect();
    Err(format!(
        "Unknown argument{} for {name}: {}. It accepts: {}.",
        if unknown.len() == 1 { "" } else { "s" },
        unknown.join(", "),
        if accepted.is_empty() {
            "no arguments".to_owned()
        } else {
            accepted.join(", ")
        }
    ))
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

/// A file named `unpatched*.yml` or `unpatched*.yaml` (any case).
fn named_like_a_config(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    name.starts_with("unpatched")
        && Path::new(&name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
}
