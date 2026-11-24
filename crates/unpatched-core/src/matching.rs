//! From stack + data to findings. See ADR-0005 for how sources combine.
//!
//! How a finding is made, for one stack item and one vulnerability:
//!
//! 1. Each source is judged on its own (`affected`, `not-affected` or
//!    `unknown`) from the ranges it gave.
//! 2. The verdicts are combined (ADR-0006): `affected` if any source says so
//!    from a specific range or version; `not-affected` only if every source
//!    that has data says so and at least one has data; otherwise `unknown`.
//!    An affected verdict that came only from an `all versions` constraint is
//!    weak: when a source with specific ranges says the version is outside
//!    them and every affected verdict is weak, the result is `unknown` with
//!    `UNP-CONFLICT`. Disagreement adds `UNP-CONFLICT`.
//! 3. An affected finding goes to `now`, `week` or `fyi` by its signals (ADR-0008). An
//!    `unknown` finding is kept (bucket `unknown`) only when the signals
//!    would have made it `now` or `week` if confirmed. The others are dropped
//!    and not counted anywhere: the data cannot say whether they matter, and
//!    listing every vulnerability that lacks version data would bury the report.

pub mod memory;

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Duration, NaiveDate, Utc};

use crate::catalog::CatalogEntry;
use crate::config::{Config, Exposure, Ignore, StackItem, Thresholds};
use crate::model::{
    AffectedRange, Bound, Constraint, DbInfo, EolCycle, Signals, SourceId, SsvcExploitation,
    VulnStatus, Vulnerability,
};
use crate::report::{
    Bucket, BucketCounts, Evidence, Finding, IgnoredBecause, ItemSummary, REPORT_FORMAT, Report,
    Summary, Verdict,
};
use crate::rules::RuleId;
use crate::version::{Scheme, VersionError, constraint_matches};

/// Read access to vulnerability data. `unpatched-db` implements it over
/// SQLite; tests implement it in memory.
pub trait Dataset {
    /// Catalog entry by id or alias.
    fn product(&self, id: &str) -> Option<CatalogEntry>;
    /// All vulnerabilities with a range for this catalog product.
    fn vulns_for_product(&self, product_id: &str) -> Vec<Vulnerability>;
    /// Exploitation signals for a CVE id.
    fn signals(&self, vuln_id: &str) -> Signals;
    /// endoflife.date cycles for a catalog product.
    fn eol_cycles(&self, product_id: &str) -> Vec<EolCycle>;
    /// True when at least one record in the data matched this product's keys.
    fn product_verified(&self, product_id: &str) -> bool;
    fn info(&self) -> Option<DbInfo>;
}

/// What the matcher needs to know about one stack item.
struct Target {
    /// Shown as `Finding::item` (name, else product id or purl).
    display: String,
    /// Stable prefix for finding keys.
    key: String,
    /// `Finding::product`: catalog id, or the purl without its version.
    product: String,
    /// `Finding::product_name`: catalog name, or the purl without its version.
    product_name: String,
    version: String,
    exposure: Exposure,
    scheme: Scheme,
    /// Names an ignore entry's `product` can match.
    ignore_names: Vec<String>,
    /// `AffectedRange::product` value to select ranges with.
    range_key: String,
    is_purl: bool,
}

/// Evaluate a whole config. `package_vulns` holds OSV results per purl stack
/// item (queried by the caller, since core does no I/O). `now` is passed in
/// so results are reproducible.
pub fn evaluate(
    config: &Config,
    data: &dyn Dataset,
    package_vulns: &HashMap<String, Vec<Vulnerability>>,
    now: DateTime<Utc>,
) -> Report {
    let mut run = Run {
        config,
        data,
        today: now.date_naive(),
        findings: Vec::new(),
        ignored: Vec::new(),
        notes: Vec::new(),
        not_affected: 0,
        keys_used: HashMap::new(),
        items: Vec::new(),
        ignore_hits: vec![IgnoreHit::default(); config.ignore.len()],
    };
    let info = data.info();
    run.check_freshness(info.as_ref(), now);
    for (i, item) in config.stack.iter().enumerate() {
        run.item(i, item, package_vulns);
    }
    run.finish(info, now)
}

struct Run<'a> {
    config: &'a Config,
    data: &'a dyn Dataset,
    today: NaiveDate,
    findings: Vec<Finding>,
    ignored: Vec<Finding>,
    notes: Vec<String>,
    not_affected: usize,
    keys_used: HashMap<String, usize>,
    items: Vec<ItemInfo>,
    /// What each `ignore` entry did, in config order.
    ignore_hits: Vec<IgnoreHit>,
}

/// What one `ignore` entry matched during the run.
#[derive(Debug, Clone, Copy, Default)]
struct IgnoreHit {
    /// It hid a finding.
    active: bool,
    /// It matched a finding but had run out.
    expired: bool,
}

/// A stack item that was checked, kept to build its [`ItemSummary`].
struct ItemInfo {
    key: String,
    item: String,
    product: String,
    product_name: String,
    version: String,
    exposure: Exposure,
    scheme: Scheme,
    /// The release cycle (endoflife.date) of the version, when known.
    cycle: Option<String>,
}

impl Run<'_> {
    fn check_freshness(&mut self, info: Option<&DbInfo>, now: DateTime<Utc>) {
        let Some(info) = info else {
            self.notes
                .push("The database has no build date, so its age is unknown.".into());
            return;
        };
        let days = i64::from(self.config.thresholds.stale_warn_days);
        if now - info.built_at <= Duration::days(days) {
            return;
        }
        let age = (now - info.built_at).num_days();
        self.notes.push(format!(
            "The database is {age} days old (built {}); the warning threshold is {days} days. \
             New vulnerabilities may be missing.",
            info.built_at.format("%Y-%m-%d")
        ));
        self.findings.push(Finding {
            key: "data/stale".into(),
            item: "database".into(),
            product: "database".into(),
            product_name: "database".into(),
            version: info.built_at.format("%Y-%m-%d").to_string(),
            exposure: Exposure::Internal,
            vuln: None,
            title: format!("The vulnerability database is {age} days old"),
            verdict: Verdict::Unknown,
            bucket: Bucket::Unknown,
            rules: vec![RuleId::StaleData],
            fixed_in: None,
            fixed_after: None,
            latest_in_cycle: None,
            cvss: None,
            signals: Signals::default(),
            evidence: Vec::new(),
            references: Vec::new(),
            ignored: None,
        });
    }

    fn unique_key(&mut self, base: &str) -> String {
        let n = self.keys_used.entry(base.to_string()).or_insert(0);
        *n += 1;
        if *n == 1 {
            base.to_string()
        } else {
            format!("{base}-{n}")
        }
    }

    fn item(
        &mut self,
        index: usize,
        item: &StackItem,
        package_vulns: &HashMap<String, Vec<Vulnerability>>,
    ) {
        let at = format!("stack[{index}]");
        let mut cycles = Vec::new();
        let mut verified = true;
        let (target, vulns) = match (&item.product, &item.purl) {
            (Some(id), None) => {
                let Some(entry) = self.data.product(id) else {
                    self.notes.push(format!(
                        "{at}: the database has no data for product {id:?} yet. Run `unpatched db update`; if the id may be wrong, `unpatched catalog list` shows the ids."
                    ));
                    return;
                };
                let Some(version) = item.version.clone().filter(|v| !v.trim().is_empty()) else {
                    self.notes.push(format!(
                        "{at}: add version: \"…\" (the version you run) to {id:?}. See `unpatched catalog show {id}` for the format."
                    ));
                    return;
                };
                if !entry.id.eq_ignore_ascii_case(id.trim()) {
                    self.notes
                        .push(format!("{at}: {} is an alias of {}.", id.trim(), entry.id));
                }
                let display = item.name.clone().unwrap_or_else(|| entry.id.clone());
                let key = self.unique_key(&slug(&display));
                cycles = self.data.eol_cycles(&entry.id);
                verified = self.data.product_verified(&entry.id);
                let mut ignore_names = vec![entry.id.clone()];
                ignore_names.extend(item.name.clone());
                let vulns = self.data.vulns_for_product(&entry.id);
                (
                    Target {
                        display,
                        key,
                        product: entry.id.clone(),
                        product_name: entry.name.clone(),
                        version,
                        exposure: item.exposure,
                        scheme: entry.versioning.clone(),
                        ignore_names,
                        range_key: entry.id,
                        is_purl: false,
                    },
                    vulns,
                )
            }
            (None, Some(purl)) => {
                let Some(parts) = parse_purl(purl) else {
                    self.notes.push(format!(
                        "{at}: {purl:?} is not a package URL. Write it like {}.",
                        crate::config::PURL_EXAMPLE
                    ));
                    return;
                };
                let version = item
                    .version
                    .clone()
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or(parts.version.clone());
                if version.is_empty() {
                    self.notes.push(format!("{at}: {purl:?} has no version."));
                    return;
                }
                let display = item.name.clone().unwrap_or_else(|| parts.bare.clone());
                let key = self.unique_key(&slug(&display));
                let mut ignore_names = vec![parts.bare.clone()];
                ignore_names.extend(item.name.clone());
                let vulns = package_vulns
                    .get(purl)
                    .or_else(|| package_vulns.get(&parts.bare))
                    .cloned()
                    .unwrap_or_default();
                (
                    Target {
                        display,
                        key,
                        product: parts.bare.clone(),
                        product_name: parts.bare.clone(),
                        version,
                        exposure: item.exposure,
                        scheme: Scheme::for_purl_type(&parts.ptype, parts.namespace.as_deref()),
                        ignore_names,
                        range_key: format!("purl:{}", parts.bare),
                        is_purl: true,
                    },
                    vulns,
                )
            }
            _ => {
                self.notes
                    .push(format!("{at}: give either product or purl."));
                return;
            }
        };

        let version_err = target.scheme.validate(&target.version).err();
        if let Some(e) = &version_err {
            self.notes.push(format!(
                "{at}: {} cannot be compared, so its findings are unknown ({}).",
                target.display, e.reason
            ));
        }

        if !verified {
            self.findings.push(Finding {
                key: format!("{}/unverified", target.key),
                item: target.display.clone(),
                product: target.product.clone(),
            product_name: target.product_name.clone(),
                version: target.version.clone(),
                exposure: target.exposure,
                vuln: None,
                title: format!(
                    "{} is not found in the vulnerability data, so an empty result is not proof of safety",
                    target.display
                ),
                verdict: Verdict::Unknown,
                bucket: Bucket::Unknown,
                rules: vec![RuleId::UnverifiedProduct],
                fixed_in: None,
                fixed_after: None,
                latest_in_cycle: None,
                cvss: None,
                signals: Signals::default(),
                evidence: Vec::new(),
                references: Vec::new(),
                ignored: None,
            });
        }

        let cycle = find_cycle(&cycles, &target.version);
        self.items.push(ItemInfo {
            key: target.key.clone(),
            item: target.display.clone(),
            product: target.product.clone(),
            product_name: target.product_name.clone(),
            version: target.version.clone(),
            exposure: target.exposure,
            scheme: target.scheme.clone(),
            cycle: cycle.map(|c| c.cycle.clone()),
        });
        if let Some(c) = cycle {
            self.eol_finding(&target, c);
        }
        let latest = cycle
            .and_then(|c| c.latest.as_deref())
            .filter(|l| {
                target.scheme.compare(l, &target.version) == Ok(std::cmp::Ordering::Greater)
            })
            .map(str::to_string);

        for vuln in &vulns {
            self.vuln(&target, vuln, version_err.as_ref(), latest.as_deref());
        }
    }

    fn eol_finding(&mut self, target: &Target, cycle: &EolCycle) {
        let reached = cycle.eol_reached || cycle.eol.is_some_and(|d| d <= self.today);
        if !reached {
            return;
        }
        let when = cycle
            .eol
            .map_or_else(|| "an unknown date".to_string(), |d| d.to_string());
        let detail = format!(
            "release cycle {} reached end of life on {when} (endoflife.date)",
            cycle.cycle
        );
        self.findings.push(Finding {
            key: format!("{}/eol", target.key),
            item: target.display.clone(),
            product: target.product.clone(),
            product_name: target.product_name.clone(),
            version: target.version.clone(),
            exposure: target.exposure,
            vuln: None,
            title: format!(
                "{} {} is past end of life: the {} release cycle no longer gets security fixes",
                target.display, target.version, cycle.cycle
            ),
            verdict: Verdict::Affected,
            bucket: Bucket::Eol,
            rules: vec![RuleId::Eol],
            fixed_in: None,
            fixed_after: None,
            latest_in_cycle: None,
            cvss: None,
            signals: Signals::default(),
            evidence: vec![Evidence {
                source: SourceId::Endoflife,
                verdict: Verdict::Affected,
                detail,
            }],
            references: Vec::new(),
            ignored: None,
        });
    }

    fn vuln(
        &mut self,
        target: &Target,
        vuln: &Vulnerability,
        version_err: Option<&VersionError>,
        latest_in_cycle: Option<&str>,
    ) {
        if vuln.status == VulnStatus::Rejected {
            return;
        }
        let mut ranges: Vec<&AffectedRange> = vuln
            .ranges
            .iter()
            .filter(|r| r.product == target.range_key)
            .collect();
        if ranges.is_empty() && target.is_purl {
            // The caller queried by purl, so every range is about this package.
            ranges = vuln.ranges.iter().collect();
        }
        if ranges.is_empty() {
            return;
        }

        let mut by_source: BTreeMap<SourceId, Vec<&AffectedRange>> = BTreeMap::new();
        for r in ranges {
            by_source.entry(r.source).or_default().push(r);
        }
        let results: Vec<SourceResult> = by_source
            .into_iter()
            .map(|(source, rs)| {
                judge_source(&target.scheme, &target.version, version_err, source, &rs)
            })
            .collect();

        let any_affected = results.iter().any(|r| r.verdict == Verdict::Affected);
        let strong_affected = results
            .iter()
            .any(|r| r.verdict == Verdict::Affected && !r.weak);
        let any_not_affected = results.iter().any(|r| r.verdict == Verdict::NotAffected);
        let with_data: Vec<&SourceResult> = results.iter().filter(|r| r.has_data).collect();
        // Weak "all versions" evidence does not beat a source with specific ranges.
        let weak_conflict = any_affected && !strong_affected && any_not_affected;
        let verdict = if weak_conflict {
            Verdict::Unknown
        } else if any_affected {
            Verdict::Affected
        } else if !with_data.is_empty()
            && with_data.iter().all(|r| r.verdict == Verdict::NotAffected)
        {
            Verdict::NotAffected
        } else {
            Verdict::Unknown
        };
        if verdict == Verdict::NotAffected {
            self.not_affected += 1;
            return;
        }
        let conflict = any_affected && any_not_affected;

        let signals = self.signals_for(vuln);
        let th = &self.config.thresholds;
        let (now_rules, week_rules) = signal_rules(
            &signals,
            vuln.cvss.as_ref().map(|c| c.score),
            target.exposure,
            th,
        );

        let mut rules: Vec<RuleId> = Vec::new();
        let bucket = if verdict == Verdict::Affected {
            if !now_rules.is_empty() {
                rules.extend(&now_rules);
                rules.extend(&week_rules);
                Bucket::Now
            } else if !week_rules.is_empty() {
                rules.extend(&week_rules);
                Bucket::Week
            } else {
                rules.push(RuleId::Affected);
                Bucket::Fyi
            }
        } else {
            if now_rules.is_empty() && week_rules.is_empty() {
                // Unknown and not urgent if confirmed: dropped (see module docs).
                return;
            }
            if weak_conflict {
                rules.push(RuleId::Conflict);
            } else {
                rules.push(
                    if version_err.is_some() || results.iter().any(|r| r.errored) {
                        RuleId::UnknownVersion
                    } else {
                        RuleId::UnknownNoRanges
                    },
                );
            }
            rules.extend(&now_rules);
            rules.extend(&week_rules);
            Bucket::Unknown
        };
        if conflict && !weak_conflict {
            rules.push(RuleId::Conflict);
        }

        let (fixed_in, fixed_after, latest) = if verdict == Verdict::Affected {
            let fixed_in = smallest_fix(&target.scheme, &results);
            let fixed_after = if fixed_in.is_none() {
                largest_inclusive_end(&target.scheme, &results)
            } else {
                None
            };
            (fixed_in, fixed_after, latest_in_cycle.map(str::to_string))
        } else {
            (None, None, None)
        };

        let mut title = if vuln.summary.trim().is_empty() {
            vuln.id.clone()
        } else {
            vuln.summary.trim().to_string()
        };
        if vuln.status == VulnStatus::Disputed {
            title.push_str(" (disputed)");
        }

        let mut finding = Finding {
            key: format!("{}/{}", target.key, vuln.id),
            item: target.display.clone(),
            product: target.product.clone(),
            product_name: target.product_name.clone(),
            version: target.version.clone(),
            exposure: target.exposure,
            vuln: Some(vuln.id.clone()),
            title,
            verdict,
            bucket,
            rules,
            fixed_in,
            fixed_after,
            latest_in_cycle: latest,
            cvss: vuln.cvss.clone(),
            signals,
            evidence: results
                .into_iter()
                .map(|r| Evidence {
                    source: r.source,
                    verdict: r.verdict,
                    detail: r.detail,
                })
                .collect(),
            references: vuln.references.iter().map(|r| r.url.clone()).collect(),
            ignored: None,
        };

        match find_ignore(
            &self.config.ignore,
            vuln,
            target,
            self.today,
            &mut self.ignore_hits,
        ) {
            IgnoreMatch::None => self.findings.push(finding),
            IgnoreMatch::Expired => {
                finding.rules.push(RuleId::IgnoreExpired);
                self.findings.push(finding);
            }
            IgnoreMatch::Active(ig) => {
                finding.rules.insert(0, RuleId::Ignored);
                finding.ignored = Some(IgnoredBecause {
                    reason: ig.reason.clone(),
                    until: ig.until,
                });
                self.ignored.push(finding);
            }
        }
    }

    fn signals_for(&self, vuln: &Vulnerability) -> Signals {
        let s = self.data.signals(&vuln.id);
        if s != Signals::default() || vuln.id.starts_with("CVE-") {
            return s;
        }
        for alias in vuln.aliases.iter().filter(|a| a.starts_with("CVE-")) {
            let s = self.data.signals(alias);
            if s != Signals::default() {
                return s;
            }
        }
        s
    }

    /// Notes for `ignore` entries that did nothing: a wrong id, or one that ran out.
    fn ignore_notes(&mut self) {
        for (i, (ig, hit)) in self.config.ignore.iter().zip(&self.ignore_hits).enumerate() {
            if hit.active {
                continue;
            }
            if hit.expired {
                self.notes.push(format!(
                    "ignore[{i}] expired on {}; the finding is back.",
                    ig.until
                ));
            } else {
                self.notes.push(format!(
                    "ignore[{i}]: {} matches no finding. Check the id or remove it.",
                    ig.cve.trim()
                ));
            }
        }
    }

    fn finish(mut self, db: Option<DbInfo>, now: DateTime<Utc>) -> Report {
        self.ignore_notes();
        let order = |f: &Finding| (f.bucket, f.item.clone(), f.vuln.clone(), f.key.clone());
        self.findings.sort_by_key(order);
        self.ignored.sort_by_key(order);
        let mut summary = Summary {
            ignored: self.ignored.len(),
            not_affected: self.not_affected,
            ..Summary::default()
        };
        for f in &self.findings {
            match f.bucket {
                Bucket::Now => summary.now += 1,
                Bucket::Week => summary.week += 1,
                Bucket::Eol => summary.eol += 1,
                Bucket::Unknown => summary.unknown += 1,
                Bucket::Fyi => summary.fyi += 1,
            }
        }
        let items = self
            .items
            .iter()
            .map(|i| item_summary(i, &self.findings))
            .collect();
        Report {
            format: REPORT_FORMAT,
            generated_at: now,
            db,
            summary,
            findings: self.findings,
            ignored: self.ignored,
            items,
            notes: self.notes,
        }
    }
}

fn release_parts(version: &str) -> Vec<&str> {
    let v = version.trim();
    let v = match v.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => v,
    };
    v.split(['.', '-', '_', '+']).collect()
}

/// True when `version` starts with the components of `prefix`.
fn has_release_prefix(version: &str, prefix: &[&str]) -> bool {
    let parts = release_parts(version);
    prefix.len() <= parts.len()
        && prefix.iter().zip(&parts).all(|(a, b)| {
            if !a.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) {
                // "9.6" matches "9.6p1": compare the leading number.
                same_part(a, leading_number(b))
            } else {
                same_part(a, b)
            }
        })
}

fn leading_number(s: &str) -> &str {
    let end = s
        .bytes()
        .position(|c| !c.is_ascii_digit())
        .unwrap_or(s.len());
    &s[..end]
}

/// The recommendation for one stack item (see [`ItemSummary`]).
fn item_summary(info: &ItemInfo, findings: &[Finding]) -> ItemSummary {
    let mine: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.item_key() == info.key && f.key != "data/stale")
        .collect();
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
    let affected: Vec<&Finding> = mine
        .iter()
        .copied()
        .filter(|f| f.vuln.is_some() && f.verdict == Verdict::Affected)
        .collect();
    let fixes: Vec<&str> = affected
        .iter()
        .filter_map(|f| f.fixed_in.as_deref())
        .collect();
    let prefix_owned: Vec<String> = match &info.cycle {
        Some(c) => c.trim().split('.').map(str::to_string).collect(),
        None => release_parts(&info.version)
            .into_iter()
            .take(2)
            .map(|p| leading_number(p).to_string())
            .filter(|p| !p.is_empty())
            .collect(),
    };
    let prefix: Vec<&str> = prefix_owned.iter().map(String::as_str).collect();
    let largest = |list: &[&str]| -> Option<String> {
        let mut best: Option<&str> = None;
        for v in list {
            best = match best {
                Some(b) if info.scheme.compare(v, b) != Ok(std::cmp::Ordering::Greater) => Some(b),
                None | Some(_) if info.scheme.validate(v).is_ok() => Some(v),
                other => other,
            };
        }
        best.map(str::to_string)
    };
    let in_cycle: Vec<&str> = fixes
        .iter()
        .copied()
        .filter(|v| has_release_prefix(v, &prefix))
        .collect();
    let upgrade_to = largest(&in_cycle).or_else(|| largest(&fixes));
    let fixed_count = upgrade_to.as_deref().map_or(0, |u| {
        fixes
            .iter()
            .filter(|v| {
                info.scheme
                    .compare(v, u)
                    .is_ok_and(|o| o != std::cmp::Ordering::Greater)
            })
            .count()
    });
    ItemSummary {
        key: info.key.clone(),
        item: info.item.clone(),
        product: info.product.clone(),
        product_name: info.product_name.clone(),
        version: info.version.clone(),
        exposure: info.exposure,
        counts,
        upgrade_to,
        fixes: fixed_count,
        of: affected.len(),
        eol: mine.iter().any(|f| f.bucket == Bucket::Eol),
        unfixed: affected
            .iter()
            .filter(|f| f.fixed_in.is_none() && f.fixed_after.is_none())
            .count(),
    }
}

/// Rules that would put an affected finding in `now`, and in `week`.
fn signal_rules(
    signals: &Signals,
    cvss: Option<f64>,
    exposure: Exposure,
    th: &Thresholds,
) -> (Vec<RuleId>, Vec<RuleId>) {
    let internet = exposure == Exposure::Internet;
    let mut now = Vec::new();
    if signals.kev.is_some() {
        now.push(RuleId::Kev);
    }
    if signals.ssvc_exploitation == Some(SsvcExploitation::Active) {
        now.push(RuleId::SsvcActive);
    }
    if !signals.exploits.is_empty() && internet {
        now.push(RuleId::ExploitExposed);
    }
    let mut week = Vec::new();
    if signals.epss.is_some_and(|e| e.score >= th.epss_week) {
        week.push(RuleId::Epss);
    }
    if cvss.is_some_and(|s| s >= th.cvss_week) {
        week.push(RuleId::Cvss);
    }
    if internet && cvss.is_some_and(|s| s >= th.cvss_week_exposed) {
        week.push(RuleId::Exposed);
    }
    (now, week)
}

/// What one source says about one item and vulnerability.
struct SourceResult {
    source: SourceId,
    verdict: Verdict,
    /// The source gave at least one constraint.
    has_data: bool,
    /// A version in this source could not be compared.
    errored: bool,
    detail: String,
    /// Exclusive end bounds of the constraints that matched.
    fixes: Vec<String>,
    /// Inclusive end bounds of the constraints that matched.
    inclusive_ends: Vec<String>,
    /// The affected verdict came only from an `all versions` constraint.
    weak: bool,
}

enum RangeOutcome {
    Affected {
        detail: String,
        fixes: Vec<String>,
        inclusive_ends: Vec<String>,
        weak: bool,
    },
    NotAffected(String),
    NoData,
    Error(String),
}

fn judge_source(
    scheme: &Scheme,
    version: &str,
    version_err: Option<&VersionError>,
    source: SourceId,
    ranges: &[&AffectedRange],
) -> SourceResult {
    let outcomes: Vec<RangeOutcome> = ranges
        .iter()
        .map(|r| judge_range(scheme, version, version_err, r))
        .collect();
    let has_data = ranges.iter().any(|r| !r.constraints.is_empty());
    let errored = outcomes.iter().any(|o| matches!(o, RangeOutcome::Error(_)));
    let mut fixes = Vec::new();
    let mut inclusive_ends = Vec::new();
    let mut weak = true;
    let mut details = Vec::new();
    let mut any_affected = false;
    let mut all_not_affected = true;
    for o in &outcomes {
        match o {
            RangeOutcome::Affected {
                detail,
                fixes: f,
                inclusive_ends: ends,
                weak: w,
            } => {
                any_affected = true;
                all_not_affected = false;
                weak &= *w;
                fixes.extend(f.iter().cloned());
                inclusive_ends.extend(ends.iter().cloned());
                details.push(detail.clone());
            }
            RangeOutcome::NotAffected(d) => details.push(d.clone()),
            RangeOutcome::NoData => {
                all_not_affected = false;
                details.push("no usable version data".to_string());
            }
            RangeOutcome::Error(d) => {
                all_not_affected = false;
                details.push(d.clone());
            }
        }
    }
    details.dedup();
    let verdict = if any_affected {
        Verdict::Affected
    } else if all_not_affected && !outcomes.is_empty() {
        Verdict::NotAffected
    } else {
        Verdict::Unknown
    };
    let verdict_text = match verdict {
        Verdict::Affected => "affected",
        Verdict::NotAffected => "not affected",
        _ => "unknown",
    };
    SourceResult {
        source,
        verdict,
        has_data,
        errored,
        detail: format!("{verdict_text}: {}", details.join("; ")),
        fixes,
        inclusive_ends,
        weak: verdict == Verdict::Affected && weak,
    }
}

fn judge_range(
    scheme: &Scheme,
    version: &str,
    version_err: Option<&VersionError>,
    r: &AffectedRange,
) -> RangeOutcome {
    if r.constraints.is_empty() {
        return RangeOutcome::NoData;
    }
    if let Some(e) = version_err {
        return RangeOutcome::Error(format!("cannot compare: {e}"));
    }
    let raw = if r.raw.trim().is_empty() {
        String::new()
    } else {
        format!(" (source says: {})", r.raw.trim())
    };
    let mut matched: Vec<&Constraint> = Vec::new();
    let mut error: Option<VersionError> = None;
    for c in &r.constraints {
        match constraint_matches(scheme, c, version) {
            Ok(true) => matched.push(c),
            Ok(false) => {}
            Err(e) => error = Some(e),
        }
    }
    if matched.is_empty() {
        return match error {
            Some(e) => RangeOutcome::Error(format!("cannot compare: {e}")),
            None => RangeOutcome::NotAffected(format!(
                "{version} is outside {}{raw}",
                describe_all(&r.constraints)
            )),
        };
    }
    for c in &r.unaffected {
        match constraint_matches(scheme, c, version) {
            Ok(true) => {
                return RangeOutcome::NotAffected(format!(
                    "{version} matches {} but the source lists {} as unaffected{raw}",
                    describe_all(&r.constraints),
                    describe(c)
                ));
            }
            Ok(false) => {}
            Err(e) => return RangeOutcome::Error(format!("cannot compare: {e}")),
        }
    }
    let mut fixes = Vec::new();
    let mut inclusive_ends = Vec::new();
    for c in &matched {
        if let Constraint::Range {
            end: Some(Bound {
                version: v,
                inclusive,
            }),
            ..
        } = c
        {
            if *inclusive {
                inclusive_ends.push(v.clone());
            } else {
                fixes.push(v.clone());
            }
        }
    }
    let weak = matched.iter().all(|c| is_all(c));
    let mut detail = format!("{version} is inside {}{raw}", describe_all_of(&matched));
    if weak {
        detail.push_str(
            "; weak evidence: this source only says all versions are affected and names no range",
        );
    }
    if fixes.is_empty() && !inclusive_ends.is_empty() {
        detail = format!(
            "{detail}; affected up to and including {}, so the fix is a later version this source does not name",
            inclusive_ends.join(", ")
        );
    }
    RangeOutcome::Affected {
        detail,
        fixes,
        inclusive_ends,
        weak,
    }
}

/// A constraint that names no version: `all`, or a range with no bounds.
fn is_all(c: &Constraint) -> bool {
    matches!(
        c,
        Constraint::All
            | Constraint::Range {
                start: None,
                end: None
            }
    )
}

/// The largest inclusive end among the affected sources' matching constraints.
fn largest_inclusive_end(scheme: &Scheme, results: &[SourceResult]) -> Option<String> {
    let mut best: Option<&String> = None;
    for v in results
        .iter()
        .filter(|r| r.verdict == Verdict::Affected)
        .flat_map(|r| &r.inclusive_ends)
    {
        best = match best {
            Some(b) if scheme.compare(v, b) != Ok(std::cmp::Ordering::Greater) => Some(b),
            _ => Some(v),
        };
    }
    best.cloned()
}

fn smallest_fix(scheme: &Scheme, results: &[SourceResult]) -> Option<String> {
    let mut best: Option<&String> = None;
    for f in results
        .iter()
        .filter(|r| r.verdict == Verdict::Affected)
        .flat_map(|r| &r.fixes)
    {
        best = match best {
            Some(b) if scheme.compare(f, b) != Ok(std::cmp::Ordering::Less) => Some(b),
            _ => Some(f),
        };
    }
    best.cloned()
}

fn describe(c: &Constraint) -> String {
    match c {
        Constraint::All => "all versions".to_string(),
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
                "all versions".to_string()
            } else {
                parts.join(" and ")
            }
        }
    }
}

fn describe_all(cs: &[Constraint]) -> String {
    cs.iter().map(describe).collect::<Vec<_>>().join(" or ")
}

fn describe_all_of(cs: &[&Constraint]) -> String {
    cs.iter()
        .map(|c| describe(c))
        .collect::<Vec<_>>()
        .join(" or ")
}

enum IgnoreMatch<'a> {
    None,
    Active(&'a Ignore),
    Expired,
}

fn find_ignore<'a>(
    ignores: &'a [Ignore],
    vuln: &Vulnerability,
    target: &Target,
    today: NaiveDate,
    hits: &mut [IgnoreHit],
) -> IgnoreMatch<'a> {
    let mut expired = false;
    let mut active: Option<&Ignore> = None;
    for (index, ig) in ignores.iter().enumerate() {
        let cve_ok = ig.cve.trim().eq_ignore_ascii_case(&vuln.id)
            || vuln
                .aliases
                .iter()
                .any(|a| ig.cve.trim().eq_ignore_ascii_case(a));
        if !cve_ok {
            continue;
        }
        let product_ok = ig.product.as_deref().is_none_or(|p| {
            target
                .ignore_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(p.trim()))
        });
        if !product_ok {
            continue;
        }
        if ig.until >= today {
            hits[index].active = true;
            if active.is_none_or(|a| ig.until > a.until) {
                active = Some(ig);
            }
        } else {
            hits[index].expired = true;
            expired = true;
        }
    }
    match (active, expired) {
        (Some(ig), _) => IgnoreMatch::Active(ig),
        (None, true) => IgnoreMatch::Expired,
        (None, false) => IgnoreMatch::None,
    }
}

/// The release cycle a version belongs to: the cycle with the most
/// components that is a prefix of the version's components.
fn find_cycle<'a>(cycles: &'a [EolCycle], version: &str) -> Option<&'a EolCycle> {
    let v = version.trim();
    let v = match v.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => v,
    };
    let vparts: Vec<&str> = v.split(['.', '-', '_', '+']).collect();
    cycles
        .iter()
        .filter_map(|c| {
            let cparts: Vec<&str> = c.cycle.trim().split('.').collect();
            let ok = !c.cycle.trim().is_empty()
                && cparts.len() <= vparts.len()
                && cparts.iter().zip(&vparts).all(|(a, b)| same_part(a, b));
            ok.then_some((cparts.len(), c))
        })
        .max_by_key(|(n, _)| *n)
        .map(|(_, c)| c)
}

fn same_part(a: &str, b: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    if digits(a) && digits(b) {
        crate::version::cmp_digits(a, b).is_eq()
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

/// Lowercase, with every run of other characters turned into one `-`.
fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            if dash && !out.is_empty() {
                out.push('-');
            }
            dash = false;
            out.push(c);
        } else {
            dash = true;
        }
    }
    if out.is_empty() {
        "item".to_string()
    } else {
        out
    }
}

struct PurlParts {
    ptype: String,
    namespace: Option<String>,
    /// `pkg:type/namespace/name` without version, qualifiers or subpath.
    bare: String,
    version: String,
}

fn parse_purl(purl: &str) -> Option<PurlParts> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let rest = rest.split('?').next().unwrap_or(rest);
    let (path, version) = match rest.rsplit_once('@') {
        Some((p, v)) => (p, percent_decode(v)),
        None => (rest, String::new()),
    };
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 2 || segments.iter().any(|s| s.is_empty()) {
        return None;
    }
    let namespace = (segments.len() > 2).then(|| segments[1].to_string());
    Some(PurlParts {
        ptype: segments[0].to_ascii_lowercase(),
        namespace,
        bare: format!("pkg:{path}"),
        version,
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = s.get(i + 1..i + 3)
            && let Ok(v) = u8::from_str_radix(hex, 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests;
