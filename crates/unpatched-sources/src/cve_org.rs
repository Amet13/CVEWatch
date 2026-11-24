//! CVE.org records in CVE JSON 5.x: the CNA's own statement of affected
//! versions, plus the CISA ADP container (SSVC) that `cvelistV5` carries.
//!
//! CNAs write `affected` in many ways. This module reads the common ones and
//! says nothing (empty constraints, which the core reads as "unknown") when
//! it cannot be sure. It never guesses a bound.

use std::path::Path;

use chrono::NaiveDate;
use serde::Deserialize;
use serde_json::Value;
use unpatched_core::{
    AffectedRange, Bound, Constraint, Cvss, Reference, SourceId, SsvcExploitation, VulnStatus,
    Vulnerability,
};

use crate::error::{Result, SourceError};
use crate::http::Http;
use crate::util::{CatalogIndex, date_prefix, push_unique};

pub const CVE_API: &str = "https://cveawg.mitre.org/api/cve";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CveState {
    Published,
    Rejected,
}

/// What a CNA says about versions it does not list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DefaultStatus {
    Affected,
    Unaffected,
    #[default]
    Unknown,
}

/// One `affected` entry of the CNA container, reduced to a product and ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnaAffected {
    /// As the CNA wrote it (empty when the entry has none).
    pub vendor: String,
    /// `product`, or `packageName` when the entry has no product.
    pub product: String,
    /// `vendor:product` pairs found in the entry's `cpes`.
    pub cpe_keys: Vec<String>,
    pub default_status: DefaultStatus,
    /// Affected when any matches. Empty: the entry has no usable version data.
    pub constraints: Vec<Constraint>,
    /// Versions the CNA says are fixed or not affected.
    pub unaffected: Vec<Constraint>,
    /// The entry's `defaultStatus` and `versions` as JSON, for `explain`.
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CveRecord {
    pub id: String,
    pub state: CveState,
    /// The CNA tagged the record `disputed`.
    pub disputed: bool,
    /// English description (the rejection reason for rejected records).
    pub summary: String,
    pub published: Option<NaiveDate>,
    pub updated: Option<NaiveDate>,
    pub cna_affected: Vec<CnaAffected>,
    /// From the CISA ADP SSVC metric.
    pub ssvc_exploitation: Option<SsvcExploitation>,
    pub ssvc_automatable: Option<bool>,
    pub references: Vec<Reference>,
    /// Best score: v4.0, then v3.1, v3.0, v2; the CNA's own before ADP's.
    pub cvss: Option<Cvss>,
}

impl CveRecord {
    /// Make a core [`Vulnerability`] with one `CveOrg` range per catalog product
    /// that an `affected` entry maps to (by CNA vendor and product, or by the
    /// CPE keys in the entry). Entries for products the catalog does not know
    /// are left out.
    ///
    /// Two entries of the same product are merged only when both have version
    /// data and neither lists unaffected versions; otherwise each stays a
    /// separate range, so one entry's "unaffected" never hides another's.
    pub fn to_vulnerability(&self, index: &CatalogIndex) -> Vulnerability {
        let mut ranges: Vec<AffectedRange> = Vec::new();
        for a in &self.cna_affected {
            let mut products: Vec<&String> = Vec::new();
            let cna_key = (a.vendor.clone(), a.product.clone());
            if let Some(ids) = index.cna.get(&cna_key) {
                products.extend(ids);
            }
            if let Some(described) = index.cna_described.get(&cna_key) {
                let text = self.summary.trim_start().to_lowercase();
                for (id, starts) in described {
                    if starts.iter().any(|s| text.starts_with(s.as_str()))
                        && !products.contains(&id)
                    {
                        products.push(id);
                    }
                }
            }
            for key in &a.cpe_keys {
                if let Some(ids) = index.cpe.get(key) {
                    for id in ids {
                        if !products.contains(&id) {
                            products.push(id);
                        }
                    }
                }
            }
            for product in products {
                let mergeable = !a.constraints.is_empty() && a.unaffected.is_empty();
                let existing = ranges.iter_mut().find(|r| {
                    mergeable
                        && r.product == *product
                        && !r.constraints.is_empty()
                        && r.unaffected.is_empty()
                });
                if let Some(r) = existing {
                    for c in &a.constraints {
                        push_unique(&mut r.constraints, c.clone());
                    }
                    r.raw.push('\n');
                    r.raw.push_str(&a.raw);
                } else {
                    ranges.push(AffectedRange {
                        source: SourceId::CveOrg,
                        product: product.clone(),
                        constraints: a.constraints.clone(),
                        unaffected: a.unaffected.clone(),
                        raw: a.raw.clone(),
                    });
                }
            }
        }
        let status = match (self.state, self.disputed) {
            (CveState::Rejected, _) => VulnStatus::Rejected,
            (_, true) => VulnStatus::Disputed,
            _ => VulnStatus::Published,
        };
        Vulnerability {
            id: self.id.clone(),
            aliases: Vec::new(),
            summary: self.summary.clone(),
            published: self.published,
            modified: self.updated,
            status,
            cvss: self.cvss.clone(),
            ranges,
            references: self.references.clone(),
        }
    }
}

// ---- version expressions ----

/// What one version string in a record means.
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    /// "0", "*", "unspecified", ...: no bound.
    Open,
    /// `8.1.*`: the branch `8.1`.
    Wild(String),
    /// A usable version.
    Val(String),
    /// Anything else (spaces, stray `*`, commit ids, prose).
    Bad,
}

fn classify(s: &str) -> Tok {
    let t = s.trim();
    match t.to_ascii_lowercase().as_str() {
        "" | "0" | "*" | "unspecified" | "unknown" | "n/a" | "na" | "-" | "none" => {
            return Tok::Open;
        }
        _ => {}
    }
    if let Some(prefix) = t.strip_suffix(".*") {
        return if prefix.is_empty() || prefix.contains(['*', ' ', ',']) {
            Tok::Bad
        } else {
            Tok::Wild(prefix.to_owned())
        };
    }
    if is_commit_id(t)
        || t.contains(['*', ',', '<', '>', '='])
        || t.chars().any(char::is_whitespace)
    {
        Tok::Bad
    } else {
        Tok::Val(t.to_owned())
    }
}

fn is_commit_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_all(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "*" | "all" | "all versions" | "any" | "any version" | "every version"
    )
}

/// `5.4` -> `5.5`: the first version after the branch. `None` unless the last
/// part is a number.
fn next_branch(prefix: &str) -> Option<String> {
    let (head, last) = match prefix.rsplit_once('.') {
        Some((h, l)) => (Some(h), l),
        None => (None, prefix),
    };
    let next = last.parse::<u64>().ok()?.checked_add(1)?;
    Some(match head {
        Some(h) => format!("{h}.{next}"),
        None => next.to_string(),
    })
}

fn incl(v: &str) -> Bound {
    Bound {
        version: v.to_owned(),
        inclusive: true,
    }
}

fn excl(v: &str) -> Bound {
    Bound {
        version: v.to_owned(),
        inclusive: false,
    }
}

fn range(start: Option<Bound>, end: Option<Bound>) -> Constraint {
    if start.is_none() && end.is_none() {
        Constraint::All
    } else {
        Constraint::Range { start, end }
    }
}

/// Read a lower bound field. `Err(())` means the text cannot be used.
fn start_bound(version: Option<&str>) -> std::result::Result<Option<Bound>, ()> {
    match version.map_or(Tok::Open, classify) {
        Tok::Open => Ok(None),
        Tok::Val(v) | Tok::Wild(v) => Ok(Some(incl(&v))),
        Tok::Bad => Err(()),
    }
}

/// Read a version that stands alone in a CNA entry: an exact version, a
/// branch (`8.1.*`), "all", or a short expression such as `>= 1.1.0, < 1.4.1`
/// or `before 2.3`.
fn parse_version_expr(s: &str) -> Option<Constraint> {
    let t = s.trim();
    if is_all(t) {
        return Some(Constraint::All);
    }
    let mut start = None;
    let mut end = None;
    let mut parts = 0;
    for part in t.split(',') {
        parts += 1;
        let p = part.trim();
        let lower = p.to_ascii_lowercase();
        let (op, rest) = [
            (">=", ">="),
            ("<=", "<="),
            (">", ">"),
            ("<", "<"),
            ("before ", "<"),
            ("prior to ", "<"),
            ("earlier than ", "<"),
            ("through ", "<="),
            ("up to and including ", "<="),
            ("up to ", "<="),
            ("=", "="),
        ]
        .iter()
        .find_map(|(prefix, op)| {
            lower
                .strip_prefix(prefix)
                .map(|_| (*op, &p[prefix.len()..]))
        })
        .unwrap_or(("", p));
        let (rest, op) = if op.is_empty() {
            if let Some(v) = lower
                .strip_suffix(" and earlier")
                .or_else(|| lower.strip_suffix(" and prior"))
                .or_else(|| lower.strip_suffix(" and below"))
                .or_else(|| lower.strip_suffix(" or earlier"))
            {
                (&p[..v.len()], "<=")
            } else if let Some(v) = lower
                .strip_suffix(" and later")
                .or_else(|| lower.strip_suffix(" and above"))
                .or_else(|| lower.strip_suffix(" or later"))
            {
                (&p[..v.len()], ">=")
            } else {
                (rest, op)
            }
        } else {
            (rest, op)
        };
        let Tok::Val(v) = classify(rest) else {
            // A lone branch or a bare version.
            if op.is_empty() && parts == 1 && !t.contains(',') {
                return match classify(rest) {
                    Tok::Wild(prefix) => Some(range(
                        Some(incl(&prefix)),
                        Some(excl(&next_branch(&prefix)?)),
                    )),
                    _ => None,
                };
            }
            return None;
        };
        match op {
            ">=" => start = Some(incl(&v)),
            ">" => start = Some(excl(&v)),
            "<=" => end = Some(incl(&v)),
            "<" => end = Some(excl(&v)),
            "=" | "" if parts == 1 && !t.contains(',') => {
                return Some(Constraint::Exact { version: v });
            }
            _ => return None,
        }
    }
    Some(Constraint::Range { start, end })
}

enum Outcome {
    Constraints(Vec<Constraint>),
    /// Commit-id versions: they say nothing about releases and are skipped.
    Skipped,
    /// A version statement we cannot read.
    Unusable,
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn version_entry(v: &Value) -> Outcome {
    use Outcome::{Constraints, Skipped, Unusable};
    let version_type = str_of(v, "versionType").unwrap_or("");
    let version = str_of(v, "version");
    if version_type.eq_ignore_ascii_case("git") || version.is_some_and(is_commit_id) {
        return Skipped;
    }
    // `patch` versions are build numbers inside a release line (NetScaler
    // "13.1" + "49.13"). Reading them as releases would give wrong verdicts.
    if version_type.eq_ignore_ascii_case("patch") {
        return Unusable;
    }
    let less_than = str_of(v, "lessThan");
    let less_or_equal = str_of(v, "lessThanOrEqual");

    if let Some(changes) = v
        .get("changes")
        .and_then(Value::as_array)
        .filter(|c| !c.is_empty())
    {
        let Ok(mut start) = start_bound(version) else {
            return Unusable;
        };
        let mut open = true; // currently in an affected stretch
        let mut out = Vec::new();
        for ch in changes {
            let (Some(at), Some(status)) = (str_of(ch, "at"), str_of(ch, "status")) else {
                return Unusable;
            };
            let Tok::Val(at) = classify(at) else {
                return Unusable;
            };
            match (open, status) {
                (true, "unaffected") => {
                    out.push(range(start.take(), Some(excl(&at))));
                    open = false;
                }
                (false, "affected") => {
                    start = Some(incl(&at));
                    open = true;
                }
                _ => {}
            }
        }
        if open {
            let end = match (less_than, less_or_equal) {
                (Some(lt), _) => match classify(lt) {
                    Tok::Val(x) => Some(excl(&x)),
                    _ => None,
                },
                (None, Some(le)) => match classify(le) {
                    Tok::Val(x) => Some(incl(&x)),
                    _ => None,
                },
                _ => None,
            };
            out.push(range(start, end));
        }
        return Constraints(out);
    }

    if let Some(lt) = less_than {
        let end = if lt.trim() == "*" {
            None
        } else if let Tok::Val(x) = classify(lt) {
            Some(excl(&x))
        } else {
            return Unusable;
        };
        let Ok(start) = start_bound(version) else {
            return Unusable;
        };
        return Constraints(vec![range(start, end)]);
    }

    if let Some(le) = less_or_equal {
        let end = match classify(le) {
            Tok::Val(x) => Some(incl(&x)),
            Tok::Wild(p) => match next_branch(&p) {
                Some(n) => Some(excl(&n)),
                None => return Unusable,
            },
            Tok::Open if le.trim() == "*" => None,
            _ => return Unusable,
        };
        let Ok(start) = start_bound(version) else {
            return Unusable;
        };
        if let (Some(s), Some(e)) = (&start, &end)
            && s.inclusive
            && e.inclusive
            && s.version == e.version
        {
            return Constraints(vec![Constraint::Exact {
                version: s.version.clone(),
            }]);
        }
        return Constraints(vec![range(start, end)]);
    }

    match version.and_then(parse_version_expr) {
        Some(c) => Constraints(vec![c]),
        None => Unusable,
    }
}

fn cpe_key(cpe: &str) -> Option<String> {
    let rest = cpe
        .strip_prefix("cpe:2.3:")
        .or_else(|| cpe.strip_prefix("cpe:/"))?;
    let parts: Vec<&str> = rest.split(':').collect();
    let (vendor, product) = (parts.get(1)?, parts.get(2)?);
    if vendor.is_empty() || product.is_empty() || *vendor == "*" || *product == "*" {
        return None;
    }
    Some(format!("{vendor}:{product}").to_ascii_lowercase())
}

fn parse_affected(a: &Value) -> CnaAffected {
    let default_status = match str_of(a, "defaultStatus")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("affected") => DefaultStatus::Affected,
        Some("unaffected") => DefaultStatus::Unaffected,
        _ => DefaultStatus::Unknown,
    };
    let mut cpe_keys: Vec<String> = Vec::new();
    for c in a
        .get("cpes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(k) = c.as_str().and_then(cpe_key)
            && !cpe_keys.contains(&k)
        {
            cpe_keys.push(k);
        }
    }

    let mut affected = Vec::new();
    let mut unaffected = Vec::new();
    let mut poisoned = false;
    for entry in a
        .get("versions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let status = str_of(entry, "status").unwrap_or("").to_ascii_lowercase();
        match (status.as_str(), version_entry(entry)) {
            ("affected", Outcome::Constraints(cs)) => {
                for c in cs {
                    push_unique(&mut affected, c);
                }
            }
            ("affected", Outcome::Unusable) => poisoned = true,
            ("unaffected", Outcome::Constraints(cs)) => {
                for c in cs {
                    push_unique(&mut unaffected, c);
                }
            }
            _ => {}
        }
    }

    // Combine the listed versions with what the CNA says about the rest.
    let constraints = match default_status {
        DefaultStatus::Affected if !unaffected.is_empty() || affected.is_empty() || poisoned => {
            vec![Constraint::All]
        }
        _ if poisoned => Vec::new(),
        _ => affected,
    };

    let mut raw_value = serde_json::Map::new();
    for key in [
        "vendor",
        "product",
        "packageName",
        "defaultStatus",
        "versions",
    ] {
        if let Some(v) = a.get(key) {
            raw_value.insert(key.to_owned(), v.clone());
        }
    }
    let mut raw = Value::Object(raw_value).to_string();
    if raw.len() > 4000 {
        let mut cut = 4000;
        while !raw.is_char_boundary(cut) {
            cut -= 1;
        }
        raw.truncate(cut);
        raw.push('…');
    }

    CnaAffected {
        vendor: str_of(a, "vendor").unwrap_or("").to_owned(),
        product: str_of(a, "product")
            .or_else(|| str_of(a, "packageName"))
            .unwrap_or("")
            .to_owned(),
        cpe_keys,
        default_status,
        constraints,
        unaffected,
        raw,
    }
}

// ---- the record ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRecord {
    cve_metadata: RawMeta,
    #[serde(default)]
    containers: RawContainers,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMeta {
    cve_id: String,
    state: String,
    #[serde(default)]
    date_published: Option<String>,
    #[serde(default)]
    date_updated: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawContainers {
    #[serde(default)]
    cna: RawCna,
    #[serde(default)]
    adp: Vec<RawAdp>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawCna {
    #[serde(default)]
    descriptions: Vec<RawText>,
    #[serde(default)]
    rejected_reasons: Vec<RawText>,
    #[serde(default)]
    affected: Vec<Value>,
    #[serde(default)]
    metrics: Vec<Value>,
    #[serde(default)]
    references: Vec<RawRef>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize, Default)]
struct RawAdp {
    #[serde(default)]
    metrics: Vec<Value>,
    #[serde(default)]
    references: Vec<RawRef>,
}

#[derive(Deserialize)]
struct RawText {
    #[serde(default)]
    lang: String,
    value: String,
}

#[derive(Deserialize)]
struct RawRef {
    url: String,
    #[serde(default)]
    tags: Vec<String>,
}

fn pick_cvss(containers: &[&[Value]]) -> Option<Cvss> {
    const KEYS: [(&str, &str); 4] = [
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
        ("cvssV2_0", "2.0"),
    ];
    for (key, version) in KEYS {
        for metrics in containers {
            for m in *metrics {
                if let Some(d) = m.get(key) {
                    let Some(score) = d.get("baseScore").and_then(Value::as_f64) else {
                        continue;
                    };
                    return Some(Cvss {
                        version: str_of(d, "version").unwrap_or(version).to_owned(),
                        score,
                        vector: str_of(d, "vectorString").map(str::to_owned),
                    });
                }
            }
        }
    }
    None
}

fn ssvc(adp: &[RawAdp]) -> (Option<SsvcExploitation>, Option<bool>) {
    let mut exploitation = None;
    let mut automatable = None;
    for m in adp.iter().flat_map(|a| &a.metrics) {
        let Some(other) = m.get("other") else {
            continue;
        };
        if str_of(other, "type") != Some("ssvc") {
            continue;
        }
        let options = other
            .get("content")
            .and_then(|c| c.get("options"))
            .and_then(Value::as_array);
        for opt in options.into_iter().flatten() {
            for (k, v) in opt.as_object().into_iter().flatten() {
                let v = v.as_str().unwrap_or("").to_ascii_lowercase();
                match k.as_str() {
                    "Exploitation" if exploitation.is_none() => {
                        exploitation = match v.as_str() {
                            "none" => Some(SsvcExploitation::None),
                            "poc" => Some(SsvcExploitation::Poc),
                            "active" => Some(SsvcExploitation::Active),
                            _ => None,
                        };
                    }
                    "Automatable" if automatable.is_none() => {
                        automatable = match v.as_str() {
                            "yes" => Some(true),
                            "no" => Some(false),
                            _ => None,
                        };
                    }
                    _ => {}
                }
            }
        }
    }
    (exploitation, automatable)
}

pub fn parse_cve_record(bytes: &[u8]) -> Result<CveRecord> {
    let what = "a CVE.org record";
    let raw: RawRecord = serde_json::from_slice(bytes).map_err(|e| SourceError::parse(what, e))?;
    let state = match raw.cve_metadata.state.as_str() {
        "REJECTED" => CveState::Rejected,
        _ => CveState::Published,
    };
    let cna = raw.containers.cna;
    let english = |list: &[RawText]| {
        list.iter()
            .find(|d| d.lang.starts_with("en"))
            .or_else(|| list.first())
            .map(|d| d.value.clone())
    };
    let summary = english(&cna.descriptions)
        .or_else(|| english(&cna.rejected_reasons))
        .unwrap_or_default();

    let mut references: Vec<Reference> = Vec::new();
    for r in cna
        .references
        .into_iter()
        .chain(raw.containers.adp.iter().flat_map(|a| {
            a.references.iter().map(|r| RawRef {
                url: r.url.clone(),
                tags: r.tags.clone(),
            })
        }))
    {
        if !references.iter().any(|x| x.url == r.url) {
            references.push(Reference {
                url: r.url,
                tags: r.tags,
            });
        }
    }

    let mut metric_lists: Vec<&[Value]> = vec![&cna.metrics];
    metric_lists.extend(raw.containers.adp.iter().map(|a| a.metrics.as_slice()));
    let (ssvc_exploitation, ssvc_automatable) = ssvc(&raw.containers.adp);

    Ok(CveRecord {
        id: raw.cve_metadata.cve_id,
        state,
        disputed: cna.tags.iter().any(|t| t == "disputed"),
        summary,
        published: raw
            .cve_metadata
            .date_published
            .as_deref()
            .and_then(date_prefix),
        updated: raw
            .cve_metadata
            .date_updated
            .as_deref()
            .and_then(date_prefix),
        cna_affected: cna.affected.iter().map(parse_affected).collect(),
        ssvc_exploitation,
        ssvc_automatable,
        references,
        cvss: pick_cvss(&metric_lists),
    })
}

/// Fetch one record from the CVE Services API.
pub fn fetch_record(http: &Http, id: &str) -> Result<CveRecord> {
    fetch_record_at(http, CVE_API, id)
}

pub(crate) fn fetch_record_at(http: &Http, base: &str, id: &str) -> Result<CveRecord> {
    let id = crate::util::normalize_cve(id).ok_or_else(|| SourceError::NotFound {
        what: format!("CVE id {id:?} (it should look like CVE-2024-21762)"),
    })?;
    match http.get_optional(&format!("{base}/{id}"))? {
        Some(bytes) => parse_cve_record(&bytes),
        None => Err(SourceError::NotFound {
            what: format!("{id} at CVE.org"),
        }),
    }
}

/// Walk a `cvelistV5` checkout and parse every `CVE-*.json` under `cves/`
/// (or under `path` itself when it has no `cves` folder), in path order.
/// A file that cannot be read gives an `Err` item and the walk goes on.
pub fn walk_cvelist_dir(path: &Path) -> impl Iterator<Item = Result<CveRecord>> {
    let root = if path.join("cves").is_dir() {
        path.join("cves")
    } else {
        path.to_path_buf()
    };
    walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|entry| match entry {
            Err(e) => {
                let path = e.path().map(Path::to_path_buf).unwrap_or_default();
                Some(Err(SourceError::Io {
                    path,
                    source: std::io::Error::other(e.to_string()),
                }))
            }
            Ok(e) => {
                let name = e.file_name().to_string_lossy();
                if e.file_type().is_file() && name.starts_with("CVE-") && name.ends_with(".json") {
                    Some(read_record_file(e.path()))
                } else {
                    None
                }
            }
        })
}

fn read_record_file(path: &Path) -> Result<CveRecord> {
    let bytes = std::fs::read(path).map_err(|source| SourceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_cve_record(&bytes).map_err(|e| match e {
        SourceError::Parse { message, .. } => SourceError::Parse {
            what: format!("the record {}", path.display()),
            message,
        },
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TestServer, fixture};

    fn rec(id: &str) -> CveRecord {
        parse_cve_record(&fixture(&format!("cve-org/{id}.json"))).unwrap()
    }

    fn rng(start: Option<&str>, s_incl: bool, end: Option<&str>, e_incl: bool) -> Constraint {
        Constraint::Range {
            start: start.map(|v| Bound {
                version: v.into(),
                inclusive: s_incl,
            }),
            end: end.map(|v| Bound {
                version: v.into(),
                inclusive: e_incl,
            }),
        }
    }

    fn exact(v: &str) -> Constraint {
        Constraint::Exact { version: v.into() }
    }

    fn entry<'a>(r: &'a CveRecord, product: &str) -> &'a CnaAffected {
        r.cna_affected
            .iter()
            .find(|a| a.product == product)
            .unwrap_or_else(|| panic!("no entry {product}"))
    }

    fn affected(json: &str) -> CnaAffected {
        parse_affected(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn fortinet_with_cpes_ssvc_and_cvss() {
        let r = rec("CVE-2024-21762");
        assert_eq!(r.state, CveState::Published);
        assert!(r.summary.contains("out-of-bounds write"));
        assert_eq!(r.published, NaiveDate::from_ymd_opt(2024, 2, 9));
        let os = entry(&r, "FortiOS");
        assert_eq!(os.vendor, "Fortinet");
        assert_eq!(os.default_status, DefaultStatus::Unaffected);
        assert_eq!(os.cpe_keys, vec!["fortinet:fortios"]);
        assert_eq!(os.constraints.len(), 6);
        assert_eq!(
            os.constraints[0],
            rng(Some("7.4.0"), true, Some("7.4.2"), true)
        );
        assert_eq!(
            os.constraints[5],
            rng(Some("6.0.0"), true, Some("6.0.18"), true)
        );
        assert!(os.unaffected.is_empty());
        assert_eq!(r.ssvc_exploitation, Some(SsvcExploitation::Active));
        assert_eq!(r.ssvc_automatable, Some(true));
        let c = r.cvss.as_ref().unwrap();
        assert_eq!(c.version, "3.1");
        assert!((c.score - 9.6).abs() < 0.01);
        assert!(!r.references.is_empty());
    }

    #[test]
    fn ivanti_equal_bounds_become_exact() {
        let r = rec("CVE-2024-21887");
        let ics = entry(&r, "ICS");
        assert_eq!(ics.vendor, "Ivanti");
        assert_eq!(ics.constraints, vec![exact("9.1R18"), exact("22.6R2")]);
        assert_eq!(r.cvss.as_ref().unwrap().version, "3.0");
    }

    #[test]
    fn citrix_patch_versions_are_not_guessed() {
        let r = rec("CVE-2023-4966");
        let adc = entry(&r, "NetScaler ADC");
        assert!(adc.constraints.is_empty(), "{:?}", adc.constraints);
        assert!(adc.raw.contains("14.1"));
    }

    #[test]
    fn nextcloud_expression_versions() {
        let r = rec("CVE-2024-22212");
        let a = entry(&r, "security-advisories");
        assert_eq!(a.vendor, "nextcloud");
        assert_eq!(
            a.constraints,
            vec![
                rng(Some("1.1.0"), true, Some("1.4.1"), false),
                rng(Some("2.0.0"), true, Some("2.1.2"), false),
                rng(Some("2.2.0"), true, Some("2.3.4"), false),
                rng(Some("2.4.0"), true, Some("2.4.5"), false),
            ]
        );
    }

    #[test]
    fn microsoft_custom_ranges() {
        let r = rec("CVE-2024-38063");
        assert_eq!(r.cna_affected.len(), 25);
        let w = entry(&r, "Windows 10 Version 1809");
        assert_eq!(
            w.constraints,
            vec![rng(
                Some("10.0.17763.0"),
                true,
                Some("10.0.17763.6293"),
                false
            )]
        );
        assert_eq!(w.default_status, DefaultStatus::Unknown);
        assert_eq!(r.ssvc_exploitation, Some(SsvcExploitation::Poc));
    }

    #[test]
    fn linux_kernel_default_affected_with_unaffected_list() {
        let r = rec("CVE-2024-26925");
        let semver: Vec<_> = r
            .cna_affected
            .iter()
            .filter(|a| a.default_status == DefaultStatus::Affected)
            .collect();
        assert_eq!(semver.len(), 1);
        let a = semver[0];
        assert_eq!(a.constraints, vec![Constraint::All]);
        assert!(a.unaffected.contains(&rng(None, true, Some("6.5"), false)));
        // `5.4.274` to `5.4.*` means before 5.5
        assert!(
            a.unaffected
                .contains(&rng(Some("5.4.274"), true, Some("5.5"), false))
        );
        // the entry that lists commit ids keeps its release ranges and drops the commits
        let first = r
            .cna_affected
            .iter()
            .find(|a| a.default_status == DefaultStatus::Unaffected)
            .unwrap();
        assert!(
            first
                .constraints
                .contains(&rng(Some("5.4.262"), true, Some("5.4.274"), false))
        );
        assert!(first.constraints.iter().all(|c| {
            match c {
                Constraint::Range { start, end } => [start, end]
                    .into_iter()
                    .flatten()
                    .all(|b| b.version.len() < 20),
                _ => true,
            }
        }));
    }

    #[test]
    fn apache_httpd_less_or_equal() {
        let r = rec("CVE-2024-38475");
        let a = entry(&r, "Apache HTTP Server");
        assert_eq!(
            a.constraints,
            vec![rng(Some("2.4.0"), true, Some("2.4.59"), true)]
        );
        assert_eq!(r.ssvc_exploitation, Some(SsvcExploitation::Active));
    }

    #[test]
    fn php_default_affected_with_branch_ranges() {
        let r = rec("CVE-2024-4577");
        let a = entry(&r, "PHP");
        assert_eq!(a.default_status, DefaultStatus::Affected);
        assert_eq!(
            a.constraints,
            vec![
                rng(Some("8.1"), true, Some("8.1.29"), false),
                rng(Some("8.2"), true, Some("8.2.20"), false),
                rng(Some("8.3"), true, Some("8.3.8"), false),
            ]
        );
    }

    #[test]
    fn synology_open_start() {
        let r = rec("CVE-2024-10443");
        let a = entry(&r, "Synology Photos");
        assert_eq!(a.vendor, "Synology");
        assert_eq!(
            a.constraints,
            vec![
                rng(None, true, Some("1.7.0-0795"), false),
                rng(None, true, Some("1.6.2-0720"), false),
            ]
        );
    }

    #[test]
    fn rejected_record() {
        let r = rec("CVE-2024-0069");
        assert_eq!(r.state, CveState::Rejected);
        assert!(r.cna_affected.is_empty());
        assert!(r.summary.contains("unused"), "{}", r.summary);
        let v = r.to_vulnerability(&CatalogIndex::default());
        assert_eq!(v.status, VulnStatus::Rejected);
    }

    #[test]
    fn log4j_changes_make_separate_ranges() {
        let r = rec("CVE-2021-44228");
        let a = &r.cna_affected[0];
        assert_eq!(a.product, "Apache Log4j2");
        assert_eq!(
            a.constraints,
            vec![
                rng(Some("2.0-beta9"), true, Some("2.3.1"), false),
                rng(Some("2.4"), true, Some("2.12.2"), false),
                rng(Some("2.13.0"), true, Some("2.15.0"), false),
            ]
        );
    }

    #[test]
    fn openssh_and_red_hat_rpm_entries() {
        let r = rec("CVE-2024-6387");
        // no vendor: the package name is the product
        let ssh = r
            .cna_affected
            .iter()
            .find(|a| a.product == "OpenSSH")
            .unwrap();
        assert_eq!(ssh.vendor, "");
        assert_eq!(
            ssh.constraints,
            vec![rng(Some("8.5p1"), true, Some("9.7p1"), true)]
        );
        let rhel = entry(&r, "Red Hat Enterprise Linux 9");
        assert_eq!(rhel.constraints, vec![Constraint::All]);
        assert_eq!(
            rhel.unaffected,
            vec![rng(Some("0:8.7p1-38.el9_4.1"), true, None, false)]
        );
        assert!(
            rhel.cpe_keys
                .contains(&"redhat:enterprise_linux".to_owned())
        );
    }

    #[test]
    fn palo_alto_unaffected_only_entries_have_no_constraints() {
        let r = rec("CVE-2024-3400");
        let all = r
            .cna_affected
            .iter()
            .find(|a| a.product == "Cloud NGFW")
            .unwrap();
        assert!(all.constraints.is_empty());
        assert_eq!(all.unaffected, vec![Constraint::All]);
        assert_eq!(r.ssvc_automatable, Some(true));
    }

    #[test]
    fn expressions() {
        assert_eq!(parse_version_expr("*"), Some(Constraint::All));
        assert_eq!(parse_version_expr("All"), Some(Constraint::All));
        assert_eq!(parse_version_expr("1.2.3"), Some(exact("1.2.3")));
        assert_eq!(
            parse_version_expr("8.1.*"),
            Some(rng(Some("8.1"), true, Some("8.2"), false))
        );
        assert_eq!(
            parse_version_expr("< 2.3"),
            Some(rng(None, true, Some("2.3"), false))
        );
        assert_eq!(
            parse_version_expr("<=2.3"),
            Some(rng(None, true, Some("2.3"), true))
        );
        assert_eq!(
            parse_version_expr("> 1.0, <= 2.0"),
            Some(rng(Some("1.0"), false, Some("2.0"), true))
        );
        assert_eq!(
            parse_version_expr("before 2.3"),
            Some(rng(None, true, Some("2.3"), false))
        );
        assert_eq!(
            parse_version_expr("through 7.4.2"),
            Some(rng(None, true, Some("7.4.2"), true))
        );
        assert_eq!(
            parse_version_expr("1.5 and earlier"),
            Some(rng(None, true, Some("1.5"), true))
        );
        assert_eq!(
            parse_version_expr("1.5 and later"),
            Some(rng(Some("1.5"), true, None, true))
        );
        for bad in [
            "",
            "unspecified",
            "n/a",
            "see advisory",
            "10.0 build 5",
            "0",
        ] {
            assert_eq!(parse_version_expr(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn less_than_variants() {
        // "0" and "unspecified" start mean no start
        let a = affected(
            r#"{"vendor":"v","product":"p","versions":[
            {"version":"unspecified","lessThan":"2.0","status":"affected"},
            {"version":"1.0","lessThan":"*","status":"affected","versionType":"semver"}]}"#,
        );
        assert_eq!(
            a.constraints,
            vec![
                rng(None, true, Some("2.0"), false),
                rng(Some("1.0"), true, None, false)
            ]
        );
        // "0" up to everything is All
        let a = affected(
            r#"{"product":"p","versions":[{"version":"0","lessThan":"*","status":"affected"}]}"#,
        );
        assert_eq!(a.constraints, vec![Constraint::All]);
        // wildcard end for lessThanOrEqual
        let a = affected(
            r#"{"product":"p","versions":[{"version":"2.1.0","lessThanOrEqual":"2.1.*","status":"affected"}]}"#,
        );
        assert_eq!(
            a.constraints,
            vec![rng(Some("2.1.0"), true, Some("2.2"), false)]
        );
    }

    #[test]
    fn unusable_entries_never_become_partial_data() {
        // one good range and one unreadable: say nothing instead of half
        let a = affected(
            r#"{"product":"p","defaultStatus":"unaffected","versions":[
            {"version":"1.0","lessThan":"2.0","status":"affected"},
            {"version":"see advisory","status":"affected"}]}"#,
        );
        assert!(a.constraints.is_empty());
        // but when the default is "affected", unreadable entries mean All
        let a = affected(
            r#"{"product":"p","defaultStatus":"affected","versions":[{"version":"see advisory","status":"affected"}]}"#,
        );
        assert_eq!(a.constraints, vec![Constraint::All]);
        // garbage upper bounds
        let a = affected(
            r#"{"product":"p","versions":[{"version":"1","lessThan":"log4j-core*","status":"affected"}]}"#,
        );
        assert!(a.constraints.is_empty());
        // no versions at all and default unknown: unknown
        assert!(affected(r#"{"product":"p"}"#).constraints.is_empty());
        // no versions and default affected: everything
        assert_eq!(
            affected(r#"{"product":"p","defaultStatus":"affected"}"#).constraints,
            vec![Constraint::All]
        );
        // status unknown is ignored
        let a = affected(r#"{"product":"p","versions":[{"version":"1.0","status":"unknown"}]}"#);
        assert!(a.constraints.is_empty());
    }

    #[test]
    fn old_style_cpes() {
        assert_eq!(
            cpe_key("cpe:/a:redhat:enterprise_linux:9::appstream").as_deref(),
            Some("redhat:enterprise_linux")
        );
        assert_eq!(
            cpe_key("cpe:2.3:a:Apache:HTTP_Server:*:*:*:*:*:*:*:*").as_deref(),
            Some("apache:http_server")
        );
        assert_eq!(cpe_key("nonsense"), None);
    }

    fn index() -> CatalogIndex {
        let mut idx = CatalogIndex::default();
        idx.cna.insert(
            ("Fortinet".into(), "FortiOS".into()),
            vec!["fortios".into()],
        );
        idx.cpe
            .insert("redhat:enterprise_linux".into(), vec!["rhel".into()]);
        idx.cna.insert(
            ("Synology".into(), "Synology Photos".into()),
            vec!["synology-photos".into()],
        );
        idx
    }

    #[test]
    fn to_vulnerability_by_cna_and_cpe_keys() {
        let v = rec("CVE-2024-21762").to_vulnerability(&index());
        assert_eq!(v.id, "CVE-2024-21762");
        assert_eq!(v.status, VulnStatus::Published);
        assert_eq!(v.ranges.len(), 1);
        assert_eq!(v.ranges[0].source, SourceId::CveOrg);
        assert_eq!(v.ranges[0].product, "fortios");
        assert_eq!(v.ranges[0].constraints.len(), 6);

        // the Red Hat entries map through their CPE keys; each has `unaffected`, so none merge
        let v = rec("CVE-2024-6387").to_vulnerability(&index());
        assert!(!v.ranges.is_empty());
        assert!(v.ranges.iter().all(|r| r.product == "rhel"));
        assert!(v.ranges.iter().any(|r| !r.unaffected.is_empty()));
    }

    #[test]
    fn cna_key_with_a_description_condition() {
        // Nextcloud files every app under `security-advisories`. Only records
        // about the server (by the description) count for the server product.
        let key = |starts: &[&str]| {
            let e = unpatched_core::CatalogEntry {
                id: "nextcloud".into(),
                name: "Nextcloud Server".into(),
                vendor: "Nextcloud".into(),
                kind: unpatched_core::ProductKind::Server,
                versioning: unpatched_core::Scheme::Dotted,
                keys: unpatched_core::MatchKeys {
                    cna: vec![unpatched_core::catalog::CnaKey {
                        vendor: "nextcloud".into(),
                        product: "security-advisories".into(),
                        summary_starts: starts.iter().map(|s| (*s).to_owned()).collect(),
                    }],
                    ..Default::default()
                },
                eol: None,
                aliases: vec![],
                homepage: None,
                version_hint: None,
                checked: chrono::NaiveDate::from_ymd_opt(2026, 11, 1).unwrap(),
            };
            CatalogIndex::from_catalog(&[e])
        };
        let idx = key(&["Nextcloud Server is a self hosted personal cloud system."]);
        // CVE-2024-22212 is about the Global Site Selector app: no server range.
        let app = rec("CVE-2024-22212");
        assert!(app.summary.starts_with("Nextcloud Global Site Selector"));
        assert!(app.to_vulnerability(&idx).ranges.is_empty());
        // A record that starts like a server advisory is kept.
        let server = parse_cve_record(
            br#"{"cveMetadata":{"cveId":"CVE-2024-37315","state":"PUBLISHED"},
            "containers":{"cna":{"descriptions":[{"lang":"en","value":"Nextcloud Server is a self hosted personal cloud system. An attacker can restore older versions."}],
            "affected":[{"vendor":"nextcloud","product":"security-advisories","versions":[{"version":">= 26.0.0, < 26.0.12","status":"affected"}]}]}}}"#,
        )
        .unwrap();
        let v = server.to_vulnerability(&idx);
        assert_eq!(v.ranges.len(), 1);
        assert_eq!(v.ranges[0].product, "nextcloud");
        // Without a condition the old behaviour (every record counts) stays possible.
        assert_eq!(app.to_vulnerability(&key(&[])).ranges.len(), 1);
    }

    #[test]
    fn same_product_entries_merge_only_when_safe() {
        let r = parse_cve_record(
            br#"{"cveMetadata":{"cveId":"CVE-2020-1","state":"PUBLISHED"},
            "containers":{"cna":{"descriptions":[{"lang":"en","value":"x"}],"affected":[
              {"vendor":"V","product":"P","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]},
              {"vendor":"V","product":"P","versions":[{"version":"2.0","lessThan":"2.5","status":"affected"}]},
              {"vendor":"V","product":"P","defaultStatus":"affected","versions":[{"version":"3.0","status":"unaffected"}]}
            ]}}}"#,
        )
        .unwrap();
        let mut idx = CatalogIndex::default();
        idx.cna.insert(("V".into(), "P".into()), vec!["p".into()]);
        let v = r.to_vulnerability(&idx);
        assert_eq!(v.ranges.len(), 2);
        assert_eq!(v.ranges[0].constraints.len(), 2);
        assert_eq!(v.ranges[1].constraints, vec![Constraint::All]);
        assert_eq!(v.ranges[1].unaffected, vec![exact("3.0")]);
    }

    #[test]
    fn disputed_tag() {
        let r = parse_cve_record(
            br#"{"cveMetadata":{"cveId":"CVE-2020-2","state":"PUBLISHED"},
            "containers":{"cna":{"tags":["disputed"],"descriptions":[{"lang":"en","value":"x"}]}}}"#,
        )
        .unwrap();
        assert!(r.disputed);
        assert_eq!(
            r.to_vulnerability(&CatalogIndex::default()).status,
            VulnStatus::Disputed
        );
    }

    #[test]
    fn walk_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("cves/2024/21xxx");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("CVE-2024-21762.json"),
            fixture("cve-org/CVE-2024-21762.json"),
        )
        .unwrap();
        std::fs::write(
            sub.join("CVE-2024-21887.json"),
            fixture("cve-org/CVE-2024-21887.json"),
        )
        .unwrap();
        std::fs::write(sub.join("CVE-2024-99999.json"), b"{not json").unwrap();
        std::fs::write(dir.path().join("cves/delta.json"), b"{}").unwrap();
        let items: Vec<_> = walk_cvelist_dir(dir.path()).collect();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_ref().unwrap().id, "CVE-2024-21762");
        assert_eq!(items[1].as_ref().unwrap().id, "CVE-2024-21887");
        let err = items[2].as_ref().unwrap_err().to_string();
        assert!(err.contains("CVE-2024-99999.json"), "{err}");
    }

    #[test]
    fn fetch_record_from_server() {
        let body = fixture("cve-org/CVE-2024-21762.json");
        let srv = TestServer::start(move |req| {
            if req.path == "/api/cve/CVE-2024-21762" {
                (200, body.clone())
            } else {
                (404, Vec::new())
            }
        });
        let http = Http::new().unwrap();
        let base = srv.url("/api/cve");
        assert_eq!(
            fetch_record_at(&http, &base, "cve-2024-21762").unwrap().id,
            "CVE-2024-21762"
        );
        assert!(matches!(
            fetch_record_at(&http, &base, "CVE-2024-1"),
            Err(SourceError::NotFound { .. })
        ));
        assert!(matches!(
            fetch_record_at(&http, &base, "CVE-2024-12345"),
            Err(SourceError::NotFound { .. })
        ));
    }
}
