//! OSV.dev: vulnerabilities in packages, asked for by package URL (purl).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use unpatched_core::{
    AffectedRange, Bound, Constraint, Reference, SourceId, VulnStatus, Vulnerability,
};

use crate::error::{Result, SourceError};
use crate::http::Http;
use crate::util::{date_prefix, normalize_cve, push_unique};

pub const OSV_API: &str = "https://api.osv.dev/v1";

/// The most queries OSV takes in one `querybatch` call.
const BATCH_SIZE: usize = 1000;

// ---- package URLs ----

/// A package URL, read into its parts (percent-escapes decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purl {
    pub ty: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: BTreeMap<String, String>,
    pub subpath: Option<String>,
    /// `pkg:<type>/<namespace>/<name>` as written: no version, no qualifiers.
    base: String,
}

/// A package as OSV names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(v) = hex {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Purl {
    pub fn parse(input: &str) -> Result<Self> {
        let bad = |reason: &str| SourceError::Purl {
            purl: input.to_owned(),
            reason: reason.to_owned(),
        };
        let s = input.trim();
        let rest = s
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("pkg:"))
            .map(|_| s[4..].trim_start_matches('/'))
            .ok_or_else(|| bad("it does not start with 'pkg:'"))?;
        let (rest, subpath) = match rest.split_once('#') {
            Some((r, sub)) => (r, Some(percent_decode(sub))),
            None => (rest, None),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, Some(q)),
            None => (rest, None),
        };
        let mut qualifiers = BTreeMap::new();
        for kv in query.into_iter().flat_map(|q| q.split('&')) {
            if let Some((k, v)) = kv.split_once('=')
                && !v.is_empty()
            {
                qualifiers.insert(k.to_ascii_lowercase(), percent_decode(v));
            }
        }
        // The version starts at the last '@' after the last '/': an '@' in an
        // npm scope (`@angular/core`) comes before it.
        let last_slash = rest.rfind('/').ok_or_else(|| bad("no package name"))?;
        let (path, version) = match rest[last_slash..].rfind('@') {
            Some(at) => {
                let at = last_slash + at;
                (&rest[..at], Some(percent_decode(&rest[at + 1..])))
            }
            None => (rest, None),
        };
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() < 2 || segments.last().is_none_or(|n| n.is_empty()) {
            return Err(bad("it needs a type and a name"));
        }
        let ty = segments[0].to_ascii_lowercase();
        if ty.is_empty()
            || !ty
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
        {
            return Err(bad("the type must be letters, digits, '+', '.' or '-'"));
        }
        let name = percent_decode(segments[segments.len() - 1]);
        let ns: Vec<String> = segments[1..segments.len() - 1]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| percent_decode(s))
            .collect();
        let namespace = (!ns.is_empty()).then(|| ns.join("/"));
        Ok(Self {
            base: format!("pkg:{path}"),
            ty,
            namespace,
            name,
            version: version.filter(|v| !v.is_empty()),
            qualifiers,
            subpath,
        })
    }

    /// The package without version and qualifiers (`pkg:deb/debian/openssl`).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The product id used in [`AffectedRange::product`].
    pub fn product_id(&self) -> String {
        format!("purl:{}", self.base)
    }

    /// The package as OSV names it, when the purl has enough to say so
    /// (for Linux distributions, the release). `None`: query by purl instead.
    pub fn osv_package(&self) -> Option<OsvPackage> {
        let ns = self.namespace.as_deref();
        let full = || match ns {
            Some(ns) => format!("{ns}/{}", self.name),
            None => self.name.clone(),
        };
        let (ecosystem, name) = match self.ty.as_str() {
            "pypi" => ("PyPI".to_owned(), normalize_pypi(&self.name)),
            "npm" => ("npm".to_owned(), full()),
            "cargo" => ("crates.io".to_owned(), self.name.clone()),
            "golang" => ("Go".to_owned(), full()),
            "maven" => (
                "Maven".to_owned(),
                match ns {
                    Some(g) => format!("{g}:{}", self.name),
                    None => self.name.clone(),
                },
            ),
            "gem" => ("RubyGems".to_owned(), self.name.clone()),
            "composer" => ("Packagist".to_owned(), full()),
            "nuget" => ("NuGet".to_owned(), self.name.clone()),
            "hex" => ("Hex".to_owned(), self.name.clone()),
            "pub" => ("Pub".to_owned(), self.name.clone()),
            "deb" => match ns {
                Some("debian") => (
                    format!("Debian:{}", self.debian_release()?),
                    self.name.clone(),
                ),
                Some("ubuntu") => (
                    format!("Ubuntu:{}", self.ubuntu_release()?),
                    self.name.clone(),
                ),
                _ => return None,
            },
            "apk" if ns == Some("alpine") => (
                format!("Alpine:v{}", self.alpine_release()?),
                self.name.clone(),
            ),
            _ => return None,
        };
        Some(OsvPackage { ecosystem, name })
    }

    fn distro(&self) -> Option<&str> {
        self.qualifiers.get("distro").map(String::as_str)
    }

    fn debian_release(&self) -> Option<String> {
        if let Some(d) = self.distro() {
            let d = d.to_ascii_lowercase();
            let d = d.strip_prefix("debian-").unwrap_or(&d);
            if d.starts_with(|c: char| c.is_ascii_digit()) {
                let major: String = d.chars().take_while(char::is_ascii_digit).collect();
                return Some(major);
            }
            let n = match d {
                "stretch" => "9",
                "buster" => "10",
                "bullseye" => "11",
                "bookworm" => "12",
                "trixie" => "13",
                "forky" => "14",
                _ => return None,
            };
            return Some(n.to_owned());
        }
        // Debian security fixes carry the release in the version: 1.2-3~deb12u1.
        let v = self.version.as_deref()?;
        let i = v.find("deb")? + 3;
        let digits: String = v[i..].chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty() && v[i + digits.len()..].starts_with('u')).then_some(digits)
    }

    fn ubuntu_release(&self) -> Option<String> {
        let d = self.distro()?.to_ascii_lowercase();
        let d = d.strip_prefix("ubuntu-").unwrap_or(&d);
        let version = if d.starts_with(|c: char| c.is_ascii_digit()) {
            d.to_owned()
        } else {
            match d {
                "xenial" => "16.04",
                "bionic" => "18.04",
                "focal" => "20.04",
                "jammy" => "22.04",
                "noble" => "24.04",
                "plucky" => "25.04",
                "questing" => "25.10",
                _ => return None,
            }
            .to_owned()
        };
        // Long-term support releases are the April releases of even years.
        let (year, month) = version.split_once('.')?;
        let lts = month == "04" && year.parse::<u32>().ok()? % 2 == 0;
        Some(if lts {
            format!("{version}:LTS")
        } else {
            version
        })
    }

    fn alpine_release(&self) -> Option<String> {
        let d = self.distro()?.to_ascii_lowercase();
        let d = d.strip_prefix("alpine-").unwrap_or(&d);
        let mut it = d.split('.');
        let (major, minor) = (it.next()?, it.next()?);
        let ok = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        (ok(major) && ok(minor)).then(|| format!("{major}.{minor}"))
    }

    fn query(&self) -> Value {
        match self.osv_package() {
            Some(p) => {
                let mut q = json!({"package": {"name": p.name, "ecosystem": p.ecosystem}});
                if let Some(v) = &self.version {
                    q["version"] = json!(v);
                }
                q
            }
            None => json!({"package": {"purl": self.purl_string()}}),
        }
    }

    /// The purl for OSV's purl queries: version kept, qualifiers dropped.
    fn purl_string(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{v}", self.base),
            None => self.base.clone(),
        }
    }
}

/// PEP 503 name normalisation.
fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

// ---- OSV records ----

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct OsvPackageRef {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackageRef>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct OsvReference {
    #[serde(default, rename = "type")]
    pub kind: String,
    pub url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Debian and Ubuntu records name their CVEs here.
    #[serde(default)]
    pub upstream: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

pub fn parse_osv_vuln(bytes: &[u8]) -> Result<OsvVuln> {
    serde_json::from_slice(bytes).map_err(|e| SourceError::parse("an OSV record", e))
}

/// The ids in each result of a `querybatch` answer (in query order) and the
/// token for the next page, if there is one.
pub type BatchResult = (Vec<String>, Option<String>);

pub fn parse_querybatch(bytes: &[u8]) -> Result<Vec<BatchResult>> {
    #[derive(Deserialize)]
    struct Answer {
        #[serde(default)]
        results: Vec<Item>,
    }
    #[derive(Deserialize, Default)]
    struct Item {
        #[serde(default)]
        vulns: Vec<Id>,
        #[serde(default)]
        next_page_token: Option<String>,
    }
    #[derive(Deserialize)]
    struct Id {
        id: String,
    }
    let a: Answer = serde_json::from_slice(bytes)
        .map_err(|e| SourceError::parse("an OSV querybatch answer", e))?;
    Ok(a.results
        .into_iter()
        .map(|i| {
            (
                i.vulns.into_iter().map(|v| v.id).collect(),
                i.next_page_token,
            )
        })
        .collect())
}

/// What a vulnerability record is matched against.
struct Target {
    package: Option<OsvPackage>,
    purl_base: String,
}

impl Target {
    fn of(p: &Purl) -> Self {
        Self {
            package: p.osv_package(),
            purl_base: p.base().to_ascii_lowercase(),
        }
    }

    fn matches(&self, a: &OsvAffected) -> bool {
        let Some(pkg) = &a.package else { return false };
        match &self.package {
            Some(t) => {
                pkg.ecosystem.eq_ignore_ascii_case(&t.ecosystem)
                    && if t.ecosystem == "PyPI" {
                        normalize_pypi(&pkg.name) == t.name
                    } else {
                        pkg.name == t.name
                    }
            }
            None => pkg.purl.as_deref().is_some_and(|p| {
                let end = p.find(['?', '@']).unwrap_or(p.len());
                p[..end].eq_ignore_ascii_case(&self.purl_base)
            }),
        }
    }
}

fn bound(v: &str, inclusive: bool) -> Bound {
    Bound {
        version: v.to_owned(),
        inclusive,
    }
}

fn close(out: &mut Vec<Constraint>, start: Option<Bound>, end: Option<Bound>) {
    push_unique(
        out,
        if start.is_none() && end.is_none() {
            Constraint::All
        } else {
            Constraint::Range { start, end }
        },
    );
}

/// Turn the events of one range into constraints. `introduced: "0"` means
/// "from the first version".
fn range_constraints(r: &OsvRange, out: &mut Vec<Constraint>) {
    let mut open: Option<Option<Bound>> = None;
    for e in &r.events {
        if let Some(v) = &e.introduced {
            if let Some(start) = open.take() {
                close(out, start, None);
            }
            open = Some((v != "0").then(|| bound(v, true)));
        } else if let Some(v) = &e.fixed {
            if let Some(start) = open.take() {
                close(out, start, Some(bound(v, false)));
            }
        } else if let Some(v) = &e.last_affected {
            if let Some(start) = open.take() {
                close(out, start, Some(bound(v, true)));
            }
        } else if let Some(v) = &e.limit
            && let Some(start) = open.take()
        {
            close(out, start, Some(bound(v, false)));
        }
    }
    if let Some(start) = open {
        close(out, start, None);
    }
}

fn affected_constraints(a: &OsvAffected) -> Vec<Constraint> {
    let mut out = Vec::new();
    // GIT ranges are commit ids: they cannot be compared with a release.
    for r in a
        .ranges
        .iter()
        .filter(|r| !r.kind.eq_ignore_ascii_case("GIT"))
    {
        range_constraints(r, &mut out);
    }
    if out.is_empty() {
        for v in &a.versions {
            push_unique(&mut out, Constraint::Exact { version: v.clone() });
        }
    }
    out
}

fn summary_of(v: &OsvVuln) -> String {
    if let Some(s) = v.summary.as_deref().filter(|s| !s.trim().is_empty()) {
        return s.trim().to_owned();
    }
    let first = v
        .details
        .as_deref()
        .and_then(|d| d.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or("")
        .trim();
    let mut out: String = first.chars().take(300).collect();
    if first.chars().count() > 300 {
        out.push('…');
    }
    out
}

/// Make a core [`Vulnerability`] for one package.
///
/// The id is the CVE when the record names exactly one (in `aliases` or
/// `upstream`), with the OSV id as an alias; otherwise it is the OSV id.
/// There is always one range for the package: with no constraints when the
/// record has no version data we can compare. CVSS is not set: OSV gives
/// only vectors.
pub fn vuln_to_core(v: &OsvVuln, package: &Purl) -> Vulnerability {
    let target = Target::of(package);
    let mut cves: Vec<String> = Vec::new();
    for s in std::iter::once(&v.id).chain(&v.aliases).chain(&v.upstream) {
        if let Some(c) = normalize_cve(s)
            && !cves.contains(&c)
        {
            cves.push(c);
        }
    }
    let id = if normalize_cve(&v.id).is_some() {
        v.id.to_ascii_uppercase()
    } else if cves.len() == 1 {
        cves[0].clone()
    } else {
        v.id.clone()
    };
    let mut aliases: Vec<String> = Vec::new();
    for s in std::iter::once(&v.id).chain(&v.aliases).chain(&v.upstream) {
        if *s != id && !aliases.contains(s) {
            aliases.push(s.clone());
        }
    }

    let mut constraints = Vec::new();
    let mut raw: Vec<Value> = Vec::new();
    for a in v.affected.iter().filter(|a| target.matches(a)) {
        for c in affected_constraints(a) {
            push_unique(&mut constraints, c);
        }
        raw.push(json!({
            "package": a.package.as_ref().map(|p| json!({"ecosystem": p.ecosystem, "name": p.name})),
            "ranges": a.ranges,
            "versions_listed": a.versions.len(),
        }));
    }

    let status = if v.withdrawn.is_some() {
        VulnStatus::Rejected
    } else {
        VulnStatus::Published
    };
    Vulnerability {
        id,
        aliases,
        summary: summary_of(v),
        published: v.published.as_deref().and_then(date_prefix),
        modified: v.modified.as_deref().and_then(date_prefix),
        status,
        cvss: None,
        ranges: vec![AffectedRange {
            source: SourceId::Osv,
            product: package.product_id(),
            constraints,
            unaffected: Vec::new(),
            raw: serde_json::to_string(&raw).unwrap_or_default(),
        }],
        references: v
            .references
            .iter()
            .map(|r| Reference {
                url: r.url.clone(),
                tags: if r.kind.is_empty() {
                    Vec::new()
                } else {
                    vec![r.kind.to_ascii_lowercase()]
                },
            })
            .collect(),
    }
}

// ---- network ----

/// Fetch one record by OSV id. `None` when OSV does not know it.
pub fn fetch_vuln(http: &Http, id: &str) -> Result<Option<OsvVuln>> {
    fetch_vuln_at(http, OSV_API, id)
}

fn fetch_vuln_at(http: &Http, base: &str, id: &str) -> Result<Option<OsvVuln>> {
    if id.is_empty() || id.contains(['/', '?', '#', ' ']) {
        return Err(SourceError::NotFound {
            what: format!("OSV id {id:?}"),
        });
    }
    http.get_optional(&format!("{base}/vulns/{id}"))?
        .map(|b| parse_osv_vuln(&b))
        .transpose()
}

/// Ask OSV about packages. The keys of the result are the purls as given.
/// Each purl gets its vulnerabilities (empty when there are none). Vulnerability
/// details are fetched once per id.
pub fn query_batch(http: &Http, purls: &[String]) -> Result<HashMap<String, Vec<Vulnerability>>> {
    query_batch_at(http, OSV_API, purls)
}

pub(crate) fn query_batch_at(
    http: &Http,
    base: &str,
    purls: &[String],
) -> Result<HashMap<String, Vec<Vulnerability>>> {
    let mut parsed: Vec<(&String, Purl)> = Vec::new();
    for p in purls {
        if !parsed.iter().any(|(q, _)| *q == p) {
            parsed.push((p, Purl::parse(p)?));
        }
    }

    // Work list of (index into `parsed`, page token).
    let mut ids: Vec<Vec<String>> = vec![Vec::new(); parsed.len()];
    let mut pending: Vec<(usize, Option<String>)> = (0..parsed.len()).map(|i| (i, None)).collect();
    while !pending.is_empty() {
        let rest = pending.split_off(pending.len().min(BATCH_SIZE));
        let chunk = std::mem::replace(&mut pending, rest);
        let queries: Vec<Value> = chunk
            .iter()
            .map(|(i, token)| {
                let mut q = parsed[*i].1.query();
                if let Some(t) = token {
                    q["page_token"] = json!(t);
                }
                q
            })
            .collect();
        let body = http.post_json(
            &format!("{base}/querybatch"),
            &json!({ "queries": queries }),
        )?;
        let results = parse_querybatch(&body)?;
        if results.len() != chunk.len() {
            return Err(SourceError::parse(
                "an OSV querybatch answer",
                format!(
                    "asked {} questions, got {} answers",
                    chunk.len(),
                    results.len()
                ),
            ));
        }
        for ((i, _), (found, next)) in chunk.into_iter().zip(results) {
            for id in found {
                if !ids[i].contains(&id) {
                    ids[i].push(id);
                }
            }
            if let Some(t) = next {
                pending.push((i, Some(t)));
            }
        }
    }

    let mut details: HashMap<String, Option<OsvVuln>> = HashMap::new();
    let mut out = HashMap::new();
    for ((purl, parsed_purl), found) in parsed.iter().zip(&ids) {
        let mut vulns = Vec::new();
        for id in found {
            if !details.contains_key(id) {
                let rec = fetch_vuln_at(http, base, id)?;
                if rec.is_none() {
                    tracing::warn!(%id, "OSV listed this id but has no record for it; skipping");
                }
                details.insert(id.clone(), rec);
            }
            if let Some(rec) = &details[id] {
                vulns.push(vuln_to_core(rec, parsed_purl));
            }
        }
        out.insert((*purl).clone(), vulns);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TestServer, fixture};
    use chrono::NaiveDate;

    fn p(s: &str) -> Purl {
        Purl::parse(s).unwrap()
    }

    fn vuln(name: &str) -> OsvVuln {
        parse_osv_vuln(&fixture(&format!("osv/vuln_{name}.json"))).unwrap()
    }

    #[allow(clippy::unnecessary_wraps)]
    fn pkg(eco: &str, name: &str) -> Option<OsvPackage> {
        Some(OsvPackage {
            ecosystem: eco.into(),
            name: name.into(),
        })
    }

    #[test]
    fn parses_purls() {
        let x = p("pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=bookworm");
        assert_eq!(x.ty, "deb");
        assert_eq!(x.namespace.as_deref(), Some("debian"));
        assert_eq!(x.name, "openssl");
        assert_eq!(x.version.as_deref(), Some("3.0.11-1~deb12u1"));
        assert_eq!(x.qualifiers["distro"], "bookworm");
        assert_eq!(x.base(), "pkg:deb/debian/openssl");
        assert_eq!(x.product_id(), "purl:pkg:deb/debian/openssl");

        let x = p("pkg:npm/%40angular/core@16.0.0");
        assert_eq!(x.namespace.as_deref(), Some("@angular"));
        assert_eq!(x.name, "core");
        let x = p("pkg:npm/@angular/core");
        assert_eq!(x.namespace.as_deref(), Some("@angular"));
        assert_eq!(x.version, None);
        let x = p("pkg:golang/golang.org/x/net@v0.1.0#sub/dir");
        assert_eq!(x.namespace.as_deref(), Some("golang.org/x"));
        assert_eq!(x.name, "net");
        assert_eq!(x.subpath.as_deref(), Some("sub/dir"));
        assert_eq!(x.base(), "pkg:golang/golang.org/x/net");
        assert_eq!(p("PKG:PyPI/Django@3.2").ty, "pypi");
    }

    #[test]
    fn rejects_bad_purls() {
        for bad in [
            "",
            "openssl",
            "pkg:",
            "pkg:npm",
            "pkg:npm/",
            "pkg:/@1",
            "pkg:Bad Type/x",
        ] {
            let err = Purl::parse(bad).unwrap_err().to_string();
            assert!(err.contains("pkg:"), "{bad}: {err}");
        }
    }

    #[test]
    fn maps_to_osv_packages() {
        let m = |s: &str| p(s).osv_package();
        assert_eq!(
            m("pkg:pypi/Django_REST.framework@1"),
            pkg("PyPI", "django-rest-framework")
        );
        assert_eq!(m("pkg:npm/lodash@4.17.15"), pkg("npm", "lodash"));
        assert_eq!(m("pkg:npm/%40angular/core@16"), pkg("npm", "@angular/core"));
        assert_eq!(m("pkg:cargo/time@0.1.0"), pkg("crates.io", "time"));
        assert_eq!(
            m("pkg:golang/golang.org/x/net@v0.1"),
            pkg("Go", "golang.org/x/net")
        );
        assert_eq!(
            m("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
            pkg("Maven", "org.apache.logging.log4j:log4j-core")
        );
        assert_eq!(m("pkg:gem/rails@6.0"), pkg("RubyGems", "rails"));
        assert_eq!(
            m("pkg:composer/laravel/framework@8"),
            pkg("Packagist", "laravel/framework")
        );
        assert_eq!(
            m("pkg:nuget/Newtonsoft.Json@12"),
            pkg("NuGet", "Newtonsoft.Json")
        );
    }

    #[test]
    fn maps_distro_packages() {
        let m = |s: &str| p(s).osv_package();
        assert_eq!(
            m("pkg:deb/debian/openssl@3.0?distro=bookworm"),
            pkg("Debian:12", "openssl")
        );
        assert_eq!(
            m("pkg:deb/debian/openssl@3.0?distro=debian-11"),
            pkg("Debian:11", "openssl")
        );
        assert_eq!(
            m("pkg:deb/debian/openssl@3.0.11-1~deb12u1"),
            pkg("Debian:12", "openssl")
        );
        assert_eq!(m("pkg:deb/debian/openssl@3.0"), None);
        assert_eq!(
            m("pkg:deb/ubuntu/openssl@3.0?distro=jammy"),
            pkg("Ubuntu:22.04:LTS", "openssl")
        );
        assert_eq!(
            m("pkg:deb/ubuntu/openssl@3.0?distro=ubuntu-24.04"),
            pkg("Ubuntu:24.04:LTS", "openssl")
        );
        assert_eq!(
            m("pkg:deb/ubuntu/openssl@3.0?distro=questing"),
            pkg("Ubuntu:25.10", "openssl")
        );
        assert_eq!(
            m("pkg:apk/alpine/openssl@3.1.4-r5?distro=3.19.1"),
            pkg("Alpine:v3.19", "openssl")
        );
        assert_eq!(
            m("pkg:apk/alpine/openssl@3.1.4-r5?distro=alpine-3.20"),
            pkg("Alpine:v3.20", "openssl")
        );
        assert_eq!(m("pkg:apk/alpine/openssl@3.1.4-r5"), None);
        // no OSV ecosystem name: ask by purl
        assert_eq!(m("pkg:rpm/redhat/openssl@3.0"), None);
        assert_eq!(m("pkg:generic/thing@1"), None);
    }

    #[test]
    fn query_shapes() {
        assert_eq!(
            p("pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm").query(),
            json!({"package":{"name":"openssl","ecosystem":"Debian:12"},"version":"3.0.11-1~deb12u1"})
        );
        assert_eq!(
            p("pkg:rpm/redhat/openssl@3.0?arch=x86_64").query(),
            json!({"package":{"purl":"pkg:rpm/redhat/openssl@3.0"}})
        );
        assert_eq!(
            p("pkg:npm/lodash").query(),
            json!({"package":{"name":"lodash","ecosystem":"npm"}})
        );
    }

    #[test]
    fn debian_record_uses_upstream_cve() {
        let purl = p("pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm");
        let v = vuln_to_core(&vuln("DEBIAN-CVE-2024-0727"), &purl);
        assert_eq!(v.id, "CVE-2024-0727");
        assert_eq!(v.aliases, vec!["DEBIAN-CVE-2024-0727"]);
        assert_eq!(v.status, VulnStatus::Published);
        assert_eq!(v.published, NaiveDate::from_ymd_opt(2024, 1, 26));
        assert_eq!(v.ranges.len(), 1);
        let r = &v.ranges[0];
        assert_eq!(r.source, SourceId::Osv);
        assert_eq!(r.product, "purl:pkg:deb/debian/openssl");
        // only the Debian:12 entry applies
        assert_eq!(
            r.constraints,
            vec![Constraint::Range {
                start: None,
                end: Some(Bound {
                    version: "3.0.13-1~deb12u1".into(),
                    inclusive: false
                })
            }]
        );
        assert!(r.raw.contains("Debian:12"));
        assert!(!r.raw.contains("Debian:13"));
    }

    #[test]
    fn pypi_record_with_one_cve_alias() {
        let purl = p("pkg:pypi/django@2.2.10");
        let v = vuln_to_core(&vuln("PYSEC-2021-9"), &purl);
        assert_eq!(v.id, "CVE-2021-3281");
        assert_eq!(v.aliases[0], "PYSEC-2021-9");
        assert!(v.aliases.contains(&"GHSA-fvgf-6h6h-3322".to_owned()));
        assert!(!v.aliases.contains(&"CVE-2021-3281".to_owned()));
        let c = &v.ranges[0].constraints;
        assert_eq!(c.len(), 3);
        assert_eq!(
            c[0],
            Constraint::Range {
                start: Some(Bound {
                    version: "2.2".into(),
                    inclusive: true
                }),
                end: Some(Bound {
                    version: "2.2.18".into(),
                    inclusive: false
                }),
            }
        );
    }

    #[test]
    fn go_record_picks_the_right_package() {
        let v = vuln_to_core(
            &vuln("GO-2022-0969"),
            &p("pkg:golang/golang.org/x/net@v0.0.1"),
        );
        assert_eq!(v.id, "CVE-2022-27664");
        assert_eq!(v.ranges[0].constraints.len(), 1);
        match &v.ranges[0].constraints[0] {
            Constraint::Range {
                start: None,
                end: Some(e),
            } => {
                assert_eq!(e.version, "0.0.0-20220906165146-f3363e06e74c");
            }
            other => panic!("{other:?}"),
        }
        let v = vuln_to_core(&vuln("GO-2022-0969"), &p("pkg:golang/stdlib@1.18.0"));
        assert_eq!(v.ranges[0].constraints.len(), 2);
    }

    #[test]
    fn two_cves_keep_the_osv_id() {
        let json = br#"{"id":"GHSA-aaaa-bbbb-cccc","aliases":["CVE-2020-0001","CVE-2020-0002"],"summary":"two","affected":[]}"#;
        let v = vuln_to_core(&parse_osv_vuln(json).unwrap(), &p("pkg:npm/x@1"));
        assert_eq!(v.id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(v.aliases, vec!["CVE-2020-0001", "CVE-2020-0002"]);
        // no affected entry for the package: one range with no constraints (unknown)
        assert_eq!(v.ranges.len(), 1);
        assert!(v.ranges[0].constraints.is_empty());
    }

    #[test]
    fn cve_id_stays() {
        let v = vuln_to_core(
            &vuln("CVE-2021-44228"),
            &p("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
        );
        assert_eq!(v.id, "CVE-2021-44228");
        assert!(!v.aliases.contains(&"CVE-2021-44228".to_owned()));
        // this record only has commit ranges: no version data to compare
        assert!(v.ranges[0].constraints.is_empty());
    }

    #[test]
    fn withdrawn_and_no_version_data() {
        let v = vuln_to_core(&vuln("OSV-2023-1121"), &p("pkg:generic/apache-poi@1"));
        assert_eq!(v.status, VulnStatus::Rejected);
        assert!(v.ranges[0].constraints.is_empty());
    }

    #[test]
    fn events_become_constraints() {
        let json = br#"{"id":"X-1","affected":[{"package":{"ecosystem":"npm","name":"x"},
          "ranges":[
            {"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"},{"introduced":"2.0.0"},{"last_affected":"2.3.0"},{"introduced":"3.0.0"}]},
            {"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc123"}]}]}]}"#;
        let v = vuln_to_core(&parse_osv_vuln(json).unwrap(), &p("pkg:npm/x@1.1.0"));
        let b = |v: &str, i| Bound {
            version: v.into(),
            inclusive: i,
        };
        assert_eq!(
            v.ranges[0].constraints,
            vec![
                Constraint::Range {
                    start: Some(b("1.0.0", true)),
                    end: Some(b("1.2.0", false))
                },
                Constraint::Range {
                    start: Some(b("2.0.0", true)),
                    end: Some(b("2.3.0", true))
                },
                Constraint::Range {
                    start: Some(b("3.0.0", true)),
                    end: None
                },
            ]
        );
    }

    #[test]
    fn introduced_zero_without_end_is_all_and_versions_are_a_fallback() {
        let json = br#"{"id":"X-2","affected":[
          {"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]},
          {"package":{"ecosystem":"npm","name":"b"},"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"deadbeef"}]}],"versions":["1.0","1.1"]}]}"#;
        let rec = parse_osv_vuln(json).unwrap();
        let a = vuln_to_core(&rec, &p("pkg:npm/a@1"));
        assert_eq!(a.ranges[0].constraints, vec![Constraint::All]);
        let b = vuln_to_core(&rec, &p("pkg:npm/b@1"));
        assert_eq!(
            b.ranges[0].constraints,
            vec![
                Constraint::Exact {
                    version: "1.0".into()
                },
                Constraint::Exact {
                    version: "1.1".into()
                }
            ]
        );
    }

    #[test]
    fn rustsec_and_ghsa_parse() {
        let v = vuln_to_core(&vuln("RUSTSEC-2020-0071"), &p("pkg:cargo/time@0.1.43"));
        assert!(v.id.starts_with("CVE-") || v.id.starts_with("RUSTSEC-"));
        assert!(!v.ranges[0].constraints.is_empty());
        let v = vuln_to_core(&vuln("GHSA-35jh-r3h4-6jhm"), &p("pkg:npm/lodash@4.17.15"));
        assert_eq!(v.id, "CVE-2021-23337");
        assert!(!v.ranges[0].constraints.is_empty());
        assert!(!v.references.is_empty());
    }

    #[test]
    fn querybatch_fixture() {
        let r = parse_querybatch(&fixture("osv/querybatch.json")).unwrap();
        let counts: Vec<usize> = r.iter().map(|(ids, _)| ids.len()).collect();
        assert_eq!(counts, vec![65, 66, 5, 0]);
        assert!(r.iter().all(|(_, next)| next.is_none()));
    }

    fn osv_server() -> TestServer {
        TestServer::start(|req| {
            if req.method == "POST" && req.path == "/v1/querybatch" {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                let q = body["queries"].as_array().unwrap();
                assert_eq!(q.len(), 4);
                assert_eq!(
                    q[0],
                    json!({"package":{"name":"openssl","ecosystem":"Debian:12"},"version":"3.0.11-1~deb12u1"})
                );
                assert_eq!(q[1]["package"]["ecosystem"], "PyPI");
                return (200, fixture("osv/querybatch.json"));
            }
            let id = req.path.strip_prefix("/v1/vulns/").unwrap_or("");
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../fixtures/osv/vuln_{id}.json"));
            match std::fs::read(path) {
                Ok(b) => (200, b),
                Err(_) => (404, Vec::new()),
            }
        })
    }

    #[test]
    fn query_batch_end_to_end() {
        let srv = osv_server();
        let http = Http::new().unwrap();
        let purls: Vec<String> = [
            "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm",
            "pkg:pypi/django@3.2.0",
            "pkg:npm/lodash@4.17.15",
            "pkg:npm/left-pad-nonexistent-zzz@1.0.0",
        ]
        .map(String::from)
        .to_vec();
        let out = query_batch_at(&http, &srv.url("/v1"), &purls).unwrap();
        assert_eq!(out.len(), 4);
        // only the records we recorded can be fetched; the others are skipped
        let deb = &out[&purls[0]];
        let v = deb.iter().find(|v| v.id == "CVE-2024-0727").unwrap();
        assert_eq!(v.ranges[0].product, "purl:pkg:deb/debian/openssl");
        assert!(out[&purls[3]].is_empty());
        assert!(out[&purls[1]].iter().any(|v| v.id == "CVE-2022-28346"));
        assert!(out[&purls[2]].iter().any(|v| v.id == "CVE-2021-23337"));
    }

    #[test]
    fn query_batch_follows_pages_and_fetches_details_once() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new((0usize, 0usize)));
        let seen = calls.clone();
        let srv = TestServer::start(move |req| {
            let mut c = seen.lock().unwrap();
            if req.path == "/v1/querybatch" {
                c.0 += 1;
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                let q = &body["queries"][0];
                if q.get("page_token").is_none() {
                    (200, br#"{"results":[{"vulns":[{"id":"GHSA-2gwj-7jmv-h26r"}],"next_page_token":"t2"}]}"#.to_vec())
                } else {
                    assert_eq!(q["page_token"], "t2");
                    (200, br#"{"results":[{"vulns":[{"id":"GHSA-2gwj-7jmv-h26r"},{"id":"PYSEC-2021-9"}]}]}"#.to_vec())
                }
            } else {
                c.1 += 1;
                let id = req.path.strip_prefix("/v1/vulns/").unwrap();
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("../../fixtures/osv/vuln_{id}.json"));
                (200, std::fs::read(path).unwrap())
            }
        });
        let http = Http::new().unwrap();
        let purl = "pkg:pypi/django@3.2.0".to_owned();
        let out = query_batch_at(&http, &srv.url("/v1"), &[purl.clone(), purl.clone()]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[&purl].len(), 2);
        assert_eq!(*calls.lock().unwrap(), (2, 2));
    }

    #[test]
    fn bad_purl_stops_the_batch() {
        let http = Http::new().unwrap();
        let err = query_batch_at(&http, "http://127.0.0.1:1", &["nope".into()]).unwrap_err();
        assert!(matches!(err, SourceError::Purl { .. }));
    }
}
