//! Vulnerability data as `unpatched` sees it after the sources normalise it.

use chrono::NaiveDate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Where a fact came from.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum SourceId {
    /// CVE.org record, CNA container (`affected`).
    CveOrg,
    /// CVE.org record, CISA ADP container (Vulnrichment).
    CisaAdp,
    /// NVD CVE 2.0 feeds (CPE configurations, CVSS).
    Nvd,
    /// OSV.dev (packages).
    Osv,
    /// CISA Known Exploited Vulnerabilities.
    Kev,
    /// FIRST EPSS.
    Epss,
    /// endoflife.date.
    Endoflife,
    /// Exploit-DB index.
    ExploitDb,
    /// Metasploit module metadata.
    Metasploit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VulnStatus {
    #[default]
    Published,
    Rejected,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Cvss {
    pub version: String,
    pub score: f32,
    pub vector: Option<String>,
}

/// One end of a version range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Bound {
    pub version: String,
    pub inclusive: bool,
}

/// What versions a source says are affected. Versions are kept as text and
/// compared with the product's [`crate::Scheme`] at match time, so a version
/// that cannot be parsed becomes `unknown` instead of a guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Constraint {
    /// Every version (a source that says "affected" with no versions).
    All,
    /// Exactly this version.
    Exact { version: String },
    /// `start <= v < end` style, either end optional.
    Range {
        start: Option<Bound>,
        end: Option<Bound>,
    },
}

/// What one source says about one product for one vulnerability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AffectedRange {
    pub source: SourceId,
    /// Catalog product id, or `purl:<package purl without version>` for packages.
    pub product: String,
    /// Affected when any constraint matches. Empty means the source has no
    /// usable version data (the verdict for this source is `unknown`).
    pub constraints: Vec<Constraint>,
    /// Versions this source says are explicitly not affected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unaffected: Vec<Constraint>,
    /// The source's own text, for `explain`.
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Reference {
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Vulnerability {
    /// `CVE-…`, or an OSV/GHSA id when there is no CVE.
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub summary: String,
    pub published: Option<NaiveDate>,
    pub modified: Option<NaiveDate>,
    #[serde(default)]
    pub status: VulnStatus,
    pub cvss: Option<Cvss>,
    pub ranges: Vec<AffectedRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KevEntry {
    pub date_added: NaiveDate,
    pub due_date: Option<NaiveDate>,
    pub known_ransomware: bool,
    pub required_action: String,
    pub vendor_project: String,
    pub product: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Epss {
    pub score: f32,
    pub percentile: f32,
    pub date: NaiveDate,
}

/// SSVC "Exploitation" decision point from the CISA ADP container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SsvcExploitation {
    None,
    Poc,
    Active,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExploitRef {
    pub source: SourceId,
    pub id: String,
    pub url: Option<String>,
}

/// Everything that says how likely a vulnerability is to be used against you.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Signals {
    pub kev: Option<KevEntry>,
    pub epss: Option<Epss>,
    pub ssvc_exploitation: Option<SsvcExploitation>,
    pub ssvc_automatable: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exploits: Vec<ExploitRef>,
}

/// A release cycle from endoflife.date.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EolCycle {
    pub cycle: String,
    pub release_date: Option<NaiveDate>,
    /// `None`: no end date announced.
    pub eol: Option<NaiveDate>,
    /// endoflife.date sometimes says only "true" (ended, date unknown).
    pub eol_reached: bool,
    pub latest: Option<String>,
    pub lts: bool,
}

/// Facts about the database a report was made from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DbInfo {
    pub schema_version: u32,
    pub built_at: chrono::DateTime<chrono::Utc>,
    pub sources: Vec<SourceStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceStatus {
    pub source: SourceId,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub records: u64,
    pub ok: bool,
    pub note: Option<String>,
}
