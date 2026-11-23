//! The report: what `check` returns, what notifiers render, what the JSON
//! output and the MCP server expose (`schema/report.schema.json`).

use chrono::{DateTime, NaiveDate, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::Exposure;
use crate::model::{Cvss, DbInfo, Signals, SourceId};
use crate::rules::RuleId;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Affected,
    /// Was affected; the configured version is at or past the fix.
    Fixed,
    NotAffected,
    Unknown,
}

/// How soon to act. Ordered most urgent first.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Bucket {
    /// Fix today.
    Now,
    /// Fix this week.
    Week,
    /// The release cycle is past end of life.
    Eol,
    /// Could be urgent, but the data cannot say yet.
    Unknown,
    /// Affected, low urgency.
    Fyi,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub source: SourceId,
    pub verdict: Verdict,
    /// Human-readable: "affected 7.2.0 to 7.2.6 (CNA Fortinet)".
    pub detail: String,
}

/// One stack item × one vulnerability (or one EOL / data problem).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    /// Stable across runs: `<item key>/<vuln id or rule>`. Used for dedup and issue markers.
    pub key: String,
    /// The stack item's `name`, else product id or purl.
    pub item: String,
    pub product: String,
    pub version: String,
    pub exposure: Exposure,
    /// CVE or advisory id; `None` for EOL and data findings.
    pub vuln: Option<String>,
    pub title: String,
    pub verdict: Verdict,
    pub bucket: Bucket,
    /// Why this bucket, most important first.
    pub rules: Vec<RuleId>,
    /// Smallest version that fixes it, when known.
    pub fixed_in: Option<String>,
    /// Latest release in the same cycle (endoflife.date), when newer than `fixed_in`.
    pub latest_in_cycle: Option<String>,
    pub cvss: Option<Cvss>,
    pub signals: Signals,
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Set when an ignore entry matched (the finding is then in `Report::ignored`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignored: Option<IgnoredBecause>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IgnoredBecause {
    pub reason: String,
    pub until: NaiveDate,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Summary {
    pub now: usize,
    pub week: usize,
    pub eol: usize,
    pub unknown: usize,
    pub fyi: usize,
    pub ignored: usize,
    /// Vulnerabilities checked against the stack that did not affect it.
    pub not_affected: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Report {
    /// Report format version.
    pub format: u32,
    pub generated_at: DateTime<Utc>,
    pub db: Option<DbInfo>,
    pub summary: Summary,
    /// Sorted by bucket, then item, then vuln id.
    pub findings: Vec<Finding>,
    pub ignored: Vec<Finding>,
    /// Problems with the run itself (stale data, unknown product ids, …).
    pub notes: Vec<String>,
}

pub const REPORT_FORMAT: u32 = 1;
