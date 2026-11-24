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
    /// Display name of the product: the catalog name ("FortiOS"), or the purl
    /// without its version for packages.
    pub product_name: String,
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
    /// Set when `fixed_in` is unknown and a source says every version up to
    /// and including this one is affected: the fix is a later release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_after: Option<String>,
    /// Set to the installed release branch (for example `7.2`) when `fixed_in`
    /// is on another branch: this branch has no fix in the data, and the fix
    /// means moving to another release train.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_other_train: Option<String>,
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

impl Finding {
    /// The stack item's key: the part of `key` before the first `/`.
    pub fn item_key(&self) -> &str {
        self.key.split_once('/').map_or(&self.key, |(k, _)| k)
    }

    /// What to do, when the wording depends on more than the fix version: the
    /// only fix is on another release train, or a version in the data cannot be
    /// read. `None` leaves the wording to the renderer.
    pub fn advice(&self) -> Option<String> {
        match self.verdict {
            Verdict::Affected if self.bucket != Bucket::Eol => {
                let branch = self.fix_other_train.as_deref()?;
                let fix = self.fixed_in.as_deref()?;
                Some(format!(
                    "No fix on the {branch} branch in the data; the first fixed release is {fix} \
                     (another release train). Check the vendor advisory."
                ))
            }
            Verdict::Unknown if self.rules.first() == Some(&RuleId::UnknownData) => {
                Some(self.unreadable_data_advice())
            }
            _ => None,
        }
    }

    /// "A version in the NVD data cannot be read ('9.5.1.'). Your version is fine."
    fn unreadable_data_advice(&self) -> String {
        let bad = |e: &Evidence| {
            let rest = e.detail.split_once("cannot read \"")?.1;
            rest.split_once('"').map(|(v, _)| v.to_string())
        };
        let found = self
            .evidence
            .iter()
            .find_map(|e| bad(e).map(|v| (e.source, v)));
        match found {
            Some((source, v)) => format!(
                "A version in the {} data cannot be read ('{v}'). Your version is fine; \
                 read the advisory and check it by hand.",
                source.label()
            ),
            None => "A version in the data cannot be read. Your version is fine; read the \
                     advisory and check it by hand."
                .into(),
        }
    }
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

/// Findings per bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct BucketCounts {
    pub now: usize,
    pub week: usize,
    pub eol: usize,
    pub unknown: usize,
    pub fyi: usize,
}

impl BucketCounts {
    pub fn get(&self, b: Bucket) -> usize {
        match b {
            Bucket::Now => self.now,
            Bucket::Week => self.week,
            Bucket::Eol => self.eol,
            Bucket::Unknown => self.unknown,
            Bucket::Fyi => self.fyi,
        }
    }

    pub fn total(&self) -> usize {
        self.now + self.week + self.eol + self.unknown + self.fyi
    }

    /// The most urgent bucket that has a finding.
    pub fn most_urgent(&self) -> Option<Bucket> {
        [
            Bucket::Now,
            Bucket::Week,
            Bucket::Eol,
            Bucket::Unknown,
            Bucket::Fyi,
        ]
        .into_iter()
        .find(|b| self.get(*b) > 0)
    }
}

/// What to do about one stack item: the one upgrade that fixes the most.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ItemSummary {
    /// The stack item's key (the part of a finding key before `/`).
    pub key: String,
    /// The stack item's `name`, else product id or purl.
    pub item: String,
    pub product: String,
    pub product_name: String,
    pub version: String,
    pub exposure: Exposure,
    pub counts: BucketCounts,
    /// The smallest version that fixes every finding with a known fix in this
    /// release cycle; the largest known fix when none is in the cycle.
    pub upgrade_to: Option<String>,
    /// Affected findings that `upgrade_to` fixes.
    pub fixes: usize,
    /// Affected findings (vulnerabilities, not EOL or data findings).
    pub of: usize,
    /// The item's release cycle is past end of life.
    pub eol: bool,
    /// Affected findings with no known fixed version.
    pub unfixed: usize,
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
    /// One recommendation per stack item, in stack order.
    #[serde(default)]
    pub items: Vec<ItemSummary>,
    /// Problems with the run itself (stale data, unknown product ids, …).
    pub notes: Vec<String>,
}

pub const REPORT_FORMAT: u32 = 1;
