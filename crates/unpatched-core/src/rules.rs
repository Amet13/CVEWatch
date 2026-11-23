//! Every rule has a stable id shown in reports and explained by `unpatched explain`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum RuleId {
    /// In CISA KEV.
    #[serde(rename = "UNP-KEV")]
    Kev,
    /// CISA SSVC says exploitation is active.
    #[serde(rename = "UNP-SSVC-ACTIVE")]
    SsvcActive,
    /// A public exploit exists and the item is internet-facing.
    #[serde(rename = "UNP-EXPLOIT-EXPOSED")]
    ExploitExposed,
    /// EPSS at or above the threshold.
    #[serde(rename = "UNP-EPSS")]
    Epss,
    /// CVSS at or above the threshold.
    #[serde(rename = "UNP-CVSS")]
    Cvss,
    /// Affected and internet-facing.
    #[serde(rename = "UNP-EXPOSED")]
    Exposed,
    /// Affected, no other signal.
    #[serde(rename = "UNP-AFFECTED")]
    Affected,
    /// The release cycle is past its end of life.
    #[serde(rename = "UNP-EOL")]
    Eol,
    /// No source has usable version data.
    #[serde(rename = "UNP-UNKNOWN-NO-RANGES")]
    UnknownNoRanges,
    /// The configured version does not parse under the product's scheme.
    #[serde(rename = "UNP-UNKNOWN-VERSION")]
    UnknownVersion,
    /// Sources disagree.
    #[serde(rename = "UNP-CONFLICT")]
    Conflict,
    /// The product's catalog keys match nothing in the database.
    #[serde(rename = "UNP-UNVERIFIED-PRODUCT")]
    UnverifiedProduct,
    /// An ignore entry matched.
    #[serde(rename = "UNP-IGNORED")]
    Ignored,
    /// An ignore entry has expired.
    #[serde(rename = "UNP-IGNORE-EXPIRED")]
    IgnoreExpired,
    /// The database is older than the warning threshold.
    #[serde(rename = "UNP-STALE-DATA")]
    StaleData,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct RuleInfo {
    pub id: RuleId,
    pub title: &'static str,
    pub explanation: &'static str,
}

impl RuleId {
    pub fn code(self) -> &'static str {
        match self {
            RuleId::Kev => "UNP-KEV",
            RuleId::SsvcActive => "UNP-SSVC-ACTIVE",
            RuleId::ExploitExposed => "UNP-EXPLOIT-EXPOSED",
            RuleId::Epss => "UNP-EPSS",
            RuleId::Cvss => "UNP-CVSS",
            RuleId::Exposed => "UNP-EXPOSED",
            RuleId::Affected => "UNP-AFFECTED",
            RuleId::Eol => "UNP-EOL",
            RuleId::UnknownNoRanges => "UNP-UNKNOWN-NO-RANGES",
            RuleId::UnknownVersion => "UNP-UNKNOWN-VERSION",
            RuleId::Conflict => "UNP-CONFLICT",
            RuleId::UnverifiedProduct => "UNP-UNVERIFIED-PRODUCT",
            RuleId::Ignored => "UNP-IGNORED",
            RuleId::IgnoreExpired => "UNP-IGNORE-EXPIRED",
            RuleId::StaleData => "UNP-STALE-DATA",
        }
    }
}

/// All rules with their explanations (for `explain` and the docs page).
pub fn all_rules() -> Vec<RuleInfo> {
    unimplemented!("rules::all_rules")
}
