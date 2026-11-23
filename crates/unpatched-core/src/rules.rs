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
    let rule = |id: RuleId| {
        let (title, explanation) = text(id);
        RuleInfo {
            id,
            title,
            explanation,
        }
    };
    ALL.iter().copied().map(rule).collect()
}

const ALL: [RuleId; 15] = [
    RuleId::Kev,
    RuleId::SsvcActive,
    RuleId::ExploitExposed,
    RuleId::Epss,
    RuleId::Cvss,
    RuleId::Exposed,
    RuleId::Affected,
    RuleId::Eol,
    RuleId::UnknownNoRanges,
    RuleId::UnknownVersion,
    RuleId::Conflict,
    RuleId::UnverifiedProduct,
    RuleId::Ignored,
    RuleId::IgnoreExpired,
    RuleId::StaleData,
];

/// Title and explanation for one rule. The `match` has no wildcard, so a new
/// rule id does not compile until it is explained here.
fn text(id: RuleId) -> (&'static str, &'static str) {
    match id {
        RuleId::Kev => (
            "Known to be exploited",
            "CISA lists this vulnerability in its Known Exploited Vulnerabilities catalog, so attackers are using it now. Fix it today.",
        ),
        RuleId::SsvcActive => (
            "Exploitation is active",
            "CISA's SSVC assessment says exploitation of this vulnerability is active. Treat it like a known exploited vulnerability and fix it today.",
        ),
        RuleId::ExploitExposed => (
            "Public exploit and reachable from the internet",
            "A public exploit exists (Exploit-DB or Metasploit) and this item is marked as internet-facing. Anyone can try it against you, so fix it today.",
        ),
        RuleId::Epss => (
            "Likely to be exploited soon",
            "The EPSS score is at or above your threshold (default 0.05), which means exploitation in the next 30 days is more likely than for most vulnerabilities. Fix it this week.",
        ),
        RuleId::Cvss => (
            "Critical severity",
            "The CVSS base score is at or above your threshold (default 9.0). Severity alone does not mean it is being exploited, but it is serious enough to fix this week.",
        ),
        RuleId::Exposed => (
            "Affected and reachable from the internet",
            "This version is affected and the item is marked as internet-facing, so attackers can reach it. Fix it this week.",
        ),
        RuleId::Affected => (
            "Affected, no sign of exploitation",
            "This version is affected, but nothing says it is exploited, it is not internet-facing and the scores are below your thresholds. Fix it with your normal updates.",
        ),
        RuleId::Eol => (
            "End of life",
            "This release cycle no longer gets security fixes (endoflife.date). New vulnerabilities will not be patched, so plan an upgrade to a supported cycle.",
        ),
        RuleId::UnknownNoRanges => (
            "No usable version data yet",
            "No source says which versions are affected (new CVEs often wait for NVD analysis). It could matter, so check the advisory yourself. The finding goes away when data arrives.",
        ),
        RuleId::UnknownVersion => (
            "Version cannot be compared",
            "Either your configured version or a version in the data does not parse under this product's version scheme. unpatched does not guess, so check the version in unpatched.yml.",
        ),
        RuleId::Conflict => (
            "Sources disagree",
            "At least one source says this version is affected and another says it is not. When in doubt unpatched reports it. Read the evidence to see which source to trust.",
        ),
        RuleId::UnverifiedProduct => (
            "Product not found in the data",
            "The catalog's names for this product match no record in the database, so an empty result would not mean you are safe. Check the catalog entry or report it.",
        ),
        RuleId::Ignored => (
            "Ignored on purpose",
            "An ignore entry in unpatched.yml accepts this risk until its date. The finding is listed separately and comes back when the entry expires.",
        ),
        RuleId::IgnoreExpired => (
            "Ignore entry has expired",
            "An ignore entry matched this finding but its date has passed, so the finding is back. Fix the issue or write a new entry with a new date.",
        ),
        RuleId::StaleData => (
            "Data is out of date",
            "The vulnerability database is older than your warning threshold (default 3 days). Results may miss new vulnerabilities, so check that the daily database build is running.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_is_explained_once() {
        let rules = all_rules();
        assert_eq!(rules.len(), ALL.len());
        let mut codes: Vec<_> = rules.iter().map(|r| r.id.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), rules.len());
        for r in &rules {
            assert!(!r.title.is_empty());
            let sentences = r.explanation.matches(". ").count() + 1;
            assert!((1..=3).contains(&sentences), "{}: {sentences}", r.id.code());
        }
    }

    #[test]
    fn codes_match_serde_names() {
        for r in all_rules() {
            let json = serde_json::to_string(&r.id).unwrap();
            assert_eq!(json, format!("\"{}\"", r.id.code()));
        }
    }
}
