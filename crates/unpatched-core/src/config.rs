//! `unpatched.yml`: the stack, ignores, thresholds and notification channels.
//! The JSON Schema in `schema/unpatched.schema.json` is generated from these types.

use chrono::NaiveDate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// File format version. Only `1` exists.
    pub version: u32,
    /// The software you run, one entry per instance.
    pub stack: Vec<StackItem>,
    /// Risks you accept on purpose, each with a reason and an end date.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<Ignore>,
    /// When a finding gets more urgent.
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default)]
    pub notify: Notify,
    /// Day of the weekly digest (`monday` … `sunday`), or `daily`.
    #[serde(default = "default_digest")]
    pub digest: String,
}

fn default_digest() -> String {
    "monday".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Exposure {
    /// Reachable from the internet (VPN portals, web apps, mail servers).
    Internet,
    /// Only reachable from inside your network.
    #[default]
    Internal,
}

/// One thing you run. Give either `product` (a catalog id) or `purl` (a package).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackItem {
    /// Catalog product id (`unpatched catalog list`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Package URL with version, e.g. `pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// Required with `product`; taken from the purl otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether the item is reachable from the internet. It can move a finding up a bucket.
    #[serde(default)]
    pub exposure: Exposure,
    /// Your label, e.g. "Office firewall". Tells instances apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Accept a risk on purpose. `until` is required: nothing is ignored forever.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ignore {
    /// The CVE (or advisory) id to ignore.
    pub cve: String,
    /// Only for this product id (or stack item `name`); all items when empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Why you accept the risk. Shown in the report.
    pub reason: String,
    /// The last day the entry applies. After it the finding comes back.
    pub until: NaiveDate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    /// EPSS score at or above which an affected finding is at least `week`.
    #[serde(default = "default_epss")]
    pub epss_week: f64,
    /// CVSS base score at or above which an affected finding is at least `week`.
    #[serde(default = "default_cvss")]
    pub cvss_week: f64,
    /// CVSS base score at or above which an affected, internet-facing finding is at least `week`.
    #[serde(default = "default_cvss_exposed")]
    pub cvss_week_exposed: f64,
    /// Days after which the database counts as stale (warning).
    #[serde(default = "default_stale_warn")]
    pub stale_warn_days: u32,
    /// Days after which a run fails because the data is too old.
    #[serde(default = "default_stale_fail")]
    pub stale_fail_days: u32,
}

fn default_epss() -> f64 {
    0.05
}
fn default_cvss() -> f64 {
    9.0
}
fn default_cvss_exposed() -> f64 {
    7.0
}
fn default_stale_warn() -> u32 {
    3
}
fn default_stale_fail() -> u32 {
    7
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            epss_week: default_epss(),
            cvss_week: default_cvss(),
            cvss_week_exposed: default_cvss_exposed(),
            stale_warn_days: default_stale_warn(),
            stale_fail_days: default_stale_fail(),
        }
    }
}

/// Channels. Secrets (tokens, webhook URLs) never go here: they come from
/// environment variables named in the docs (`UNPATCHED_TELEGRAM_TOKEN`, …).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    /// GitHub Issues in the repository the Action runs in.
    #[serde(default = "yes")]
    pub issues: bool,
    /// Send messages to a Telegram chat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram: Option<Telegram>,
    /// Slack incoming webhook (URL in `UNPATCHED_SLACK_WEBHOOK`).
    #[serde(default)]
    pub slack: bool,
    /// Discord webhook (URL in `UNPATCHED_DISCORD_WEBHOOK`).
    #[serde(default)]
    pub discord: bool,
    /// Send messages to an ntfy topic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntfy: Option<Ntfy>,
    /// Generic JSON webhook (URL in `UNPATCHED_WEBHOOK_URL`).
    #[serde(default)]
    pub webhook: bool,
}

fn yes() -> bool {
    true
}

impl Default for Notify {
    fn default() -> Self {
        Self {
            issues: true,
            telegram: None,
            slack: false,
            discord: false,
            ntfy: None,
            webhook: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Telegram {
    /// Chat id. The bot token comes from `UNPATCHED_TELEGRAM_TOKEN`.
    pub chat: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ntfy {
    /// The ntfy topic to publish to.
    pub topic: String,
    /// The ntfy server.
    #[serde(default = "default_ntfy_server")]
    pub server: String,
}

fn default_ntfy_server() -> String {
    "https://ntfy.sh".into()
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unpatched.yml is not valid YAML for this format: {0}")]
    Parse(#[from] serde_norway::Error),
    #[error("unpatched.yml: {0}")]
    Invalid(String),
}

impl Config {
    /// Parse and check `unpatched.yml` text (structure only; catalog ids are
    /// checked by the caller, which has the catalog).
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = serde_norway::from_str(text)?;
        cfg.check()?;
        Ok(cfg)
    }

    fn check(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Invalid(format!(
                "version {} is not supported; use 1",
                self.version
            )));
        }
        for (i, item) in self.stack.iter().enumerate() {
            let at = format!("stack[{i}]");
            match (&item.product, &item.purl) {
                (Some(_), Some(_)) => {
                    return Err(ConfigError::Invalid(format!(
                        "{at}: give product or purl, not both"
                    )));
                }
                (None, None) => {
                    return Err(ConfigError::Invalid(format!("{at}: needs product or purl")));
                }
                (Some(_), None) if item.version.as_deref().is_none_or(str::is_empty) => {
                    return Err(ConfigError::Invalid(format!(
                        "{at}: product needs a version"
                    )));
                }
                (None, Some(p)) if !p.starts_with("pkg:") || !p.contains('@') => {
                    return Err(ConfigError::Invalid(format!(
                        "{at}: purl must look like pkg:type/name@version"
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
