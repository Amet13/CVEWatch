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
    /// The text is not YAML at all.
    #[error("unpatched.yml is not valid YAML: {0}")]
    Parse(serde_norway::Error),
    /// The text is YAML, but not the `unpatched.yml` format.
    #[error("unpatched.yml does not match the unpatched.yml format: {0}")]
    Format(serde_norway::Error),
    #[error("unpatched.yml: {0}")]
    Invalid(String),
}

impl ConfigError {
    /// Line and column (1-based) of a YAML problem, when there is one.
    pub fn location(&self) -> Option<(usize, usize)> {
        match self {
            Self::Parse(e) | Self::Format(e) => e.location().map(|l| (l.line(), l.column())),
            Self::Invalid(_) => None,
        }
    }

    /// Byte offset of a YAML problem, when there is one.
    pub fn index(&self) -> Option<usize> {
        match self {
            Self::Parse(e) | Self::Format(e) => e.location().map(|l| l.index()),
            Self::Invalid(_) => None,
        }
    }

    /// The message with the parser's detail cut short: a wrong file (a log, a
    /// binary) must not flood the terminal or leak into a message.
    pub fn short_message(&self) -> String {
        let mut m = match self {
            Self::Parse(e) => format!(
                "unpatched.yml is not valid YAML: {}",
                short_detail(&e.to_string())
            ),
            Self::Format(e) => format!(
                "unpatched.yml does not match the unpatched.yml format: {}",
                short_detail(&e.to_string())
            ),
            Self::Invalid(m) => format!("unpatched.yml: {}", short_detail(m)),
        };
        if let Some(h) = self.hint() {
            m.push(' ');
            m.push_str(&h);
        }
        m
    }

    /// "Did you mean `exposure`?" for an unknown field close to a known one.
    /// Only names the format knows are ever returned, never file content.
    pub fn hint(&self) -> Option<String> {
        let Self::Format(e) = self else { return None };
        let msg = e.to_string();
        let rest = msg.split_once("unknown field `")?.1;
        let (name, rest) = rest.split_once('`')?;
        let expected = rest.split_once("expected ")?.1;
        let expected = expected.split(" at line ").next().unwrap_or(expected);
        let known: Vec<&str> = expected
            .split('`')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, s)| s)
            .collect();
        let name_lc = name.to_lowercase();
        let (d, best) = known
            .iter()
            .map(|k| (edit_distance(&name_lc, k), *k))
            .min_by_key(|(d, _)| *d)?;
        (d <= 2.max(name.len() / 3)).then(|| format!("Did you mean `{best}`?"))
    }
}

/// Edit distance between two strings (characters).
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push(
                (prev[j] + usize::from(ca != cb))
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Longest part of a YAML error message shown as it is.
const MAX_DETAIL: usize = 200;

/// A serde message cut to [`MAX_DETAIL`] characters, so a wrong file cannot flood the terminal.
pub fn short_detail(text: &str) -> String {
    let one_line = text.replace('\n', " ");
    if one_line.chars().count() <= MAX_DETAIL {
        return one_line;
    }
    let cut: String = one_line.chars().take(MAX_DETAIL).collect();
    format!("{cut}…")
}

/// The example shown when a purl is wrong.
pub const PURL_EXAMPLE: &str = "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm";

impl Config {
    /// Parse and check `unpatched.yml` text (structure only; catalog ids are
    /// checked by the caller, which has the catalog).
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = match serde_norway::from_str(text) {
            Ok(c) => c,
            Err(e) => {
                return Err(
                    if serde_norway::from_str::<serde_norway::Value>(text).is_ok() {
                        ConfigError::Format(e)
                    } else {
                        ConfigError::Parse(e)
                    },
                );
            }
        };
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
                    return Err(ConfigError::Invalid(format!(
                        "{at}: add `product:` (a catalog id) or `purl:` (a package URL)"
                    )));
                }
                (Some(p), None) if item.version.as_deref().is_none_or(str::is_empty) => {
                    return Err(ConfigError::Invalid(format!(
                        "{at}: add version: \"…\" (the version you run). See `unpatched catalog show {p}` for the format"
                    )));
                }
                (None, Some(p)) if !p.starts_with("pkg:") || !p.contains('@') => {
                    return Err(ConfigError::Invalid(format!(
                        "{at}: {p:?} is not a package URL. Write it like {PURL_EXAMPLE}"
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
