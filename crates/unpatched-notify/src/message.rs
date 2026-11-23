//! What a chat channel is asked to send, and how it reads in each chat dialect.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, Utc};
use unpatched_core::{Bucket, Finding, Report, Summary};

use crate::render::{
    BUCKETS, bucket_emoji, bucket_label, db_line, escape_discord, escape_slack, escape_telegram,
    heartbeat, subject,
};
use crate::state::DeliveryState;

/// Telegram `sendMessage` text limit.
pub const TELEGRAM_MAX: usize = 4096;
/// Discord webhook `content` limit.
pub const DISCORD_MAX: usize = 2000;
/// Slack: well below the 40,000 limit, so one message stays readable.
pub const SLACK_MAX: usize = 3900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// New or escalated "fix today" findings, sent at once.
    Alert,
    /// The periodic summary of everything open.
    Digest,
    /// Findings that were fixed or went away.
    Resolved,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::Alert => "alert",
            Event::Digest => "digest",
            Event::Resolved => "resolved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Plain,
    /// Slack mrkdwn.
    Slack,
    /// Discord Markdown.
    Discord,
    /// Telegram MarkdownV2.
    Telegram,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub event: Event,
    pub generated_at: DateTime<Utc>,
    pub summary: Summary,
    /// The findings this message is about.
    pub findings: Vec<Finding>,
    /// Keys that were not in the state at the last digest (shown as "new").
    pub new_keys: BTreeSet<String>,
    /// Keys of findings that are gone (for `Event::Resolved`).
    pub resolved: Vec<String>,
    /// Heartbeat and database age, one line each.
    pub footer: Vec<String>,
    pub report_url: Option<String>,
}

impl Message {
    fn base(event: Event, report: &Report, findings: Vec<Finding>) -> Self {
        Self {
            event,
            generated_at: report.generated_at,
            summary: report.summary.clone(),
            findings,
            new_keys: BTreeSet::new(),
            resolved: Vec::new(),
            footer: vec![heartbeat(report), db_line(report)],
            report_url: None,
        }
    }

    /// Findings that must be known right now.
    pub fn alert(report: &Report, findings: Vec<Finding>) -> Self {
        let mut m = Self::base(Event::Alert, report, findings);
        m.new_keys = m.findings.iter().map(|f| f.key.clone()).collect();
        m
    }

    /// Everything that is open; findings not in `since` are marked new.
    pub fn digest(report: &Report, since: Option<&DeliveryState>) -> Self {
        let mut m = Self::base(Event::Digest, report, report.findings.clone());
        if let Some(s) = since {
            m.new_keys = m
                .findings
                .iter()
                .filter(|f| !s.sent.contains_key(&f.key))
                .map(|f| f.key.clone())
                .collect();
        }
        m
    }

    pub fn resolved(report: &Report, keys: Vec<String>) -> Self {
        let mut m = Self::base(Event::Resolved, report, Vec::new());
        m.resolved = keys;
        m
    }

    #[must_use]
    pub fn with_report_url(mut self, url: Option<String>) -> Self {
        self.report_url = url;
        self
    }

    pub fn has_now(&self) -> bool {
        self.event != Event::Resolved && self.findings.iter().any(|f| f.bucket == Bucket::Now)
    }

    /// One line, no formatting: the title of the message.
    pub fn headline(&self) -> String {
        match self.event {
            Event::Alert => {
                let n = self.findings.len();
                format!("unpatched · {n} to fix today")
            }
            Event::Digest => format!("unpatched · week {}", self.generated_at.iso_week().week()),
            Event::Resolved => {
                let n = self.resolved.len();
                format!("unpatched · {n} resolved")
            }
        }
    }

    /// The finding lines: one per stack item and bucket.
    fn lines(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for bucket in BUCKETS {
            let mut groups: BTreeMap<(String, String, String), Vec<&Finding>> = BTreeMap::new();
            for f in self.findings.iter().filter(|f| f.bucket == bucket) {
                groups
                    .entry((f.item.clone(), f.product.clone(), f.version.clone()))
                    .or_default()
                    .push(f);
            }
            for group in groups.values() {
                let head = format!("{} {}", bucket_emoji(bucket), bucket_label(bucket));
                let mut text = format!("{}: {}", subject(group[0]), group_detail(bucket, group));
                if group.iter().any(|f| self.new_keys.contains(&f.key))
                    && self.event == Event::Digest
                {
                    text.push_str(" (new)");
                }
                out.push((head, text));
            }
        }
        for key in &self.resolved {
            out.push(("✅ Resolved".into(), key.clone()));
        }
        out
    }

    /// The message in a chat dialect, cut to `max_len` characters.
    pub fn render(&self, dialect: Dialect, max_len: usize) -> String {
        let lines = self.lines();
        let assemble = |keep: usize| -> String {
            let mut out = String::new();
            out.push_str(&bold(dialect, &self.headline()));
            out.push_str("\n\n");
            for (head, text) in &lines[..keep] {
                out.push_str(&bold(dialect, head));
                out.push_str("  ");
                out.push_str(&escape(dialect, text));
                out.push('\n');
            }
            if keep < lines.len() {
                out.push_str(&escape(
                    dialect,
                    &format!("…and {} more", lines.len() - keep),
                ));
                out.push('\n');
            }
            out.push('\n');
            for l in &self.footer {
                out.push_str(&escape(dialect, l));
                out.push('\n');
            }
            if let Some(url) = &self.report_url {
                out.push_str(&escape(dialect, url));
                out.push('\n');
            }
            out.trim_end().to_owned()
        };
        for keep in (0..=lines.len()).rev() {
            let text = assemble(keep);
            if text.chars().count() <= max_len {
                return text;
            }
        }
        // Not even the header and footer fit: keep the start of it.
        let text = assemble(0);
        let cut: String = text.chars().take(max_len.saturating_sub(1)).collect();
        // Do not leave a dangling escape character at the end.
        format!("{}…", cut.trim_end_matches('\\'))
    }
}

fn bold(d: Dialect, s: &str) -> String {
    match d {
        Dialect::Plain => s.to_owned(),
        Dialect::Slack => format!("*{}*", escape_slack(s)),
        Dialect::Discord => format!("**{}**", escape_discord(s)),
        Dialect::Telegram => format!("*{}*", escape_telegram(s)),
    }
}

fn escape(d: Dialect, s: &str) -> String {
    match d {
        Dialect::Plain => s.to_owned(),
        Dialect::Slack => escape_slack(s),
        Dialect::Discord => escape_discord(s),
        Dialect::Telegram => escape_telegram(s),
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The part of a digest line after the item name.
fn group_detail(bucket: Bucket, group: &[&Finding]) -> String {
    let n = group.len();
    let first = group[0];
    let base = match bucket {
        Bucket::Eol => "past end of life. Plan an upgrade.".to_owned(),
        Bucket::Unknown => format!(
            "{} with no version data yet",
            plural(n, "advisory", "advisories")
        ),
        Bucket::Now | Bucket::Week | Bucket::Fyi => {
            let what = if n == 1 {
                let id = first.vuln.clone().unwrap_or_else(|| first.title.clone());
                if first.signals.kev.is_some() {
                    format!("{id}, exploited")
                } else {
                    id
                }
            } else {
                plural(n, "advisory", "advisories")
            };
            match best_fix(group) {
                Some(v) => format!("{what}, upgrade to {v}+"),
                None => format!("{what}, no fixed version known yet"),
            }
        }
    };
    format!("{base}{}", why_hint(bucket, first))
}

/// A short tail for lines where the reason is not obvious.
fn why_hint(bucket: Bucket, f: &Finding) -> String {
    if let (Bucket::Week, Some(e)) = (bucket, f.signals.epss.as_ref()) {
        return format!(" (EPSS {:.0}%)", e.score * 100.0);
    }
    String::new()
}

/// The highest `fixed_in` of the group, comparing dotted numbers loosely.
fn best_fix(group: &[&Finding]) -> Option<String> {
    group
        .iter()
        .filter_map(|f| f.fixed_in.as_deref())
        .max_by(|a, b| loose_cmp(a, b))
        .map(str::to_owned)
}

fn loose_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    parts(a).cmp(&parts(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{fortios, report, sample_report};

    #[test]
    fn digest_dialects() {
        let r = sample_report();
        let m = Message::digest(&r, None);
        insta::assert_snapshot!("digest_plain", m.render(Dialect::Plain, usize::MAX));
        insta::assert_snapshot!("digest_slack", m.render(Dialect::Slack, SLACK_MAX));
        insta::assert_snapshot!("digest_discord", m.render(Dialect::Discord, DISCORD_MAX));
        insta::assert_snapshot!("digest_telegram", m.render(Dialect::Telegram, TELEGRAM_MAX));
    }

    #[test]
    fn alert_message() {
        let r = sample_report();
        let m = Message::alert(&r, vec![fortios()])
            .with_report_url(Some("https://example.com/r".into()));
        assert!(m.has_now());
        insta::assert_snapshot!("alert_plain", m.render(Dialect::Plain, usize::MAX));
    }

    #[test]
    fn resolved_message() {
        let r = report(vec![]);
        let m = Message::resolved(&r, vec!["office-firewall/CVE-2024-21762".into()]);
        assert!(!m.has_now());
        let t = m.render(Dialect::Plain, usize::MAX);
        assert!(t.contains("1 resolved") && t.contains("✅ Resolved"));
    }

    #[test]
    fn long_digests_are_cut() {
        let mut findings = Vec::new();
        for i in 0..300 {
            let mut f = fortios();
            f.key = format!("host{i}/CVE-2024-21762");
            f.item = format!("host{i}");
            findings.push(f);
        }
        let r = report(findings);
        let m = Message::digest(&r, None);
        for (d, max) in [
            (Dialect::Telegram, TELEGRAM_MAX),
            (Dialect::Discord, DISCORD_MAX),
        ] {
            let t = m.render(d, max);
            assert!(t.chars().count() <= max, "{d:?}: {}", t.chars().count());
            assert!(t.contains("more"), "{d:?}");
            assert!(t.contains("🟢"), "footer kept");
        }
    }

    #[test]
    fn tiny_limit_still_works() {
        let m = Message::digest(&sample_report(), None);
        let t = m.render(Dialect::Telegram, 20);
        assert!(t.chars().count() <= 20);
    }

    #[test]
    fn best_fix_is_numeric() {
        let mut a = fortios();
        a.fixed_in = Some("29.0.8".into());
        let mut b = fortios();
        b.fixed_in = Some("29.0.10".into());
        assert_eq!(best_fix(&[&a, &b]).as_deref(), Some("29.0.10"));
    }
}
