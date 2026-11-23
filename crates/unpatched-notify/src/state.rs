//! What was already delivered, and what is new since.
//!
//! The same state model lives in two stores behind [`StateStore`]: a local file
//! (`.unpatched/state.json`, [`FileStore`]) and the hidden JSON block of the
//! pinned status issue ([`crate::github::IssuesStore`]).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use chrono::{DateTime, Datelike, NaiveDate, Utc, Weekday};
use serde::{Deserialize, Serialize};
use unpatched_core::{Bucket, Finding, Report};

use crate::error::{Error, Result};

pub const STATE_VERSION: u32 = 1;

/// What we know about one finding we have seen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SentRecord {
    pub first_seen: DateTime<Utc>,
    /// When a channel was last told about it; `None` while it only waits for a digest.
    #[serde(default)]
    pub last_sent: Option<DateTime<Utc>>,
    /// The bucket at the last run.
    pub bucket: Bucket,
    /// Channels that were told about it in this bucket (`issues`, `telegram`, ...).
    #[serde(default)]
    pub channels: Vec<String>,
    /// The finding's GitHub issue, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue: Option<u64>,
    /// Someone closed the issue but the finding is still there.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub closed_by_human: bool,
}

impl SentRecord {
    pub fn new(first_seen: DateTime<Utc>, bucket: Bucket) -> Self {
        Self {
            first_seen,
            last_sent: None,
            bucket,
            channels: Vec::new(),
            issue: None,
            closed_by_human: false,
        }
    }

    pub fn told(&self, channel: &str) -> bool {
        self.channels.iter().any(|c| c == channel)
    }

    pub fn mark_told(&mut self, channel: &str, now: DateTime<Utc>) {
        if !self.told(channel) {
            self.channels.push(channel.to_owned());
            self.channels.sort();
        }
        self.last_sent = Some(now);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryState {
    pub version: u32,
    #[serde(default)]
    pub last_run: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_digest: Option<NaiveDate>,
    /// Keyed by finding key.
    #[serde(default)]
    pub sent: BTreeMap<String, SentRecord>,
}

impl Default for DeliveryState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            last_run: None,
            last_digest: None,
            sent: BTreeMap::new(),
        }
    }
}

impl DeliveryState {
    pub fn from_json(text: &str) -> Result<Self> {
        let state: Self = serde_json::from_str(text)
            .map_err(|e| Error::State(format!("cannot read the saved state: {e}")))?;
        if state.version > STATE_VERSION {
            return Err(Error::State(format!(
                "the saved state has version {}, this unpatched understands {STATE_VERSION}. Update unpatched.",
                state.version
            )));
        }
        Ok(state)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}

/// The weekday of the digest, or every day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestDay {
    Daily,
    On(Weekday),
}

impl FromStr for DigestDay {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim().to_ascii_lowercase();
        if s == "daily" {
            return Ok(Self::Daily);
        }
        s.parse::<Weekday>().map(Self::On).map_err(|_| {
            Error::Config(format!(
                "digest: {s:?} is not a day. Use monday ... sunday, or daily."
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Escalation {
    pub finding: Finding,
    pub from: Bucket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedReason {
    /// An ignore entry now covers it.
    Ignored,
    /// Fixed (a fixed version is configured), or the advisory is gone.
    FixedOrGone,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedItem {
    pub key: String,
    pub record: SentRecord,
    pub reason: ResolvedReason,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeliveryPlan {
    /// Findings never seen before (any bucket).
    pub new_findings: Vec<Finding>,
    /// Findings whose bucket became more urgent.
    pub escalated: Vec<Escalation>,
    /// In the state, no longer in the report.
    pub resolved: Vec<ResolvedItem>,
    pub digest_due: bool,
}

impl DeliveryPlan {
    /// New or escalated findings that must be delivered at once.
    pub fn immediate(&self) -> Vec<&Finding> {
        self.new_findings
            .iter()
            .chain(self.escalated.iter().map(|e| &e.finding))
            .filter(|f| f.bucket == Bucket::Now)
            .collect()
    }
}

/// Compare the report with the saved state.
///
/// `now` findings go out at once when new or escalated. Everything else waits
/// for the digest. An unknown `digest_day` counts as `monday`; [`crate::deliver`]
/// rejects it before it gets here.
pub fn plan(
    report: &Report,
    state: &DeliveryState,
    now: DateTime<Utc>,
    digest_day: &str,
) -> DeliveryPlan {
    let day = digest_day
        .parse::<DigestDay>()
        .unwrap_or(DigestDay::On(Weekday::Mon));
    let mut plan = DeliveryPlan::default();
    for f in &report.findings {
        match state.sent.get(&f.key) {
            None => plan.new_findings.push(f.clone()),
            Some(rec) if f.bucket < rec.bucket => plan.escalated.push(Escalation {
                finding: f.clone(),
                from: rec.bucket,
            }),
            Some(_) => {}
        }
    }
    for (key, rec) in &state.sent {
        if report.findings.iter().any(|f| &f.key == key) {
            continue;
        }
        let reason = if report.ignored.iter().any(|f| &f.key == key) {
            ResolvedReason::Ignored
        } else {
            ResolvedReason::FixedOrGone
        };
        plan.resolved.push(ResolvedItem {
            key: key.clone(),
            record: rec.clone(),
            reason,
        });
    }
    let today = now.date_naive();
    let on_day = match day {
        DigestDay::Daily => true,
        DigestDay::On(w) => today.weekday() == w,
    };
    let done_today = state.last_digest == Some(today);
    let overdue = state
        .last_digest
        .is_some_and(|d| (today - d).num_days() >= 7);
    plan.digest_due = !done_today && (on_day || overdue);
    plan
}

/// Where the delivery state lives.
pub trait StateStore {
    /// The saved state; an empty one when nothing was saved yet.
    fn load(&self) -> Result<DeliveryState>;
    /// Save the state. `report` is the run it belongs to (the issues-backed
    /// store renders it into the status issue).
    fn save(&self, state: &DeliveryState, report: &Report) -> Result<()>;
    /// True when `save` already updates the status issue.
    fn writes_status_issue(&self) -> bool {
        false
    }
}

/// `.unpatched/state.json` next to `unpatched.yml`.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `<dir>/.unpatched/state.json`.
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self::new(dir.into().join(".unpatched").join("state.json"))
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl StateStore for FileStore {
    fn load(&self) -> Result<DeliveryState> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => DeliveryState::from_json(&text).map_err(|e| {
                Error::State(format!(
                    "{e}. Delete {} to start over.",
                    self.path.display()
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DeliveryState::default()),
            Err(e) => Err(Error::State(format!(
                "cannot read {}: {e}",
                self.path.display()
            ))),
        }
    }

    fn save(&self, state: &DeliveryState, _report: &Report) -> Result<()> {
        let io =
            |e: std::io::Error| Error::State(format!("cannot write {}: {e}", self.path.display()));
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(state)
            .map_err(|e| Error::State(format!("cannot encode the state: {e}")))?;
        std::fs::write(&tmp, text + "\n").map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::fixture::{report, sample_report};

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 6, 0, 0).unwrap()
    }

    fn state_from(r: &Report) -> DeliveryState {
        let mut s = DeliveryState::default();
        for f in &r.findings {
            s.sent
                .insert(f.key.clone(), SentRecord::new(at(2026, 11, 1), f.bucket));
        }
        s
    }

    #[test]
    fn everything_is_new_on_the_first_run() {
        let r = sample_report();
        let p = plan(&r, &DeliveryState::default(), at(2026, 11, 24), "monday");
        assert_eq!(p.new_findings.len(), r.findings.len());
        assert!(p.escalated.is_empty() && p.resolved.is_empty());
        assert_eq!(p.immediate().len(), 1);
        assert!(!p.digest_due, "2026-11-24 is a Tuesday");
    }

    #[test]
    fn known_findings_are_quiet() {
        let r = sample_report();
        let p = plan(&r, &state_from(&r), at(2026, 11, 23), "monday");
        assert!(p.new_findings.is_empty() && p.escalated.is_empty() && p.resolved.is_empty());
        assert!(p.digest_due, "2026-11-23 is a Monday");
    }

    #[test]
    fn escalation_and_resolution() {
        let r = sample_report();
        let mut s = state_from(&r);
        let week = r
            .findings
            .iter()
            .find(|f| f.bucket == Bucket::Week)
            .unwrap();
        s.sent.get_mut(&week.key).unwrap().bucket = Bucket::Fyi;
        let now_f = r.findings.iter().find(|f| f.bucket == Bucket::Now).unwrap();
        s.sent.get_mut(&now_f.key).unwrap().bucket = Bucket::Week;
        s.sent.insert(
            "gone/CVE-1".into(),
            SentRecord::new(at(2026, 11, 1), Bucket::Now),
        );
        let ign = &r.ignored[0];
        s.sent.insert(
            ign.key.clone(),
            SentRecord::new(at(2026, 11, 1), Bucket::Week),
        );
        let p = plan(&r, &s, at(2026, 11, 24), "monday");
        assert_eq!(p.escalated.len(), 2);
        assert_eq!(p.immediate().len(), 1);
        assert_eq!(p.resolved.len(), 2);
        let by_key = |k: &str| p.resolved.iter().find(|x| x.key == k).unwrap().reason;
        assert_eq!(by_key("gone/CVE-1"), ResolvedReason::FixedOrGone);
        assert_eq!(by_key(&ign.key), ResolvedReason::Ignored);
    }

    #[test]
    fn de_escalation_is_not_news() {
        let r = report(vec![]);
        let mut s = DeliveryState::default();
        s.sent.insert(
            "a/CVE-1".into(),
            SentRecord::new(at(2026, 11, 1), Bucket::Fyi),
        );
        let p = plan(&r, &s, at(2026, 11, 24), "monday");
        assert!(p.escalated.is_empty());
    }

    #[test]
    fn digest_days() {
        let r = report(vec![]);
        let mut s = DeliveryState::default();
        assert!(plan(&r, &s, at(2026, 11, 25), "daily").digest_due);
        assert!(plan(&r, &s, at(2026, 11, 25), "Wednesday").digest_due);
        assert!(!plan(&r, &s, at(2026, 11, 25), "thursday").digest_due);
        s.last_digest = Some(at(2026, 11, 25).date_naive());
        assert!(
            !plan(&r, &s, at(2026, 11, 25), "daily").digest_due,
            "once a day"
        );
        s.last_digest = Some(at(2026, 11, 16).date_naive());
        assert!(
            plan(&r, &s, at(2026, 11, 24), "monday").digest_due,
            "a missed digest is caught up"
        );
    }

    #[test]
    fn digest_day_parses() {
        assert_eq!("daily".parse::<DigestDay>().unwrap(), DigestDay::Daily);
        assert_eq!(
            "Sunday".parse::<DigestDay>().unwrap(),
            DigestDay::On(Weekday::Sun)
        );
        assert!("someday".parse::<DigestDay>().is_err());
    }

    #[test]
    fn file_store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        assert_eq!(store.load().unwrap(), DeliveryState::default());
        let r = sample_report();
        let mut s = state_from(&r);
        s.last_run = Some(at(2026, 11, 23));
        s.last_digest = Some(at(2026, 11, 23).date_naive());
        store.save(&s, &r).unwrap();
        assert_eq!(store.load().unwrap(), s);
        std::fs::write(store.path(), "not json").unwrap();
        let err = store.load().unwrap_err().to_string();
        assert!(err.contains("Delete"), "{err}");
    }

    #[test]
    fn newer_state_is_refused() {
        let err = DeliveryState::from_json(r#"{"version": 99}"#).unwrap_err();
        assert!(err.to_string().contains("Update unpatched"));
    }
}
