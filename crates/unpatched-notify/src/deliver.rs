//! The orchestration the CLI calls: plan, issues, chat, save state.
//!
//! A channel that fails does not stop the others. The failures are collected
//! and returned at the end.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use unpatched_core::{Bucket, Config, Finding, Report};

use crate::channels::Channel;
use crate::error::{Error, Result};
use crate::github::{GitHub, IssueSync};
use crate::message::{Event, Message};
use crate::render::{issue_bucket, issue_count};
use crate::state::{
    self, DeliveryPlan, DeliveryState, DigestDay, ItemRecord, SentRecord, StateStore,
};

#[derive(Debug, Clone)]
pub struct DeliverOptions {
    /// The time of this run; also decides the digest day.
    pub now: DateTime<Utc>,
    /// Send nothing, write nothing; only record what would happen.
    pub dry_run: bool,
    /// Set to use GitHub issues (the CLI sets it in GitHub Actions or with
    /// `--github`). Ignored when `notify.issues` is off.
    pub github: Option<GitHub>,
    /// Send the digest even when it is not due.
    pub force_digest: bool,
    /// A link to the run or report, added to messages.
    pub report_url: Option<String>,
}

impl Default for DeliverOptions {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            dry_run: false,
            github: None,
            force_digest: false,
            report_url: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SentMessage {
    pub channel: String,
    pub event: Event,
    /// How many findings (or resolved keys) the message carried.
    pub items: usize,
}

#[derive(Debug)]
pub struct DeliveryOutcome {
    pub plan: DeliveryPlan,
    /// `None` when issues are off.
    pub issues: Option<IssueSync>,
    pub status_issue: Option<u64>,
    pub sent: Vec<SentMessage>,
    /// What a dry run would have done.
    pub planned: Vec<String>,
    /// One line per failure.
    pub errors: Vec<String>,
    /// The state after this run (saved unless `dry_run`).
    pub state: DeliveryState,
}

/// Deliver, and fail with [`Error::Delivery`] when anything failed. The
/// delivered parts and the saved state stay; use [`deliver_collect`] to keep
/// the outcome on failure.
pub fn deliver(
    report: &Report,
    config: &Config,
    store: &dyn StateStore,
    channels: &[Box<dyn Channel>],
    opts: &DeliverOptions,
) -> Result<DeliveryOutcome> {
    let outcome = deliver_collect(report, config, store, channels, opts)?;
    if outcome.errors.is_empty() {
        Ok(outcome)
    } else {
        Err(Error::Delivery {
            errors: outcome.errors,
        })
    }
}

/// Like [`deliver`], but problems with single channels or issues end up in
/// [`DeliveryOutcome::errors`]. Only a state that cannot be read is an error.
pub fn deliver_collect(
    report: &Report,
    config: &Config,
    store: &dyn StateStore,
    channels: &[Box<dyn Channel>],
    opts: &DeliverOptions,
) -> Result<DeliveryOutcome> {
    config.digest.parse::<DigestDay>()?;
    let old = store.load()?;
    let mut plan = state::plan(report, &old, opts.now, &config.digest);
    plan.digest_due |= opts.force_digest;
    let mut errors: Vec<String> = Vec::new();
    let mut planned: Vec<String> = Vec::new();

    // GitHub issues.
    let gh = opts
        .github
        .as_ref()
        .filter(|_| config.notify.issues)
        .map(|g| g.clone().with_dry_run(opts.dry_run));
    let mut issues = None;
    if let Some(gh) = &gh {
        match gh.ensure_labels().and_then(|()| gh.sync_issues(report)) {
            Ok(sync) => {
                errors.extend(sync.errors.iter().map(|e| format!("github: {e}")));
                issues = Some(sync);
            }
            Err(e) => errors.push(format!("github: {e}")),
        }
    }

    // Chat.
    let mut told: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut sent = Vec::new();
    let mut digest_sent = false;
    for ch in channels {
        let name = ch.name().to_owned();
        let mut messages: Vec<Message> = Vec::new();

        // New or escalated "fix today" items, and ones this channel missed
        // (it failed last time, or it was added later).
        let immediate: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.bucket == Bucket::Now)
            .filter(|f| {
                old.sent
                    .get(&f.key)
                    .is_none_or(|r| r.bucket != Bucket::Now || !r.told(&name))
            })
            .cloned()
            .collect();
        if !immediate.is_empty() {
            messages.push(Message::alert(report, immediate));
        }
        let resolved: Vec<String> = plan
            .resolved
            .iter()
            .filter(|r| r.record.told(&name))
            .map(|r| r.key.clone())
            .collect();
        if !resolved.is_empty() {
            messages.push(Message::resolved(report, resolved));
        }
        if plan.digest_due {
            messages.push(Message::digest(report, Some(&old)));
        }

        for msg in messages {
            let msg = msg.with_report_url(opts.report_url.clone());
            let items = msg.findings.len().max(msg.resolved.len());
            let event = msg.event;
            if opts.dry_run {
                planned.push(format!(
                    "send {} to {name} ({items} item(s))",
                    event.as_str()
                ));
            } else if let Err(e) = ch.send(&msg) {
                errors.push(format!("{name}: {e}"));
                continue;
            }
            sent.push(SentMessage {
                channel: name.clone(),
                event,
                items,
            });
            match event {
                Event::Alert => {
                    told.entry(name.clone())
                        .or_default()
                        .extend(msg.findings.iter().map(|f| f.key.clone()));
                }
                Event::Digest => digest_sent = true,
                Event::Resolved => {}
            }
        }
    }

    // The state after this run.
    let mut next = old.clone();
    for r in &plan.resolved {
        next.sent.remove(&r.key);
    }
    for f in &report.findings {
        let rec = next
            .sent
            .entry(f.key.clone())
            .or_insert_with(|| SentRecord::new(opts.now, f.bucket));
        if rec.bucket != f.bucket {
            rec.bucket = f.bucket;
            rec.channels.clear();
        }
        for (channel, keys) in &told {
            if keys.contains(&f.key) {
                rec.mark_told(channel, opts.now);
            }
        }
    }
    // Issues are per stack item.
    let numbers = issues
        .as_ref()
        .map(IssueSync::issue_numbers)
        .unwrap_or_default();
    let human_closed: BTreeSet<&str> = issues
        .iter()
        .flat_map(|s| s.closed_but_affected.iter().map(|(k, _)| k.as_str()))
        .collect();
    let with_issue: BTreeSet<&str> = report
        .items
        .iter()
        .filter(|i| issue_count(i) > 0)
        .map(|i| i.key.as_str())
        .collect();
    next.items.retain(|k, _| with_issue.contains(k.as_str()));
    for i in report.items.iter().filter(|i| issue_count(i) > 0) {
        let bucket = issue_bucket(i).unwrap_or(Bucket::Unknown);
        let rec = next
            .items
            .entry(i.key.clone())
            .or_insert_with(|| ItemRecord::new(opts.now, bucket));
        rec.bucket = bucket;
        if let Some(n) = numbers.get(&i.key).copied().filter(|n| *n > 0) {
            rec.issue = Some(n);
        }
        rec.closed_by_human = human_closed.contains(i.key.as_str());
    }
    next.last_run = Some(opts.now);
    if plan.digest_due && (channels.is_empty() || digest_sent) {
        next.last_digest = Some(opts.now.date_naive());
    }

    // Status issue and state.
    let mut status_issue = None;
    if let Some(gh) = gh
        .as_ref()
        .filter(|_| opts.dry_run || !store.writes_status_issue())
    {
        match gh.update_status(report, &next) {
            Ok(n) => status_issue = Some(n),
            Err(e) => errors.push(format!("github: {e}")),
        }
    }
    if opts.dry_run {
        planned.push("save the delivery state".into());
    } else if let Err(e) = store.save(&next, report) {
        errors.push(e.to_string());
    }
    if let Some(gh) = &gh {
        let mut github_plan = gh.planned_actions();
        github_plan.append(&mut planned);
        planned = github_plan;
    }

    Ok(DeliveryOutcome {
        plan,
        issues,
        status_issue,
        sent,
        planned,
        errors,
        state: next,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use chrono::TimeZone;

    use super::*;
    use crate::fixture::{fortios, report, sample_report};
    use crate::state::FileStore;
    use crate::testutil::TestServer;

    #[derive(Debug)]
    struct Mock {
        name: &'static str,
        fail: Arc<Mutex<bool>>,
        got: Arc<Mutex<Vec<(Event, usize)>>>,
    }

    impl Channel for Mock {
        fn name(&self) -> &str {
            self.name
        }
        fn send(&self, msg: &Message) -> Result<()> {
            if *self.fail.lock().unwrap() {
                return Err(Error::Http {
                    service: self.name.into(),
                    message: "down".into(),
                });
            }
            self.got
                .lock()
                .unwrap()
                .push((msg.event, msg.findings.len().max(msg.resolved.len())));
            Ok(())
        }
    }

    type Got = Arc<Mutex<Vec<(Event, usize)>>>;

    fn mock(name: &'static str) -> (Box<dyn Channel>, Got, Arc<Mutex<bool>>) {
        let got: Got = Arc::default();
        let fail = Arc::new(Mutex::new(false));
        let ch = Mock {
            name,
            fail: Arc::clone(&fail),
            got: Arc::clone(&got),
        };
        (Box::new(ch), got, fail)
    }

    fn config() -> Config {
        Config::from_yaml("version: 1\nstack:\n  - product: nextcloud\n    version: '1'\n").unwrap()
    }

    fn at(d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, d, 6, 17, 0).unwrap()
    }

    fn opts(d: u32) -> DeliverOptions {
        DeliverOptions {
            now: at(d),
            ..DeliverOptions::default()
        }
    }

    #[test]
    fn first_run_alerts_and_digests_then_goes_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let (ch, got, _) = mock("telegram");
        let chans = vec![ch];
        let r = sample_report();
        // 2026-11-23 is a Monday.
        let out = deliver(&r, &config(), &store, &chans, &opts(23)).unwrap();
        assert_eq!(
            *got.lock().unwrap(),
            vec![(Event::Alert, 1), (Event::Digest, 6)]
        );
        assert_eq!(out.sent.len(), 2);
        let saved = store.load().unwrap();
        assert_eq!(saved.sent.len(), 6);
        assert_eq!(saved.last_digest, Some(at(23).date_naive()));
        assert!(saved.sent[&fortios().key].told("telegram"));
        assert!(!saved.sent["redis/CVE-2025-1111"].told("telegram"));

        got.lock().unwrap().clear();
        let out = deliver(&r, &config(), &store, &chans, &opts(23)).unwrap();
        assert!(got.lock().unwrap().is_empty(), "nothing new, digest done");
        assert!(out.sent.is_empty());
        assert_eq!(out.plan.new_findings.len(), 0);

        // Tuesday: still quiet. Next Monday: the digest again, no alert.
        deliver(&r, &config(), &store, &chans, &opts(24)).unwrap();
        assert!(got.lock().unwrap().is_empty());
        deliver(&r, &config(), &store, &chans, &opts(30)).unwrap();
        assert_eq!(*got.lock().unwrap(), vec![(Event::Digest, 6)]);
    }

    #[test]
    fn only_now_findings_are_immediate() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let (ch, got, _) = mock("slack");
        let chans = vec![ch];
        let quiet = report(vec![]);
        deliver(&quiet, &config(), &store, &chans, &opts(24)).unwrap();
        assert!(got.lock().unwrap().is_empty());
        // A new week finding waits; a new now finding goes out.
        let r = report(vec![
            fortios(),
            crate::fixture::nextcloud("CVE-2026-1", "29.0.8"),
        ]);
        deliver(&r, &config(), &store, &chans, &opts(25)).unwrap();
        assert_eq!(*got.lock().unwrap(), vec![(Event::Alert, 1)]);
    }

    #[test]
    fn escalation_is_sent_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let (ch, got, _) = mock("slack");
        let chans = vec![ch];
        let mut f = fortios();
        f.bucket = Bucket::Week;
        deliver(
            &report(vec![f.clone()]),
            &config(),
            &store,
            &chans,
            &opts(24),
        )
        .unwrap();
        assert!(got.lock().unwrap().is_empty());
        f.bucket = Bucket::Now;
        let out = deliver(
            &report(vec![f.clone()]),
            &config(),
            &store,
            &chans,
            &opts(25),
        )
        .unwrap();
        assert_eq!(out.plan.escalated.len(), 1);
        assert_eq!(*got.lock().unwrap(), vec![(Event::Alert, 1)]);
        deliver(&report(vec![f]), &config(), &store, &chans, &opts(26)).unwrap();
        assert_eq!(got.lock().unwrap().len(), 1);
    }

    #[test]
    fn resolved_is_reported_once_to_channels_that_were_told() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let (a, got_a, _) = mock("telegram");
        let (b, got_b, _) = mock("slack");
        let chans = vec![a, b];
        deliver(
            &report(vec![fortios()]),
            &config(),
            &store,
            &chans,
            &opts(24),
        )
        .unwrap();
        got_a.lock().unwrap().clear();
        got_b.lock().unwrap().clear();
        let gone = report(vec![]);
        let out = deliver(&gone, &config(), &store, &chans, &opts(25)).unwrap();
        assert_eq!(out.plan.resolved.len(), 1);
        assert_eq!(*got_a.lock().unwrap(), vec![(Event::Resolved, 1)]);
        assert_eq!(*got_b.lock().unwrap(), vec![(Event::Resolved, 1)]);
        assert!(store.load().unwrap().sent.is_empty());
        deliver(&gone, &config(), &store, &chans, &opts(26)).unwrap();
        assert_eq!(got_a.lock().unwrap().len(), 1, "reported once");
    }

    #[test]
    fn one_failing_channel_does_not_stop_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let (bad, got_bad, fail) = mock("telegram");
        let (good, got_good, _) = mock("slack");
        *fail.lock().unwrap() = true;
        let chans = vec![bad, good];
        let r = report(vec![fortios()]);
        let err = deliver(&r, &config(), &store, &chans, &opts(24)).unwrap_err();
        let Error::Delivery { errors } = err else {
            panic!("wrong error")
        };
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("telegram:"));
        assert_eq!(got_good.lock().unwrap().len(), 1);
        let saved = store.load().unwrap();
        let rec = &saved.sent[&fortios().key];
        assert!(rec.told("slack") && !rec.told("telegram"), "state kept");

        // The channel recovers: only it gets the alert.
        *fail.lock().unwrap() = false;
        deliver(&r, &config(), &store, &chans, &opts(25)).unwrap();
        assert_eq!(got_bad.lock().unwrap().len(), 1);
        assert_eq!(got_good.lock().unwrap().len(), 1);
    }

    #[test]
    fn collect_keeps_the_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let (bad, _, fail) = mock("ntfy");
        *fail.lock().unwrap() = true;
        let out = deliver_collect(
            &report(vec![fortios()]),
            &config(),
            &store,
            &[bad],
            &opts(24),
        )
        .unwrap();
        assert_eq!(out.errors.len(), 1);
        assert!(out.sent.is_empty());
    }

    #[test]
    fn dry_run_touches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let (ch, got, _) = mock("slack");
        let o = DeliverOptions {
            dry_run: true,
            ..opts(23)
        };
        let out = deliver(&sample_report(), &config(), &store, &[ch], &o).unwrap();
        assert!(got.lock().unwrap().is_empty());
        assert!(!store.path().exists());
        assert!(
            out.planned
                .iter()
                .any(|p| p.starts_with("send alert to slack"))
        );
        assert!(out.planned.iter().any(|p| p.contains("save")));
    }

    #[test]
    fn bad_digest_day_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config();
        cfg.digest = "someday".into();
        let err = deliver(
            &report(vec![]),
            &cfg,
            &FileStore::in_dir(dir.path()),
            &[],
            &opts(23),
        )
        .unwrap_err();
        assert!(err.to_string().contains("monday"));
    }

    #[test]
    fn issues_are_synced_and_numbers_are_kept() {
        let srv = TestServer::start(|req| match req.method.as_str() {
            "GET" => (200, "[]".into()),
            _ => (201, r#"{"number":5,"node_id":"N"}"#.into()),
        });
        let gh = GitHub::new(srv.base(), "tok", "o/r")
            .unwrap()
            .with_write_delay(Duration::ZERO);
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_dir(dir.path());
        let o = DeliverOptions {
            github: Some(gh),
            ..opts(24)
        };
        let out = deliver(&report(vec![fortios()]), &config(), &store, &[], &o).unwrap();
        assert_eq!(out.issues.as_ref().unwrap().created.len(), 1);
        assert_eq!(out.status_issue, Some(5));
        let saved = store.load().unwrap();
        assert_eq!(saved.items["office-firewall"].issue, Some(5));

        // `notify.issues: false` turns it off.
        let before = srv.requests().len();
        let mut cfg = config();
        cfg.notify.issues = false;
        let out = deliver(&report(vec![fortios()]), &cfg, &store, &[], &o).unwrap();
        assert!(out.issues.is_none());
        assert_eq!(srv.requests().len(), before);
    }
}
