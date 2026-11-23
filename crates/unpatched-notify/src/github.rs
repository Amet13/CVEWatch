//! GitHub Issues: one issue per finding, plus one pinned status issue that also
//! holds the delivery state. Needs only `issues: write`.
//!
//! Environment: `GITHUB_TOKEN`, `GITHUB_REPOSITORY` (`owner/name`) and
//! `GITHUB_API_URL` (default `https://api.github.com`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Method;
use reqwest::blocking::Client;
use serde_json::{Value, json};
use unpatched_core::{Bucket, Finding, Report};

use crate::error::{Error, Result};
use crate::http::{Secret, check, client, http_err};
use crate::render::{markdown_issue, markdown_status, parse_finding_marker, parse_state_block};
use crate::state::{DeliveryState, StateStore};

pub const DEFAULT_API_URL: &str = "https://api.github.com";
pub const LABEL_BASE: &str = "unpatched";
pub const LABEL_STATUS: &str = "unpatched:status";
pub const STATUS_TITLE: &str = "unpatched status";
/// Added to the body of an issue that unpatched itself closed.
pub const CLOSED_MARKER: &str = "<!-- unpatched:closed -->";

/// `(name, colour, description)`.
pub const LABELS: [(&str, &str, &str); 7] = [
    (LABEL_BASE, "5319e7", "Opened by unpatched"),
    ("unpatched:now", "d73a4a", "Fix today"),
    ("unpatched:week", "fbca04", "Fix this week"),
    ("unpatched:eol", "586069", "Past end of life"),
    ("unpatched:unknown", "bfd4f2", "The data cannot say yet"),
    ("unpatched:fyi", "e1e4e8", "Affected, low urgency"),
    (LABEL_STATUS, "0e8a16", "The unpatched status issue"),
];

pub fn bucket_label_name(b: Bucket) -> &'static str {
    match b {
        Bucket::Now => "unpatched:now",
        Bucket::Week => "unpatched:week",
        Bucket::Eol => "unpatched:eol",
        Bucket::Unknown => "unpatched:unknown",
        Bucket::Fyi => "unpatched:fyi",
    }
}

fn is_bucket_label(name: &str) -> bool {
    [
        Bucket::Now,
        Bucket::Week,
        Bucket::Eol,
        Bucket::Unknown,
        Bucket::Fyi,
    ]
    .iter()
    .any(|b| bucket_label_name(*b) == name)
}

/// An issue as far as we care.
#[derive(Debug, Clone, PartialEq)]
pub struct IssueInfo {
    pub number: u64,
    pub node_id: String,
    pub open: bool,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    /// The finding key from the hidden marker.
    pub key: Option<String>,
}

impl IssueInfo {
    pub fn is_status(&self) -> bool {
        self.labels.iter().any(|l| l == LABEL_STATUS)
    }

    pub fn closed_by_unpatched(&self) -> bool {
        self.body.contains(CLOSED_MARKER)
    }
}

/// What a sync did, by finding key and issue number.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IssueSync {
    pub created: Vec<(String, u64)>,
    pub updated: Vec<(String, u64)>,
    pub closed: Vec<(String, u64)>,
    pub reopened: Vec<(String, u64)>,
    /// A person closed the issue and the finding is still there.
    pub closed_but_affected: Vec<(String, u64)>,
    pub unchanged: Vec<(String, u64)>,
    /// Problems with single issues; the sync went on.
    pub errors: Vec<String>,
}

impl IssueSync {
    /// The issue number for every finding that has one now.
    pub fn issue_numbers(&self) -> BTreeMap<String, u64> {
        self.created
            .iter()
            .chain(&self.updated)
            .chain(&self.reopened)
            .chain(&self.closed_but_affected)
            .chain(&self.unchanged)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct GitHub {
    http: Client,
    api: String,
    token: Secret,
    repo: String,
    dry_run: bool,
    write_delay: Duration,
    log: Arc<Mutex<Vec<String>>>,
}

impl GitHub {
    pub fn new(
        api_url: impl Into<String>,
        token: impl Into<String>,
        repository: impl Into<String>,
    ) -> Result<Self> {
        let repo = repository.into();
        if repo.split('/').filter(|p| !p.is_empty()).count() != 2 {
            return Err(Error::Config(format!(
                "GITHUB_REPOSITORY is {repo:?}; expected owner/name."
            )));
        }
        Ok(Self {
            http: client()?,
            api: api_url.into().trim_end_matches('/').to_owned(),
            token: Secret::new(token),
            repo,
            dry_run: false,
            write_delay: Duration::from_secs(1),
            log: Arc::default(),
        })
    }

    /// From `GITHUB_TOKEN`, `GITHUB_REPOSITORY` and `GITHUB_API_URL`.
    pub fn from_env() -> Result<Self> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    pub fn from_env_with(env: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let get = |k: &str| {
            env(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let token = get("GITHUB_TOKEN").ok_or(Error::MissingEnv {
            var: "GITHUB_TOKEN",
            what: "GitHub issues",
        })?;
        let repo = get("GITHUB_REPOSITORY").ok_or(Error::MissingEnv {
            var: "GITHUB_REPOSITORY",
            what: "GitHub issues",
        })?;
        let api = get("GITHUB_API_URL").unwrap_or_else(|| DEFAULT_API_URL.into());
        Self::new(api, token, repo)
    }

    /// True inside a GitHub Actions run.
    pub fn in_actions() -> bool {
        std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true")
    }

    /// Only log what would be written.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Pause after each write (GitHub's secondary rate limits want about 1 s).
    #[must_use]
    pub fn with_write_delay(mut self, delay: Duration) -> Self {
        self.write_delay = delay;
        self
    }

    /// The writes that were skipped in dry-run mode.
    pub fn planned_actions(&self) -> Vec<String> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    // ------------------------------------------------------------ plumbing

    fn request(&self, method: &Method, url: &str, body: Option<&Value>) -> Result<Value> {
        let mut retried = false;
        loop {
            let mut req = self
                .http
                .request(method.clone(), url)
                .bearer_auth(self.token.expose())
                .header("accept", "application/vnd.github+json")
                .header("x-github-api-version", "2022-11-28");
            if let Some(b) = body {
                req = req.json(b);
            }
            let resp = req.send().map_err(|e| http_err("github", e))?;
            let status = resp.status().as_u16();
            if !retried && matches!(status, 403 | 429) {
                let wait = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                if let Some(secs) = wait {
                    tracing::warn!("GitHub rate limit: waiting {secs}s");
                    std::thread::sleep(Duration::from_secs(secs.min(60)));
                    retried = true;
                    continue;
                }
            }
            let resp = check("github", resp, &[self.token.expose()])?;
            let text = resp.text().map_err(|e| http_err("github", e))?;
            if text.trim().is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_str(&text).map_err(|e| Error::Api {
                service: "github".into(),
                status,
                message: format!("unexpected answer: {e}"),
            });
        }
    }

    fn get(&self, path: &str) -> Result<Value> {
        self.request(&Method::GET, &format!("{}{path}", self.api), None)
    }

    /// A write. In dry-run mode nothing is sent.
    fn write(&self, method: &Method, path: &str, body: &Value, what: &str) -> Result<Value> {
        if self.dry_run {
            tracing::info!("dry run: would {what}");
            if let Ok(mut l) = self.log.lock() {
                l.push(what.to_owned());
            }
            return Ok(Value::Null);
        }
        let out = self.request(method, &format!("{}{path}", self.api), Some(body));
        std::thread::sleep(self.write_delay);
        out
    }

    fn pages(&self, path: &str) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        let sep = if path.contains('?') { '&' } else { '?' };
        for page in 1..=100 {
            let v = self.get(&format!("{path}{sep}per_page=100&page={page}"))?;
            let items = v.as_array().cloned().unwrap_or_default();
            let n = items.len();
            all.extend(items);
            if n < 100 {
                break;
            }
        }
        Ok(all)
    }

    // ------------------------------------------------------------ labels

    /// Create the labels unpatched uses, when missing.
    pub fn ensure_labels(&self) -> Result<()> {
        let existing: BTreeSet<String> = self
            .pages(&format!("/repos/{}/labels", self.repo))?
            .iter()
            .filter_map(|l| l["name"].as_str().map(str::to_lowercase))
            .collect();
        for (name, color, description) in LABELS {
            if existing.contains(name) {
                continue;
            }
            let body = json!({ "name": name, "color": color, "description": description });
            match self.write(
                &Method::POST,
                &format!("/repos/{}/labels", self.repo),
                &body,
                &format!("create label {name}"),
            ) {
                // 422: it appeared in the meantime.
                Ok(_) | Err(Error::Api { status: 422, .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ issues

    /// Every issue (open and closed) that carries the `unpatched` label.
    pub fn list_issues(&self) -> Result<Vec<IssueInfo>> {
        let raw = self.pages(&format!(
            "/repos/{}/issues?labels={LABEL_BASE}&state=all&sort=created&direction=asc",
            self.repo
        ))?;
        Ok(raw
            .iter()
            .filter(|i| i.get("pull_request").is_none())
            .filter_map(parse_issue)
            .collect())
    }

    /// Make the issues match the report: create, update, close, reopen.
    ///
    /// Only `now`, `week`, `eol` and `unknown` findings get new issues; `fyi`
    /// findings live in the status issue (and keep an issue they already had).
    pub fn sync_issues(&self, report: &Report) -> Result<IssueSync> {
        let issues = self.list_issues()?;
        let mut by_key: HashMap<&str, &IssueInfo> = HashMap::new();
        for i in issues.iter().filter(|i| !i.is_status()) {
            let Some(key) = i.key.as_deref() else {
                continue;
            };
            // Prefer an open issue; otherwise the newest one.
            let better = by_key
                .get(key)
                .is_none_or(|old| (i.open, i.number) > (old.open, old.number));
            if better {
                by_key.insert(key, i);
            }
        }

        let mut sync = IssueSync::default();
        let current: BTreeSet<&str> = report.findings.iter().map(|f| f.key.as_str()).collect();
        for f in &report.findings {
            let result = match by_key.get(f.key.as_str()) {
                None if f.bucket == Bucket::Fyi => continue,
                None => self.create_issue(f, report, &mut sync),
                Some(issue) => self.refresh_issue(f, issue, report, &mut sync),
            };
            if let Err(e) = result {
                sync.errors.push(format!("{}: {e}", f.key));
            }
        }
        for (key, issue) in &by_key {
            if !issue.open || current.contains(key) {
                continue;
            }
            match self.close_issue(key, issue, report) {
                Ok(()) => sync.closed.push(((*key).to_owned(), issue.number)),
                Err(e) => sync.errors.push(format!("{key}: {e}")),
            }
        }
        sync.created.sort();
        sync.closed.sort();
        Ok(sync)
    }

    fn create_issue(&self, f: &Finding, report: &Report, sync: &mut IssueSync) -> Result<()> {
        let (title, body) = markdown_issue(f, report);
        let payload = json!({
            "title": title,
            "body": body,
            "labels": [LABEL_BASE, bucket_label_name(f.bucket)],
        });
        let v = self.write(
            &Method::POST,
            &format!("/repos/{}/issues", self.repo),
            &payload,
            &format!("create issue {title:?}"),
        )?;
        sync.created
            .push((f.key.clone(), v["number"].as_u64().unwrap_or(0)));
        Ok(())
    }

    fn refresh_issue(
        &self,
        f: &Finding,
        issue: &IssueInfo,
        report: &Report,
        sync: &mut IssueSync,
    ) -> Result<()> {
        let (title, body) = markdown_issue(f, report);
        let mut labels: Vec<String> = issue
            .labels
            .iter()
            .filter(|l| !is_bucket_label(l))
            .cloned()
            .collect();
        for want in [LABEL_BASE, bucket_label_name(f.bucket)] {
            if !labels.iter().any(|l| l == want) {
                labels.push(want.to_owned());
            }
        }
        let key = f.key.clone();
        let n = issue.number;
        if !issue.open {
            if !issue.closed_by_unpatched() {
                // A person closed it. Do not argue; the status issue says so.
                sync.closed_but_affected.push((key, n));
                return Ok(());
            }
            let payload = json!({
                "state": "open", "title": title, "body": body, "labels": labels,
            });
            self.write(
                &Method::PATCH,
                &format!("/repos/{}/issues/{n}", self.repo),
                &payload,
                &format!("reopen issue #{n}"),
            )?;
            self.comment(
                n,
                "unpatched: this finding is back, so the issue is open again.",
            )?;
            sync.reopened.push((key, n));
            return Ok(());
        }
        let mut have: Vec<&String> = issue.labels.iter().collect();
        let mut want: Vec<&String> = labels.iter().collect();
        have.sort();
        want.sort();
        if issue.title == title && issue.body.trim() == body.trim() && have == want {
            sync.unchanged.push((key, n));
            return Ok(());
        }
        let payload = json!({ "title": title, "body": body, "labels": labels });
        self.write(
            &Method::PATCH,
            &format!("/repos/{}/issues/{n}", self.repo),
            &payload,
            &format!("update issue #{n}"),
        )?;
        sync.updated.push((key, n));
        Ok(())
    }

    fn close_issue(&self, key: &str, issue: &IssueInfo, report: &Report) -> Result<()> {
        let n = issue.number;
        let note = match report.ignored.iter().find(|f| f.key == key) {
            Some(f) => {
                let why = f.ignored.as_ref().map_or(String::new(), |i| {
                    format!(" ({} until {})", i.reason, i.until)
                });
                format!(
                    "unpatched: this finding is now ignored in unpatched.yml{why}. Closing the issue."
                )
            }
            None => "unpatched: this finding is gone. Either unpatched.yml now shows a version \
                     that is not affected, or the advisory was withdrawn. Closing the issue."
                .to_owned(),
        };
        self.comment(n, &note)?;
        let body = format!("{}\n\n{CLOSED_MARKER}\n", issue.body.trim_end());
        self.write(
            &Method::PATCH,
            &format!("/repos/{}/issues/{n}", self.repo),
            &json!({ "state": "closed", "state_reason": "completed", "body": body }),
            &format!("close issue #{n}"),
        )?;
        Ok(())
    }

    fn comment(&self, number: u64, text: &str) -> Result<()> {
        self.write(
            &Method::POST,
            &format!("/repos/{}/issues/{number}/comments", self.repo),
            &json!({ "body": text }),
            &format!("comment on issue #{number}"),
        )
        .map(drop)
    }

    // ------------------------------------------------------------ status issue

    fn find_status(&self) -> Result<Option<IssueInfo>> {
        Ok(self
            .list_issues()?
            .into_iter()
            .rev()
            .find(IssueInfo::is_status))
    }

    /// The delivery state in the status issue; empty when there is none yet.
    pub fn load_state(&self) -> Result<DeliveryState> {
        Ok(self
            .find_status()?
            .and_then(|i| parse_state_block(&i.body))
            .unwrap_or_default())
    }

    /// Create or update the pinned status issue. Returns its number.
    pub fn update_status(&self, report: &Report, state: &DeliveryState) -> Result<u64> {
        let body = markdown_status(report, state);
        let labels = [LABEL_BASE, LABEL_STATUS];
        if let Some(issue) = self.find_status()? {
            let n = issue.number;
            if issue.open && issue.body.trim() == body.trim() && issue.title == STATUS_TITLE {
                return Ok(n);
            }
            self.write(
                &Method::PATCH,
                &format!("/repos/{}/issues/{n}", self.repo),
                &json!({ "state": "open", "title": STATUS_TITLE, "body": body, "labels": labels }),
                "update the status issue",
            )?;
            return Ok(n);
        }
        let v = self.write(
            &Method::POST,
            &format!("/repos/{}/issues", self.repo),
            &json!({ "title": STATUS_TITLE, "body": body, "labels": labels }),
            "create the status issue",
        )?;
        if let Some(id) = v["node_id"].as_str() {
            self.pin(id);
        }
        Ok(v["number"].as_u64().unwrap_or(0))
    }

    /// Pin an issue (GraphQL). Failure is ignored: pinning is a nicety.
    fn pin(&self, node_id: &str) {
        let body = json!({
            "query": "mutation($id: ID!) { pinIssue(input: {issueId: $id}) { issue { id } } }",
            "variables": { "id": node_id },
        });
        let url = self.graphql_url();
        let result = self.request(&Method::POST, &url, Some(&body));
        if let Err(e) = result {
            tracing::debug!("could not pin the status issue: {e}");
        }
    }

    fn graphql_url(&self) -> String {
        if let Some(base) = self.api.strip_suffix("/api/v3") {
            format!("{base}/api/graphql")
        } else {
            format!("{}/graphql", self.api)
        }
    }
}

fn parse_issue(v: &Value) -> Option<IssueInfo> {
    let body = v["body"].as_str().unwrap_or_default().to_owned();
    Some(IssueInfo {
        number: v["number"].as_u64()?,
        node_id: v["node_id"].as_str().unwrap_or_default().to_owned(),
        open: v["state"].as_str() == Some("open"),
        title: v["title"].as_str().unwrap_or_default().to_owned(),
        key: parse_finding_marker(&body),
        body,
        labels: v["labels"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|l| l["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// The delivery state in the pinned status issue.
#[derive(Debug, Clone)]
pub struct IssuesStore {
    gh: GitHub,
}

impl IssuesStore {
    pub fn new(gh: GitHub) -> Self {
        Self { gh }
    }
}

impl StateStore for IssuesStore {
    fn load(&self) -> Result<DeliveryState> {
        self.gh.load_state()
    }

    fn save(&self, state: &DeliveryState, report: &Report) -> Result<()> {
        self.gh.update_status(report, state).map(drop)
    }

    fn writes_status_issue(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::fixture::{fortios, report, sample_report};
    use crate::state::SentRecord;
    use crate::testutil::{Request, TestServer};

    /// A fake GitHub that keeps issues in memory.
    #[derive(Default)]
    struct Fake {
        labels: Vec<String>,
        issues: Vec<Value>,
        next: u64,
    }

    fn fake(initial: Vec<Value>, labels: &[&str]) -> (TestServer, Arc<Mutex<Fake>>) {
        let state = Arc::new(Mutex::new(Fake {
            labels: labels.iter().map(|s| (*s).to_owned()).collect(),
            next: initial
                .iter()
                .filter_map(|i| i["number"].as_u64())
                .max()
                .unwrap_or(0)
                + 1,
            issues: initial,
        }));
        let st = Arc::clone(&state);
        let srv = TestServer::start(move |req: &Request| {
            let mut f = st.lock().unwrap();
            let path = req.path.split('?').next().unwrap().to_owned();
            let page: usize = req
                .path
                .split("&page=")
                .nth(1)
                .and_then(|p| p.split('&').next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(1);
            let slice = |all: Vec<Value>| -> String {
                let v: Vec<Value> = all.into_iter().skip((page - 1) * 100).take(100).collect();
                serde_json::to_string(&v).unwrap()
            };
            match (req.method.as_str(), path.as_str()) {
                ("GET", "/repos/o/r/labels") => {
                    let l = f.labels.iter().map(|n| json!({"name": n})).collect();
                    (200, slice(l))
                }
                ("POST", "/repos/o/r/labels") => {
                    let n = req.json()["name"].as_str().unwrap().to_owned();
                    f.labels.push(n);
                    (201, "{}".into())
                }
                ("GET", "/repos/o/r/issues") => (200, slice(f.issues.clone())),
                ("POST", "/repos/o/r/issues") => {
                    let b = req.json();
                    let n = f.next;
                    f.next += 1;
                    let labels: Vec<Value> = b["labels"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|l| json!({"name": l}))
                        .collect();
                    let issue = json!({
                        "number": n, "node_id": format!("NODE{n}"), "state": "open",
                        "title": b["title"], "body": b["body"], "labels": labels,
                    });
                    f.issues.push(issue.clone());
                    (201, issue.to_string())
                }
                ("PATCH", p) if p.starts_with("/repos/o/r/issues/") => {
                    let n: u64 = p.rsplit('/').next().unwrap().parse().unwrap();
                    let b = req.json();
                    let issue = f.issues.iter_mut().find(|i| i["number"] == n).unwrap();
                    for k in ["state", "title", "body"] {
                        if b.get(k).is_some() {
                            issue[k] = b[k].clone();
                        }
                    }
                    if let Some(ls) = b["labels"].as_array() {
                        issue["labels"] = ls.iter().map(|l| json!({"name": l})).collect();
                    }
                    (200, issue.to_string())
                }
                ("POST", p) if p.ends_with("/comments") => (201, "{}".into()),
                ("POST", "/graphql") => (200, r#"{"data":{}}"#.into()),
                _ => (404, r#"{"message":"Not Found"}"#.into()),
            }
        });
        (srv, state)
    }

    fn gh(srv: &TestServer) -> GitHub {
        GitHub::new(srv.base(), "ghs_SECRET", "o/r")
            .unwrap()
            .with_write_delay(Duration::ZERO)
    }

    fn existing(r: &Report, f: &Finding, number: u64, open: bool, by_unpatched: bool) -> Value {
        let (title, mut body) = markdown_issue(f, r);
        if by_unpatched {
            body = format!("{body}\n{CLOSED_MARKER}\n");
        }
        json!({
            "number": number, "node_id": format!("NODE{number}"),
            "state": if open { "open" } else { "closed" },
            "title": title, "body": body,
            "labels": [{"name": LABEL_BASE}, {"name": bucket_label_name(f.bucket)}],
        })
    }

    fn writes(srv: &TestServer) -> Vec<(String, String)> {
        srv.requests()
            .into_iter()
            .filter(|r| r.method != "GET")
            .map(|r| (r.method, r.path))
            .collect()
    }

    #[test]
    fn labels_are_created_once() {
        let (srv, st) = fake(vec![], &["bug", "unpatched", "unpatched:now"]);
        gh(&srv).ensure_labels().unwrap();
        assert_eq!(writes(&srv).len(), 5);
        assert!(
            st.lock()
                .unwrap()
                .labels
                .contains(&LABEL_STATUS.to_string())
        );
        let again = srv.requests().len();
        gh(&srv).ensure_labels().unwrap();
        let posts = srv.requests()[again..]
            .iter()
            .filter(|r| r.method == "POST")
            .count();
        assert_eq!(posts, 0);
    }

    #[test]
    fn creates_issues_for_new_findings_except_fyi() {
        let r = sample_report();
        let (srv, st) = fake(vec![], &[]);
        let sync = gh(&srv).sync_issues(&r).unwrap();
        assert_eq!(sync.created.len(), 5, "fyi gets no issue");
        assert!(sync.errors.is_empty());
        let f = st.lock().unwrap();
        let first = &f.issues[0];
        assert!(first["title"].as_str().unwrap().starts_with("🔴 Fix today"));
        assert!(
            first["body"]
                .as_str()
                .unwrap()
                .contains("<!-- unpatched:finding=office-firewall/CVE-2024-21762 -->")
        );
        let auth = srv.requests()[0]
            .header("authorization")
            .unwrap()
            .to_owned();
        assert_eq!(auth, "Bearer ghs_SECRET");
    }

    #[test]
    fn second_run_changes_nothing() {
        let r = sample_report();
        let (srv, _st) = fake(vec![], &[]);
        gh(&srv).sync_issues(&r).unwrap();
        let before = writes(&srv).len();
        let sync = gh(&srv).sync_issues(&r).unwrap();
        assert_eq!(writes(&srv).len(), before, "no writes");
        assert_eq!(sync.unchanged.len(), 5);
        assert!(sync.created.is_empty() && sync.updated.is_empty() && sync.closed.is_empty());
    }

    #[test]
    fn bucket_change_updates_title_and_labels() {
        let mut r = sample_report();
        let f = r
            .findings
            .iter()
            .find(|f| f.bucket == Bucket::Week)
            .unwrap()
            .clone();
        let old = existing(&r, &f, 7, true, false);
        let mut moved = f.clone();
        moved.bucket = Bucket::Now;
        r.findings = vec![moved];
        let mut issue = old;
        issue["labels"] =
            json!([{"name": "unpatched"}, {"name": "unpatched:week"}, {"name": "customer-x"}]);
        let (srv, st) = fake(vec![issue], &[]);
        let sync = gh(&srv).sync_issues(&r).unwrap();
        assert_eq!(sync.updated, vec![(f.key.clone(), 7)]);
        let got = st.lock().unwrap().issues[0].clone();
        assert!(got["title"].as_str().unwrap().starts_with("🔴 Fix today"));
        let labels: Vec<&str> = got["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["name"].as_str().unwrap())
            .collect();
        assert!(labels.contains(&"unpatched:now") && !labels.contains(&"unpatched:week"));
        assert!(labels.contains(&"customer-x"), "user labels are kept");
    }

    #[test]
    fn resolved_findings_are_closed_with_a_comment() {
        let r = sample_report();
        let gone = fortios();
        let (srv, st) = fake(vec![existing(&r, &gone, 3, true, false)], &[]);
        let quiet = report(vec![]);
        let sync = gh(&srv).sync_issues(&quiet).unwrap();
        assert_eq!(sync.closed, vec![(gone.key.clone(), 3)]);
        let reqs = srv.requests();
        let comment = reqs.iter().find(|q| q.path.ends_with("/comments")).unwrap();
        assert!(
            comment.json()["body"]
                .as_str()
                .unwrap()
                .contains("not affected")
        );
        let issue = st.lock().unwrap().issues[0].clone();
        assert_eq!(issue["state"], "closed");
        assert!(issue["body"].as_str().unwrap().contains(CLOSED_MARKER));
    }

    #[test]
    fn ignored_findings_say_so_when_closed() {
        let mut r = sample_report();
        let ign = r.ignored[0].clone();
        let (srv, _st) = fake(vec![existing(&r, &ign, 4, true, false)], &[]);
        r.findings.clear();
        gh(&srv).sync_issues(&r).unwrap();
        let reqs = srv.requests();
        let comment = reqs.iter().find(|q| q.path.ends_with("/comments")).unwrap();
        assert!(
            comment.json()["body"]
                .as_str()
                .unwrap()
                .contains("app disabled")
        );
    }

    #[test]
    fn reopens_only_what_unpatched_closed() {
        let r = sample_report();
        let a = fortios();
        let b = r
            .findings
            .iter()
            .find(|f| f.bucket == Bucket::Eol)
            .unwrap()
            .clone();
        let issues = vec![
            existing(&r, &a, 1, false, true),
            existing(&r, &b, 2, false, false),
        ];
        let (srv, st) = fake(issues, &[]);
        let mut only = r.clone();
        only.findings = vec![a.clone(), b.clone()];
        let sync = gh(&srv).sync_issues(&only).unwrap();
        assert_eq!(sync.reopened, vec![(a.key, 1)]);
        assert_eq!(sync.closed_but_affected, vec![(b.key, 2)]);
        let f = st.lock().unwrap();
        assert_eq!(f.issues[0]["state"], "open");
        assert_eq!(f.issues[1]["state"], "closed", "a human's decision stands");
        assert!(
            !f.issues[0]["body"]
                .as_str()
                .unwrap()
                .contains(CLOSED_MARKER)
        );
    }

    #[test]
    fn pagination_finds_issues_on_later_pages() {
        let r = report(vec![]);
        let mut issues = Vec::new();
        for n in 1..=150u64 {
            let mut f = fortios();
            f.key = format!("host{n}/CVE-1");
            issues.push(existing(&r, &f, n, true, false));
        }
        let (srv, _st) = fake(issues, &[]);
        let sync = gh(&srv).sync_issues(&r).unwrap();
        assert_eq!(sync.closed.len(), 150);
    }

    #[test]
    fn dry_run_writes_nothing() {
        let r = sample_report();
        let (srv, _st) = fake(vec![], &[]);
        let g = gh(&srv).with_dry_run(true);
        g.ensure_labels().unwrap();
        let sync = g.sync_issues(&r).unwrap();
        g.update_status(&r, &DeliveryState::default()).unwrap();
        assert_eq!(sync.created.len(), 5);
        assert!(writes(&srv).is_empty());
        let plan = g.planned_actions();
        assert!(plan.iter().any(|a| a.starts_with("create issue")));
        assert!(plan.iter().any(|a| a.contains("status issue")));
    }

    #[test]
    fn status_issue_is_created_pinned_and_holds_state() {
        let r = sample_report();
        let (srv, st) = fake(vec![], &[]);
        let g = gh(&srv);
        assert_eq!(g.load_state().unwrap(), DeliveryState::default());
        let mut state = DeliveryState::default();
        state.sent.insert(
            "a/CVE-1".into(),
            SentRecord::new(r.generated_at, Bucket::Now),
        );
        let n = g.update_status(&r, &state).unwrap();
        assert_eq!(n, 1);
        assert!(
            srv.requests().iter().any(|q| q.path == "/graphql"),
            "pinned"
        );
        assert_eq!(g.load_state().unwrap(), state);
        // Unchanged body: no second write.
        let before = writes(&srv).len();
        g.update_status(&r, &state).unwrap();
        assert_eq!(writes(&srv).len(), before);
        // A changed state patches the same issue.
        state.last_digest = Some(r.generated_at.date_naive());
        assert_eq!(g.update_status(&r, &state).unwrap(), 1);
        assert_eq!(st.lock().unwrap().issues.len(), 1);
        assert_eq!(g.load_state().unwrap(), state);
        // The status issue is never closed by a sync.
        let sync = g.sync_issues(&report(vec![])).unwrap();
        assert!(sync.closed.is_empty());
    }

    #[test]
    fn pin_failure_is_ignored() {
        let srv = TestServer::start(|req| {
            match (req.method.as_str(), req.path.split('?').next().unwrap()) {
                ("GET", _) => (200, "[]".into()),
                ("POST", "/repos/o/r/issues") => (201, r#"{"number":9,"node_id":"N"}"#.into()),
                _ => (500, "no".into()),
            }
        });
        let n = gh(&srv)
            .update_status(&report(vec![]), &DeliveryState::default())
            .unwrap();
        assert_eq!(n, 9);
    }

    #[test]
    fn issues_store_round_trip() {
        let r = sample_report();
        let (srv, _st) = fake(vec![], &[]);
        let store = IssuesStore::new(gh(&srv));
        assert!(store.writes_status_issue());
        let mut s = DeliveryState {
            last_run: Some(r.generated_at),
            ..DeliveryState::default()
        };
        s.sent.insert(
            "k/CVE-2".into(),
            SentRecord::new(r.generated_at, Bucket::Week),
        );
        store.save(&s, &r).unwrap();
        assert_eq!(store.load().unwrap(), s);
    }

    #[test]
    fn api_errors_hide_the_token() {
        let srv =
            TestServer::start(|_| (401, r#"{"message":"Bad credentials ghs_SECRET"}"#.into()));
        let err = gh(&srv).ensure_labels().unwrap_err().to_string();
        assert!(err.contains("401") && !err.contains("ghs_SECRET"), "{err}");
    }

    #[test]
    fn env_handling() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let err = GitHub::from_env_with(env(&[])).unwrap_err().to_string();
        assert!(err.contains("GITHUB_TOKEN"));
        let err = GitHub::from_env_with(env(&[("GITHUB_TOKEN", "t")]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("GITHUB_REPOSITORY"));
        let err =
            GitHub::from_env_with(env(&[("GITHUB_TOKEN", "t"), ("GITHUB_REPOSITORY", "nope")]))
                .unwrap_err()
                .to_string();
        assert!(err.contains("owner/name"));
        let g = GitHub::from_env_with(env(&[("GITHUB_TOKEN", "t"), ("GITHUB_REPOSITORY", "o/r")]))
            .unwrap();
        assert_eq!(g.api, DEFAULT_API_URL);
        let g = GitHub::new("https://ghe.example/api/v3/", "t", "o/r").unwrap();
        assert_eq!(g.graphql_url(), "https://ghe.example/api/graphql");
        let _: BTreeMap<String, u64> = IssueSync::default().issue_numbers();
    }
}
