//! Pure rendering: report in, text out. No network, no clock, no environment
//! (except [`TextOptions::auto`], which reads `NO_COLOR`).

use std::fmt::Write as _;

use serde_json::{Value, json};
use unpatched_core::config::Exposure;
use unpatched_core::rules::{RuleId, all_rules};
use unpatched_core::{Bucket, Finding, Report, SourceId, SsvcExploitation, Verdict};

use crate::state::DeliveryState;

// ---------------------------------------------------------------- vocabulary

pub fn bucket_emoji(b: Bucket) -> &'static str {
    match b {
        Bucket::Now => "🔴",
        Bucket::Week => "🟡",
        Bucket::Eol => "⚫",
        Bucket::Unknown => "❔",
        Bucket::Fyi => "⚪",
    }
}

pub fn bucket_label(b: Bucket) -> &'static str {
    match b {
        Bucket::Now => "Fix today",
        Bucket::Week => "This week",
        Bucket::Eol => "End of life",
        Bucket::Unknown => "Unknown",
        Bucket::Fyi => "FYI",
    }
}

/// All buckets, most urgent first.
pub const BUCKETS: [Bucket; 5] = [
    Bucket::Now,
    Bucket::Week,
    Bucket::Eol,
    Bucket::Unknown,
    Bucket::Fyi,
];

pub fn source_name(s: SourceId) -> &'static str {
    match s {
        SourceId::CveOrg => "CVE.org",
        SourceId::CisaAdp => "CISA Vulnrichment",
        SourceId::Nvd => "NVD",
        SourceId::Osv => "OSV",
        SourceId::Kev => "CISA KEV",
        SourceId::Epss => "EPSS",
        SourceId::Endoflife => "endoflife.date",
        SourceId::ExploitDb => "Exploit-DB",
        SourceId::Metasploit => "Metasploit",
    }
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Affected => "affected",
        Verdict::Fixed => "fixed",
        Verdict::NotAffected => "not affected",
        Verdict::Unknown => "unknown",
    }
}

fn rule_title(id: RuleId) -> &'static str {
    all_rules()
        .into_iter()
        .find(|r| r.id == id)
        .map_or("", |r| r.title)
}

fn rule_explanation(id: RuleId) -> &'static str {
    all_rules()
        .into_iter()
        .find(|r| r.id == id)
        .map_or("", |r| r.explanation)
}

/// "FortiOS 7.2.5", with the stack item's own name in brackets when it has one.
pub fn subject(f: &Finding) -> String {
    if f.item == f.product {
        format!("{} {}", f.product_name, f.version)
    } else {
        format!("{} {} ({})", f.product_name, f.version, f.item)
    }
}

fn exposure_name(e: Exposure) -> &'static str {
    match e {
        Exposure::Internet => "internet-facing",
        Exposure::Internal => "internal",
    }
}

/// Why this bucket, most important first.
pub fn why_parts(f: &Finding) -> Vec<String> {
    let mut p = Vec::new();
    if let Some(r) = f
        .rules
        .first()
        .filter(|_| matches!(f.bucket, Bucket::Eol | Bucket::Unknown))
    {
        p.push(rule_title(*r).to_owned());
    }
    if let Some(k) = &f.signals.kev {
        p.push(format!("In CISA KEV since {}", k.date_added));
        if k.known_ransomware {
            p.push("ransomware use: known".into());
        }
        if let Some(d) = k.due_date {
            p.push(format!("CISA due date {d}"));
        }
    }
    match f.signals.ssvc_exploitation {
        Some(SsvcExploitation::Active) => p.push("SSVC: exploitation is active".into()),
        Some(SsvcExploitation::Poc) => p.push("SSVC: proof of concept exists".into()),
        Some(SsvcExploitation::None) | None => {}
    }
    if f.signals.ssvc_automatable == Some(true) {
        p.push("SSVC: automatable".into());
    }
    if let Some(e) = &f.signals.epss {
        p.push(format!(
            "EPSS {:.1}% (percentile {:.0})",
            e.score * 100.0,
            e.percentile * 100.0
        ));
    }
    match f.signals.exploits.as_slice() {
        [] => {}
        [one] => p.push(format!("public exploit: {}", one.id)),
        many => p.push(format!("{} public exploits", many.len())),
    }
    if let Some(c) = &f.cvss {
        p.push(format!("CVSS {:.1}", c.score));
    }
    if f.exposure == Exposure::Internet {
        p.push(exposure_name(f.exposure).into());
    }
    if p.is_empty() {
        p.push(
            f.rules
                .first()
                .map_or("affected", |r| rule_title(*r))
                .to_owned(),
        );
    }
    p
}

pub fn why(f: &Finding) -> String {
    why_parts(f).join(" · ")
}

/// What to do about it.
pub fn action(f: &Finding) -> String {
    if f.bucket == Bucket::Eol {
        return "Upgrade to a supported release.".into();
    }
    if f.verdict == Verdict::Unknown {
        return missing(f);
    }
    match (&f.fixed_in, &f.latest_in_cycle) {
        (Some(fix), Some(latest)) if fix != latest => {
            format!("Upgrade to {fix} or later ({latest} is current in this branch).")
        }
        (Some(fix), _) => format!("Upgrade to {fix} or later."),
        (None, Some(latest)) => format!("Upgrade to {latest} (current in this branch)."),
        (None, None) => "No fixed version is known yet. Check the vendor advisory.".into(),
    }
}

/// What is missing, for an `unknown` finding.
fn missing(f: &Finding) -> String {
    let rule = f.rules.first().copied();
    match rule {
        Some(RuleId::UnknownNoRanges) => {
            "No source has version data for this yet. Read the advisory and check your version by hand.".into()
        }
        Some(RuleId::UnknownVersion) => {
            "A version cannot be compared. Check the version in unpatched.yml.".into()
        }
        Some(RuleId::Conflict) => "Sources disagree. Read the evidence below.".into(),
        Some(RuleId::UnverifiedProduct) => {
            "The data has no record of this product. Check the catalog entry.".into()
        }
        Some(RuleId::StaleData) => {
            "Refresh the database (unpatched db update) and check the daily build.".into()
        }
        _ => "The data cannot say yet. Read the advisory.".into(),
    }
}

fn is_exploited(f: &Finding) -> bool {
    f.signals.kev.is_some() || f.signals.ssvc_exploitation == Some(SsvcExploitation::Active)
}

// ---------------------------------------------------------------- text

#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    /// Evidence, references and rule explanations.
    pub verbose: bool,
    /// ANSI colours. Ignored when `NO_COLOR` is set.
    pub color: bool,
}

impl TextOptions {
    /// Colour only on a terminal, and never when `NO_COLOR` is set.
    pub fn auto(verbose: bool, is_terminal: bool) -> Self {
        Self {
            verbose,
            color: is_terminal,
        }
    }
}

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

struct Paint(bool);

impl Paint {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_owned()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn bucket(&self, b: Bucket, s: &str) -> String {
        let code = match b {
            Bucket::Now => "1;31",
            Bucket::Week => "1;33",
            Bucket::Eol => "1;90",
            Bucket::Unknown => "1;35",
            Bucket::Fyi => "1;37",
        };
        self.wrap(code, s)
    }
}

/// "🟢 1,412 checked, nothing else affects you".
pub fn heartbeat(report: &Report) -> String {
    let n = group_thousands(report.summary.not_affected);
    if report.findings.is_empty() {
        format!("🟢 {n} checked, nothing affects you")
    } else {
        format!("🟢 {n} checked, nothing else affects you")
    }
}

fn group_thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "Database: built 2026-11-22 02:41 UTC, 1 day old".
pub fn db_line(report: &Report) -> String {
    match &report.db {
        None => "Database: no build date, so its age is unknown".into(),
        Some(db) => {
            let days = (report.generated_at - db.built_at).num_days().max(0);
            format!(
                "Database: built {}, {days} day{} old",
                db.built_at.format("%Y-%m-%d %H:%M UTC"),
                if days == 1 { "" } else { "s" }
            )
        }
    }
}

/// The terminal report.
pub fn text(report: &Report, opts: &TextOptions) -> String {
    let paint = Paint(opts.color && !no_color());
    let mut out = String::new();
    if report.findings.is_empty() {
        out.push_str("Nothing to fix.\n\n");
    }
    for bucket in BUCKETS {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.bucket == bucket)
            .collect();
        if group.is_empty() {
            continue;
        }
        let head = format!(
            "{} {} ({})",
            bucket_emoji(bucket),
            bucket_label(bucket),
            group.len()
        );
        let _ = writeln!(out, "{}\n", paint.bucket(bucket, &head));
        for f in group {
            text_finding(&mut out, f, *opts, &paint);
            out.push('\n');
        }
    }
    let _ = writeln!(out, "{}", heartbeat(report));
    if report.summary.ignored > 0 {
        let _ = writeln!(
            out,
            "{} ignored on purpose (see unpatched.yml)",
            report.summary.ignored
        );
    }
    let _ = writeln!(out, "{}", paint.dim(&db_line(report)));
    for n in &report.notes {
        let _ = writeln!(out, "Note: {n}");
    }
    out
}

fn text_finding(out: &mut String, f: &Finding, opts: TextOptions, paint: &Paint) {
    let _ = writeln!(out, "  {}", paint.bold(&subject(f)));
    match &f.vuln {
        Some(id) => {
            let _ = writeln!(out, "  {id}  {}", f.title);
        }
        None => {
            let _ = writeln!(out, "  {}", f.title);
        }
    }
    let _ = writeln!(out, "    Why   {}", why(f));
    let _ = writeln!(out, "    Do    {}", action(f));
    let rules: Vec<&str> = f.rules.iter().map(|r| r.code()).collect();
    let _ = writeln!(
        out,
        "    Rule  {} · verdict {}",
        rules.join(", "),
        verdict_name(f.verdict)
    );
    if opts.verbose {
        for e in &f.evidence {
            let _ = writeln!(
                out,
                "    Evidence  {}: {} ({})",
                source_name(e.source),
                e.detail,
                verdict_name(e.verdict)
            );
        }
        for r in &f.rules {
            let _ = writeln!(out, "    Rule {}  {}", r.code(), rule_explanation(*r));
        }
        for url in &f.references {
            let _ = writeln!(out, "    See   {url}");
        }
    }
}

// ---------------------------------------------------------------- markdown: issues

/// Hidden marker that ties an issue to a finding.
pub fn finding_marker(key: &str) -> String {
    format!("<!-- unpatched:finding={} -->", escape_comment(key))
}

/// The finding key in an issue body, if there is a marker.
pub fn parse_finding_marker(body: &str) -> Option<String> {
    let start = body.find("<!-- unpatched:finding=")? + "<!-- unpatched:finding=".len();
    let end = body[start..].find(" -->")? + start;
    Some(unescape_comment(&body[start..end]))
}

/// Keep `--` and `>` out of an HTML comment.
fn escape_comment(s: &str) -> String {
    s.replace('%', "%25")
        .replace("--", "-%2D")
        .replace('>', "%3E")
}

fn unescape_comment(s: &str) -> String {
    s.replace("%3E", ">")
        .replace("%2D", "-")
        .replace("%25", "%")
}

fn issue_what(f: &Finding) -> String {
    match (&f.vuln, f.bucket) {
        (Some(v), _) => v.clone(),
        (None, Bucket::Eol) => "past end of life".into(),
        (None, _) => f.title.clone(),
    }
}

/// `🔴 Fix today: fortios 7.2.5 (Office firewall) — CVE-2024-21762 (exploited)`
pub fn issue_title(f: &Finding) -> String {
    let suffix = if is_exploited(f) {
        " (exploited)"
    } else if f.rules.contains(&RuleId::ExploitExposed) {
        " (public exploit)"
    } else {
        ""
    };
    let title = format!(
        "{} {}: {} — {}{suffix}",
        bucket_emoji(f.bucket),
        bucket_label(f.bucket),
        subject(f),
        issue_what(f)
    );
    crate::http::truncate(&title, 250)
}

fn issue_sentence(f: &Finding) -> String {
    let who = if f.item == f.product {
        format!("`{}`", subject(f))
    } else {
        format!("**{}** runs `{} {}`", f.item, f.product_name, f.version)
    };
    let id = f.vuln.as_deref().unwrap_or("this");
    match (f.bucket, f.verdict) {
        (Bucket::Eol, _) => format!("{who} is past end of life and no longer gets security fixes."),
        (_, Verdict::Unknown) => {
            format!("unpatched cannot tell whether {who} is affected by {id}.")
        }
        _ if f.item == f.product => format!("{who} is affected by {id}."),
        _ => format!("{who}, which is affected by {id}."),
    }
}

/// One GitHub issue per finding: `(title, body)`.
pub fn markdown_issue(f: &Finding, _report: &Report) -> (String, String) {
    let mut b = String::new();
    let _ = writeln!(b, "{}\n", issue_sentence(f));
    if let Some(v) = &f.vuln {
        let _ = writeln!(b, "**{v}**: {}\n", f.title);
    } else {
        let _ = writeln!(b, "{}\n", f.title);
    }
    let label = if f.bucket == Bucket::Now {
        "Why now"
    } else {
        "Why"
    };
    let _ = writeln!(b, "**{label}:** {}\n", why(f));
    let _ = writeln!(b, "**Do:** {}\n", action(f));
    if !f.evidence.is_empty() {
        b.push_str("**Evidence**\n\n");
        for e in &f.evidence {
            let _ = writeln!(
                b,
                "- {}: {} ({})",
                source_name(e.source),
                e.detail,
                verdict_name(e.verdict)
            );
        }
        b.push('\n');
    }
    b.push_str("**Rules**\n\n");
    for (i, r) in f.rules.iter().enumerate() {
        if i == 0 {
            let _ = writeln!(
                b,
                "- `{}` {}. {}",
                r.code(),
                rule_title(*r),
                rule_explanation(*r)
            );
        } else {
            let _ = writeln!(b, "- `{}` {}", r.code(), rule_title(*r));
        }
    }
    let _ = writeln!(
        b,
        "- Verdict: {} · bucket: {}",
        verdict_name(f.verdict),
        bucket_label(f.bucket)
    );
    b.push('\n');
    if !f.references.is_empty() {
        b.push_str("**References**\n\n");
        for url in &f.references {
            let _ = writeln!(b, "- {url}");
        }
        b.push('\n');
    }
    b.push_str(
        "---\n\nClose this issue when it is fixed; unpatched closes it on its own once \
         unpatched.yml shows a fixed version.\n\n",
    );
    b.push_str(&finding_marker(&f.key));
    b.push('\n');
    (issue_title(f), b)
}

// ---------------------------------------------------------------- markdown: status issue

pub const STATE_MARKER_START: &str = "<!-- unpatched:state ";
const STATUS_LIST_CAP: usize = 200;

/// The state JSON, safe inside an HTML comment.
fn state_block(state: &DeliveryState) -> String {
    let json = state
        .to_json()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e");
    format!("{STATE_MARKER_START}{json} -->")
}

/// The delivery state in a status issue body.
pub fn parse_state_block(body: &str) -> Option<DeliveryState> {
    let start = body.find(STATE_MARKER_START)? + STATE_MARKER_START.len();
    let end = body[start..].find(" -->")? + start;
    DeliveryState::from_json(&body[start..end]).ok()
}

/// The pinned status issue body.
pub fn markdown_status(report: &Report, state: &DeliveryState) -> String {
    let s = &report.summary;
    let mut b = String::new();
    let open = report.findings.len();
    if open == 0 {
        let _ = writeln!(b, "{}\n", heartbeat(report));
    } else {
        let _ = writeln!(
            b,
            "{open} open finding{}. {}\n",
            if open == 1 { "" } else { "s" },
            heartbeat(report)
        );
    }
    b.push_str("| Bucket | Findings |\n| --- | ---: |\n");
    for (bucket, n) in [
        (Bucket::Now, s.now),
        (Bucket::Week, s.week),
        (Bucket::Eol, s.eol),
        (Bucket::Unknown, s.unknown),
        (Bucket::Fyi, s.fyi),
    ] {
        let _ = writeln!(
            b,
            "| {} {} | {n} |",
            bucket_emoji(bucket),
            bucket_label(bucket)
        );
    }
    let _ = writeln!(b, "| Ignored on purpose | {} |", s.ignored);
    b.push('\n');

    let mut listed = 0usize;
    for bucket in BUCKETS {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.bucket == bucket)
            .collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(b, "### {} {}\n", bucket_emoji(bucket), bucket_label(bucket));
        for f in group {
            if listed >= STATUS_LIST_CAP {
                break;
            }
            listed += 1;
            let rec = state.sent.get(&f.key);
            let link = match (rec.and_then(|r| r.issue), bucket) {
                (Some(n), _) => format!("#{n} "),
                (None, _) => String::new(),
            };
            let _ = writeln!(
                b,
                "- {link}{} — {}: {}",
                subject(f),
                issue_what(f),
                action(f)
            );
        }
        b.push('\n');
    }
    if listed < open {
        let _ = writeln!(b, "…and {} more.\n", open - listed);
    }

    let reopened: Vec<_> = state
        .sent
        .iter()
        .filter(|(k, r)| r.closed_by_human && report.findings.iter().any(|f| &f.key == *k))
        .collect();
    if !reopened.is_empty() {
        b.push_str("### Closed but still affected\n\n");
        b.push_str(
            "Someone closed these issues, but the findings are still there. unpatched does not reopen them.\n\n",
        );
        for (key, rec) in reopened {
            let f = report.findings.iter().find(|f| &f.key == key);
            let name = f.map_or_else(|| key.clone(), subject);
            let link = rec.issue.map_or(String::new(), |n| format!("#{n} "));
            let _ = writeln!(b, "- {link}{name}");
        }
        b.push('\n');
    }

    let _ = writeln!(b, "{}\n", db_line(report));
    let last = state.last_run.unwrap_or(report.generated_at);
    let _ = writeln!(b, "Last run: {}\n", last.format("%Y-%m-%d %H:%M UTC"));
    if !report.notes.is_empty() {
        b.push_str("### Notes\n\n");
        for n in &report.notes {
            let _ = writeln!(b, "- {n}");
        }
        b.push('\n');
    }
    b.push_str(&state_block(state));
    b.push('\n');
    b
}

// ---------------------------------------------------------------- markdown: run summary

fn md_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A summary of one run, for `$GITHUB_STEP_SUMMARY`: counts, the findings by
/// bucket, the data age and the notes.
pub fn markdown_summary(report: &Report) -> String {
    let s = &report.summary;
    let mut b = String::from("## unpatched\n\n");
    if report.findings.is_empty() {
        let _ = writeln!(b, "Nothing to fix. {}\n", heartbeat(report));
    } else {
        let n = report.findings.len();
        let _ = writeln!(
            b,
            "{n} finding{} to look at. {}\n",
            if n == 1 { "" } else { "s" },
            heartbeat(report)
        );
        b.push_str("| Bucket | Findings |\n| --- | ---: |\n");
        for (bucket, n) in [
            (Bucket::Now, s.now),
            (Bucket::Week, s.week),
            (Bucket::Eol, s.eol),
            (Bucket::Unknown, s.unknown),
            (Bucket::Fyi, s.fyi),
        ] {
            let _ = writeln!(
                b,
                "| {} {} | {n} |",
                bucket_emoji(bucket),
                bucket_label(bucket)
            );
        }
        b.push('\n');
    }
    for bucket in BUCKETS {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.bucket == bucket)
            .collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(b, "### {} {}\n", bucket_emoji(bucket), bucket_label(bucket));
        for f in group {
            let _ = writeln!(
                b,
                "- **{}**: {}",
                md_escape(&subject(f)),
                md_escape(&issue_what(f))
            );
            let _ = writeln!(b, "  - Why: {}", md_escape(&why(f)));
            let _ = writeln!(b, "  - Do: {}", md_escape(&action(f)));
            let rules: Vec<String> = f.rules.iter().map(|r| format!("`{}`", r.code())).collect();
            let _ = writeln!(b, "  - Rules: {}", rules.join(", "));
        }
        b.push('\n');
    }
    if s.ignored > 0 {
        let _ = writeln!(b, "{} ignored on purpose (see unpatched.yml).\n", s.ignored);
    }
    let _ = writeln!(b, "{}\n", db_line(report));
    if !report.notes.is_empty() {
        b.push_str("### Notes\n\n");
        for n in &report.notes {
            let _ = writeln!(b, "- {}", md_escape(n));
        }
        b.push('\n');
    }
    b
}

// ---------------------------------------------------------------- digest

/// A short digest for chat: plain text with light Markdown.
pub fn digest(report: &Report, since_state: Option<&DeliveryState>) -> String {
    crate::message::Message::digest(report, since_state)
        .render(crate::message::Dialect::Plain, usize::MAX)
}

/// Escape text for Telegram MarkdownV2.
pub fn escape_telegram(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if "_*[]()~`>#+-=|{}.!\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Escape text for Slack mrkdwn.
pub fn escape_slack(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Escape text for Discord Markdown and stop mass mentions.
pub fn escape_discord(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' | '_' | '~' | '`' | '|' | '\\' | '>' | '#' => {
                out.push('\\');
                out.push(c);
            }
            '@' => out.push_str("@\u{200b}"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------- json, sarif

pub fn json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

fn sarif_level(b: Bucket) -> &'static str {
    match b {
        Bucket::Now => "error",
        Bucket::Week | Bucket::Eol | Bucket::Unknown => "warning",
        Bucket::Fyi => "note",
    }
}

fn sarif_result(f: &Finding, suppressed: bool) -> Value {
    let rule = f.rules.first().copied().unwrap_or(RuleId::Affected);
    let mut r = json!({
        "ruleId": rule.code(),
        "level": sarif_level(f.bucket),
        "message": {
            "text": format!("{}: {} Why: {} Do: {}", subject(f), f.title, why(f), action(f)),
        },
        "locations": [{
            "physicalLocation": { "artifactLocation": { "uri": "unpatched.yml" } },
            "logicalLocations": [{
                "name": f.item,
                "fullyQualifiedName": format!("{} {}", f.product_name, f.version),
                "kind": "resource",
            }],
        }],
        "partialFingerprints": { "unpatched/finding": f.key },
        "properties": {
            "bucket": f.bucket,
            "verdict": f.verdict,
            "vulnerability": f.vuln,
            "fixedIn": f.fixed_in,
            "rules": f.rules.iter().map(|r| r.code()).collect::<Vec<_>>(),
        },
    });
    if suppressed {
        let reason = f.ignored.as_ref().map_or(String::new(), |i| {
            format!("{} (until {})", i.reason, i.until)
        });
        r["suppressions"] = json!([{ "kind": "external", "justification": reason }]);
    }
    r
}

/// SARIF 2.1.0.
pub fn sarif(report: &Report) -> String {
    let rules: Vec<Value> = all_rules()
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id.code(),
                "name": r.id.code(),
                "shortDescription": { "text": r.title },
                "fullDescription": { "text": r.explanation },
            })
        })
        .collect();
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| sarif_result(f, false))
        .chain(report.ignored.iter().map(|f| sarif_result(f, true)))
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "unpatched",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/Amet13/unpatched",
                "rules": rules,
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{fortios, report, sample_report};
    use crate::state::SentRecord;

    fn state_with_issues(r: &Report) -> DeliveryState {
        let mut s = DeliveryState {
            last_run: Some(r.generated_at),
            ..DeliveryState::default()
        };
        for (i, f) in r.findings.iter().enumerate() {
            let mut rec = SentRecord::new(r.generated_at, f.bucket);
            rec.issue = (f.bucket != Bucket::Fyi).then_some(10 + i as u64);
            s.sent.insert(f.key.clone(), rec);
        }
        s
    }

    #[test]
    fn text_report() {
        let r = sample_report();
        insta::assert_snapshot!("text", text(&r, &TextOptions::default()));
    }

    #[test]
    fn text_report_verbose() {
        let r = sample_report();
        let opts = TextOptions {
            verbose: true,
            color: false,
        };
        insta::assert_snapshot!("text_verbose", text(&r, &opts));
    }

    #[test]
    fn text_report_empty() {
        insta::assert_snapshot!("text_empty", text(&report(vec![]), &TextOptions::default()));
    }

    #[test]
    fn colour_is_optional() {
        let r = sample_report();
        let plain = text(&r, &TextOptions::default());
        assert!(!plain.contains('\x1b'));
        let coloured = text(
            &r,
            &TextOptions {
                verbose: false,
                color: true,
            },
        );
        assert_eq!(coloured.contains('\x1b'), !no_color());
    }

    #[test]
    fn issue_for_now_finding() {
        let r = sample_report();
        let (title, body) = markdown_issue(&fortios(), &r);
        assert_eq!(
            title,
            "🔴 Fix today: FortiOS 7.2.5 (Office firewall) — CVE-2024-21762 (exploited)"
        );
        insta::assert_snapshot!("issue_now", body);
    }

    #[test]
    fn issue_for_eol_and_unknown() {
        let r = sample_report();
        let eol = r.findings.iter().find(|f| f.bucket == Bucket::Eol).unwrap();
        let (title, body) = markdown_issue(eol, &r);
        assert_eq!(title, "⚫ End of life: PostgreSQL 13.12 — past end of life");
        insta::assert_snapshot!("issue_eol", body);
        let unk = r
            .findings
            .iter()
            .find(|f| f.bucket == Bucket::Unknown)
            .unwrap();
        let (title, body) = markdown_issue(unk, &r);
        assert!(title.starts_with("❔ Unknown: Home Assistant 2024.10.1"));
        insta::assert_snapshot!("issue_unknown", body);
    }

    #[test]
    fn marker_round_trip() {
        for key in ["a/CVE-1", "weird--key>x%2D/y", "plain"] {
            let m = finding_marker(key);
            assert!(!m[4..m.len() - 3].contains("--"), "{m}");
            assert_eq!(
                parse_finding_marker(&format!("text\n\n{m}\n")).as_deref(),
                Some(key)
            );
        }
        assert_eq!(parse_finding_marker("no marker"), None);
    }

    #[test]
    fn run_summary() {
        let r = sample_report();
        insta::assert_snapshot!("summary", markdown_summary(&r));
    }

    #[test]
    fn status_issue() {
        let r = sample_report();
        let mut s = state_with_issues(&r);
        let key = &r.findings[1].key;
        s.sent.get_mut(key).unwrap().closed_by_human = true;
        let body = markdown_status(&r, &s);
        assert_eq!(parse_state_block(&body).unwrap(), s);
        insta::assert_snapshot!("status", body);
    }

    #[test]
    fn status_issue_quiet() {
        let r = report(vec![]);
        let body = markdown_status(&r, &DeliveryState::default());
        assert!(body.contains("🟢 1,412 checked, nothing affects you"));
        assert!(parse_state_block(&body).is_some());
    }

    #[test]
    fn state_block_survives_hostile_keys() {
        let mut s = DeliveryState::default();
        s.sent.insert(
            "x --> <script>".into(),
            SentRecord::new(sample_report().generated_at, Bucket::Now),
        );
        let body = markdown_status(&report(vec![]), &s);
        assert_eq!(parse_state_block(&body).unwrap(), s);
    }

    #[test]
    fn digest_text() {
        let r = sample_report();
        let mut s = DeliveryState::default();
        s.sent.insert(
            r.findings[0].key.clone(),
            SentRecord::new(r.generated_at, Bucket::Now),
        );
        insta::assert_snapshot!("digest", digest(&r, Some(&s)));
    }

    #[test]
    fn escapes() {
        assert_eq!(escape_telegram("a.b-c_d (x)!"), "a\\.b\\-c\\_d \\(x\\)\\!");
        assert_eq!(escape_slack("<a> & b"), "&lt;a&gt; &amp; b");
        assert_eq!(escape_discord("@everyone *x*"), "@\u{200b}everyone \\*x\\*");
    }

    #[test]
    fn json_round_trips() {
        let r = sample_report();
        let back: Report = serde_json::from_str(&json(&r)).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn sarif_output() {
        let r = sample_report();
        let v: Value = serde_json::from_str(&sarif(&r)).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), all_rules().len());
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), r.findings.len() + 1);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "unpatched.yml"
        );
        assert!(results.last().unwrap()["suppressions"].is_array());
    }
}
