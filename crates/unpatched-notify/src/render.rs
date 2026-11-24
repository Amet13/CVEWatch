//! Pure rendering: report in, text out. No network, no clock, no environment
//! (except [`TextOptions::auto`], which reads `NO_COLOR`).

use std::fmt::Write as _;

use serde_json::{Value, json};
use unpatched_core::config::Exposure;
use unpatched_core::rules::{RuleId, all_rules};
use unpatched_core::{Bucket, Finding, ItemSummary, Report, SourceId, SsvcExploitation, Verdict};

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

/// The bucket as a person says it in a sentence: "today", "this week",
/// "end of life", "unknown", "FYI". JSON keeps `now`, `week`, `eol`,
/// `unknown` and `fyi`.
pub fn bucket_word(b: Bucket) -> &'static str {
    match b {
        Bucket::Now => "today",
        Bucket::Week => "this week",
        Bucket::Eol => "end of life",
        Bucket::Unknown => "unknown",
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

/// Compare dotted numbers loosely (`7.2.10` is after `7.2.9`). For display
/// decisions only; verdicts use the product's version scheme in core.
pub(crate) fn loose_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    parts(a).cmp(&parts(b))
}

/// Longest title shown unless `--verbose`.
pub const TITLE_MAX: usize = 140;

/// The first sentence of a description, at most [`TITLE_MAX`] characters,
/// with an ellipsis when it is cut.
pub fn short_title(title: &str) -> String {
    let t = title.trim();
    let mut end = t.len();
    let chars: Vec<(usize, char)> = t.char_indices().collect();
    for (n, (i, c)) in chars.iter().enumerate() {
        if *c == '\n' {
            end = *i;
            break;
        }
        if matches!(c, '.' | '!' | '?')
            && chars
                .get(n + 1)
                .is_none_or(|(_, next)| next.is_whitespace())
        {
            end = i + c.len_utf8();
            break;
        }
    }
    let first = t[..end].trim();
    if first.chars().count() <= TITLE_MAX {
        return first.to_owned();
    }
    let cut: String = first.chars().take(TITLE_MAX - 1).collect();
    format!("{}…", cut.trim_end())
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
    if let Some(advice) = f.advice() {
        return advice;
    }
    if f.verdict == Verdict::Unknown {
        return missing(f);
    }
    match (&f.fixed_in, &f.fixed_after, &f.latest_in_cycle) {
        (Some(fix), _, Some(latest)) if fix != latest => {
            format!("Upgrade to {fix} or later ({latest} is current in this branch).")
        }
        (Some(fix), _, _) => format!("Upgrade to {fix} or later."),
        (None, Some(after), Some(latest))
            if loose_cmp(latest, after) == std::cmp::Ordering::Greater =>
        {
            format!("Upgrade to a release after {after} (latest in this cycle: {latest}).")
        }
        (None, Some(after), _) => format!("Upgrade to a release after {after}."),
        (None, None, Some(latest)) => format!("Upgrade to {latest} (current in this branch)."),
        (None, None, None) => "No fixed version is known yet. Check the vendor advisory.".into(),
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

// ---------------------------------------------------------------- item lines

/// "FortiOS 7.2.5", with the item's own name in brackets when it has one.
pub fn item_subject(i: &ItemSummary) -> String {
    if i.item == i.product {
        format!("{} {}", i.product_name, i.version)
    } else {
        format!("{} {} ({})", i.product_name, i.version, i.item)
    }
}

/// 🔴/🟡/⚫/❔/⚪ by the most urgent bucket, 🟢 when the item has no findings.
pub fn item_emoji(i: &ItemSummary) -> &'static str {
    i.counts.most_urgent().map_or("🟢", bucket_emoji)
}

/// "14 today · 36 this week · 228 FYI", only the buckets that have findings.
pub fn item_counts(i: &ItemSummary) -> String {
    let parts: Vec<String> = BUCKETS
        .into_iter()
        .filter(|b| i.counts.get(*b) > 0)
        .map(|b| format!("{} {}", i.counts.get(b), bucket_word(b)))
        .collect();
    if parts.is_empty() {
        "nothing to fix".into()
    } else {
        parts.join(" · ")
    }
}

/// The release branch of a version: `7.2` for `7.2.12`.
fn branch_of(version: &str) -> Option<String> {
    let v = version.trim().trim_start_matches(['v', 'V']);
    let mut parts = v.split('.');
    let (major, minor) = (parts.next()?, parts.next()?);
    let digits = |p: &str| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit());
    (digits(major) && minor.chars().next().is_some_and(|c| c.is_ascii_digit())).then(|| {
        format!(
            "{major}.{}",
            minor.trim_end_matches(|c: char| !c.is_ascii_digit())
        )
    })
}

/// "upgrade to 7.2.12 (fixes all 11)" or "upgrade to 7.2.12 (fixes 61 of 110;
/// 49 have no fix on 7.2)", when there is advice.
pub fn item_advice(i: &ItemSummary) -> Option<String> {
    match &i.upgrade_to {
        Some(v) => {
            let of = i.of.max(i.fixes);
            let how = if i.fixes >= of {
                match of {
                    1 => "fixes it".to_owned(),
                    n => format!("fixes all {n}"),
                }
            } else {
                let rest = of - i.fixes;
                let on = branch_of(v).unwrap_or_else(|| "this release".to_owned());
                let have = if rest == 1 { "has" } else { "have" };
                format!("fixes {} of {of}; {rest} {have} no fix on {on}", i.fixes)
            };
            Some(format!("upgrade to {v} ({how})"))
        }
        None if i.eol => Some("upgrade to a supported release".into()),
        None if i.unfixed > 0 => Some("no fixed version known yet".into()),
        None => None,
    }
}

/// `🔴 FortiOS 7.2.5 (Office firewall)  14 now · 36 week  →  upgrade to 7.2.12 (fixes 48 of 50)`
pub fn item_line(i: &ItemSummary) -> String {
    let mut line = format!("{} {}  {}", item_emoji(i), item_subject(i), item_counts(i));
    if let Some(a) = item_advice(i) {
        let _ = write!(line, "  →  {a}");
    }
    line
}

/// The items that have findings, most urgent first (stack order within a bucket).
pub fn items_to_show(report: &Report) -> Vec<&ItemSummary> {
    let mut items: Vec<&ItemSummary> = report
        .items
        .iter()
        .filter(|i| i.counts.total() > 0)
        .collect();
    items.sort_by_key(|i| i.counts.most_urgent());
    items
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

/// "🟢 990 vulnerabilities checked against your versions: not affected".
pub fn heartbeat(report: &Report) -> String {
    let n = report.summary.not_affected;
    let count = group_thousands(n);
    let what = if n == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    format!("🟢 {count} {what} checked against your versions: not affected")
}

/// "87 to act on (14 today, 69 this week, 3 end of life, 1 unknown), 228 FYI".
/// "To act on" is everything but FYI.
pub fn counts_line(report: &Report) -> String {
    let s = &report.summary;
    let act = s.now + s.week + s.eol + s.unknown;
    let mut line = if act == 0 {
        "Nothing to act on".to_owned()
    } else {
        let parts: Vec<String> = [
            (s.now, Bucket::Now),
            (s.week, Bucket::Week),
            (s.eol, Bucket::Eol),
            (s.unknown, Bucket::Unknown),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, b)| format!("{n} {}", bucket_word(b)))
        .collect();
        format!("{act} to act on ({})", parts.join(", "))
    };
    if s.fyi > 0 {
        let _ = write!(line, ", {} FYI", s.fyi);
    }
    line
}

/// "228 FYI not shown: run with -v or --format json" when FYI findings are left out.
pub fn fyi_hidden_line(report: &Report) -> Option<String> {
    (report.summary.fyi > 0).then(|| {
        format!(
            "{} FYI not shown: run with -v or --format json",
            report.summary.fyi
        )
    })
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
    let _ = writeln!(out, "{}\n", paint.bold(&counts_line(report)));
    let items = items_to_show(report);
    if !items.is_empty() {
        for i in items {
            let bucket = i.counts.most_urgent().unwrap_or(Bucket::Fyi);
            let _ = writeln!(out, "{}", paint.bucket(bucket, &item_line(i)));
        }
        out.push('\n');
    }
    for bucket in BUCKETS {
        if bucket == Bucket::Fyi && !opts.verbose {
            continue;
        }
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
    if !opts.verbose
        && let Some(line) = fyi_hidden_line(report)
    {
        let _ = writeln!(out, "{line}\n");
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

/// The full title with `--verbose`, else its first sentence.
fn shown_title(f: &Finding, verbose: bool) -> String {
    if verbose {
        f.title.clone()
    } else {
        short_title(&f.title)
    }
}

fn text_finding(out: &mut String, f: &Finding, opts: TextOptions, paint: &Paint) {
    let _ = writeln!(out, "  {}", paint.bold(&subject(f)));
    match &f.vuln {
        Some(id) => {
            let _ = writeln!(out, "  {id}  {}", shown_title(f, opts.verbose));
        }
        None => {
            let _ = writeln!(out, "  {}", shown_title(f, opts.verbose));
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

const ITEM_MARKER: &str = "<!-- unpatched:item=";

/// Hidden marker that ties an issue to a stack item.
pub fn item_marker(key: &str) -> String {
    format!("{ITEM_MARKER}{} -->", escape_comment(key))
}

/// The stack item key in an issue body, if there is a marker.
pub fn parse_item_marker(body: &str) -> Option<String> {
    let start = body.find(ITEM_MARKER)? + ITEM_MARKER.len();
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
        (None, _) => short_title(&f.title),
    }
}

/// Buckets that get an issue.
pub const ISSUE_BUCKETS: [Bucket; 4] = [Bucket::Now, Bucket::Week, Bucket::Eol, Bucket::Unknown];

/// Findings of an item that need action: `now`, `week`, `eol` or `unknown`.
pub fn issue_count(i: &ItemSummary) -> usize {
    i.counts.now + i.counts.week + i.counts.eol + i.counts.unknown
}

/// The most urgent bucket of an item that gets an issue.
pub fn issue_bucket(i: &ItemSummary) -> Option<Bucket> {
    ISSUE_BUCKETS.into_iter().find(|b| i.counts.get(*b) > 0)
}

/// `🔴 FortiOS 7.2.5 (Office firewall): 14 to fix today — upgrade to 7.2.12`
pub fn issue_title(i: &ItemSummary) -> String {
    let bucket = issue_bucket(i).unwrap_or(Bucket::Unknown);
    let what = match bucket {
        Bucket::Now => format!("{} to fix today", i.counts.now),
        Bucket::Week => format!("{} to fix this week", i.counts.week),
        Bucket::Eol => "past end of life".to_owned(),
        Bucket::Unknown | Bucket::Fyi => format!("{} to check", i.counts.unknown),
    };
    let advice = match (&i.upgrade_to, i.eol) {
        (Some(v), _) => format!(" — upgrade to {v}"),
        (None, true) => " — upgrade to a supported release".to_owned(),
        (None, false) => String::new(),
    };
    let title = format!(
        "{} {}: {what}{advice}",
        bucket_emoji(bucket),
        item_subject(i)
    );
    crate::http::truncate(&title, 250)
}

/// The `ignore:` entry that accepts a risk, as YAML lines.
pub fn ignore_snippet(cve: &str) -> String {
    format!("ignore:\n  - cve: {cve}\n    reason: …\n    until: YYYY-MM-DD\n")
}

/// How many findings an issue lists before it says "and N more".
pub const ISSUE_LIST_CAP: usize = 60;

/// One GitHub issue per stack item: `(title, body)`.
pub fn markdown_item_issue(item: &ItemSummary, report: &Report) -> (String, String) {
    let mut b = String::new();
    let _ = writeln!(b, "{}\n", md_escape(&item_line(item)));
    if item.exposure == Exposure::Internet {
        b.push_str("This item is marked as internet-facing.\n\n");
    }
    let mut listed = 0usize;
    let mut total = 0usize;
    for bucket in ISSUE_BUCKETS {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.item_key() == item.key && f.bucket == bucket)
            .collect();
        if group.is_empty() {
            continue;
        }
        total += group.len();
        let _ = writeln!(
            b,
            "### {} {} ({})\n",
            bucket_emoji(bucket),
            bucket_label(bucket),
            group.len()
        );
        for f in group {
            if listed >= ISSUE_LIST_CAP {
                break;
            }
            listed += 1;
            let _ = writeln!(b, "{}", issue_entry(f));
        }
        b.push('\n');
    }
    if total > listed {
        let _ = writeln!(
            b,
            "…and {} more (run `unpatched check` for all).\n",
            total - listed
        );
    }
    if item.counts.fyi > 0 {
        let _ = writeln!(
            b,
            "{} FYI not listed here: run `unpatched check -v` or `--format json`.\n",
            item.counts.fyi
        );
    }
    b.push_str(
        "---\n\nunpatched keeps this issue up to date and closes it once the item has nothing \
         left to fix (when the version in unpatched.yml is fixed).\n\n\
         To accept this risk, add to unpatched.yml:\n\n```yaml\n",
    );
    b.push_str(&ignore_snippet("CVE-…"));
    b.push_str("```\n\n");
    b.push_str(&item_marker(&item.key));
    b.push('\n');
    (issue_title(item), b)
}

/// One finding as a list entry: id, short title, why, fix.
fn issue_entry(f: &Finding) -> String {
    let id = issue_what(f);
    let mut line = format!("- **{}**", md_escape(&id));
    if f.vuln.is_some() {
        let t = short_title(&f.title);
        if !t.is_empty() {
            let _ = write!(line, " {}", md_escape(&t));
        }
    }
    let _ = write!(
        line,
        " — {} — {}",
        md_escape(&why(f)),
        md_escape(&action(f))
    );
    line
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
    let _ = writeln!(b, "{}. {}\n", counts_line(report), heartbeat(report));
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

    let items = items_to_show(report);
    if !items.is_empty() {
        b.push_str("### What to do\n\n");
        for i in items {
            let link = state
                .items
                .get(&i.key)
                .and_then(|r| r.issue)
                .map_or(String::new(), |n| format!("#{n} "));
            let _ = writeln!(b, "- {link}{}", md_escape(&item_line(i)));
        }
        b.push('\n');
    }

    let mut listed = 0usize;
    let listable = open - s.fyi;
    for bucket in BUCKETS {
        if bucket == Bucket::Fyi {
            continue;
        }
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
            let _ = writeln!(b, "- {} — {}: {}", subject(f), issue_what(f), action(f));
        }
        b.push('\n');
    }
    if listed < listable {
        let _ = writeln!(b, "…and {} more.\n", listable - listed);
    }
    if let Some(line) = fyi_hidden_line(report) {
        let _ = writeln!(b, "{line}\n");
    }

    let reopened: Vec<(&ItemSummary, Option<u64>)> = report
        .items
        .iter()
        .filter(|i| issue_count(i) > 0)
        .filter_map(|i| {
            let rec = state.items.get(&i.key)?;
            rec.closed_by_human.then_some((i, rec.issue))
        })
        .collect();
    if !reopened.is_empty() {
        b.push_str("### Closed but still affected\n\n");
        b.push_str(
            "Someone closed these issues, but the items still have findings. unpatched does not reopen them.\n\n",
        );
        for (i, issue) in reopened {
            let link = issue.map_or(String::new(), |n| format!("#{n} "));
            let _ = writeln!(b, "- {link}{}", item_subject(i));
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
    markdown_summary_with(report, false)
}

/// Like [`markdown_summary`]; with `verbose` the FYI findings are listed too.
pub fn markdown_summary_with(report: &Report, verbose: bool) -> String {
    let s = &report.summary;
    let mut b = String::from("## unpatched\n\n");
    if report.findings.is_empty() {
        let _ = writeln!(b, "Nothing to act on. {}\n", heartbeat(report));
    } else {
        let _ = writeln!(b, "{}. {}\n", counts_line(report), heartbeat(report));
        let items = items_to_show(report);
        if !items.is_empty() {
            for i in items {
                let _ = writeln!(b, "- {}", md_escape(&item_line(i)));
            }
            b.push('\n');
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
        b.push('\n');
    }
    for bucket in BUCKETS {
        if bucket == Bucket::Fyi && !verbose {
            continue;
        }
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
    if !verbose && let Some(line) = fyi_hidden_line(report) {
        let _ = writeln!(b, "{line}\n");
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
            "text": format!(
                "{}: {} Why: {} Do: {}",
                subject(f),
                short_title(&f.title),
                why(f),
                action(f)
            ),
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
            "fixedAfter": f.fixed_after,
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
    use crate::state::{ItemRecord, SentRecord};

    fn state_with_issues(r: &Report) -> DeliveryState {
        let mut s = DeliveryState {
            last_run: Some(r.generated_at),
            ..DeliveryState::default()
        };
        for f in &r.findings {
            s.sent
                .insert(f.key.clone(), SentRecord::new(r.generated_at, f.bucket));
        }
        for (i, item) in r.items.iter().enumerate() {
            let bucket = item.counts.most_urgent().unwrap();
            let mut rec = ItemRecord::new(r.generated_at, bucket);
            rec.issue = (bucket != Bucket::Fyi).then_some(10 + i as u64);
            s.items.insert(item.key.clone(), rec);
        }
        s
    }

    fn item<'a>(r: &'a Report, key: &str) -> &'a ItemSummary {
        r.items.iter().find(|i| i.key == key).unwrap()
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
    fn issue_for_an_item_with_now_findings() {
        let r = sample_report();
        let (title, body) = markdown_item_issue(item(&r, "office-firewall"), &r);
        assert_eq!(
            title,
            "🔴 FortiOS 7.2.5 (Office firewall): 1 to fix today — upgrade to 7.2.7"
        );
        insta::assert_snapshot!("issue_item_now", body);
    }

    #[test]
    fn issue_for_week_eol_and_unknown_items() {
        let r = sample_report();
        let (title, body) = markdown_item_issue(item(&r, "nextcloud"), &r);
        assert_eq!(
            title,
            "🟡 Nextcloud 29.0.3: 2 to fix this week — upgrade to 29.0.8"
        );
        insta::assert_snapshot!("issue_item_week", body);
        let (title, body) = markdown_item_issue(item(&r, "postgresql"), &r);
        assert_eq!(
            title,
            "⚫ PostgreSQL 13.12: past end of life — upgrade to a supported release"
        );
        insta::assert_snapshot!("issue_item_eol", body);
        let (title, body) = markdown_item_issue(item(&r, "home-assistant"), &r);
        assert_eq!(title, "❔ Home Assistant 2024.10.1: 1 to check");
        insta::assert_snapshot!("issue_item_unknown", body);
    }

    #[test]
    fn long_issues_are_capped() {
        let findings: Vec<Finding> = (0..100)
            .map(|i| {
                let mut f = fortios();
                f.key = format!("office-firewall/CVE-2026-{i:04}");
                f.vuln = Some(format!("CVE-2026-{i:04}"));
                f
            })
            .collect();
        let r = report(findings);
        let (title, body) = markdown_item_issue(item(&r, "office-firewall"), &r);
        assert!(title.contains("100 to fix today"), "{title}");
        assert_eq!(body.matches("\n- **CVE-").count(), ISSUE_LIST_CAP);
        assert!(body.contains("…and 40 more (run `unpatched check` for all)."));
        assert!(body.contains("<!-- unpatched:item=office-firewall -->"));
    }

    #[test]
    fn marker_round_trip() {
        for key in ["a", "weird--key>x%2D", "plain"] {
            let m = item_marker(key);
            assert!(!m[4..m.len() - 3].contains("--"), "{m}");
            assert_eq!(
                parse_item_marker(&format!("text\n\n{m}\n")).as_deref(),
                Some(key)
            );
        }
        assert_eq!(parse_item_marker("no marker"), None);
    }

    #[test]
    fn titles_are_cut_to_the_first_sentence() {
        assert_eq!(short_title("One. Two."), "One.");
        assert_eq!(short_title("No stop here"), "No stop here");
        assert_eq!(
            short_title("Versions 7.2.5 and 7.2.6 are hit. More."),
            "Versions 7.2.5 and 7.2.6 are hit."
        );
        assert_eq!(short_title("First line\nsecond line"), "First line");
        let long = format!("{} end.", "word ".repeat(60));
        let cut = short_title(&long);
        assert_eq!(cut.chars().count(), TITLE_MAX);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn verbose_text_keeps_the_full_title() {
        let mut f = fortios();
        f.title = "First sentence. Second sentence with more detail.".into();
        let r = report(vec![f]);
        let short = text(&r, &TextOptions::default());
        assert!(short.contains("First sentence.") && !short.contains("Second sentence"));
        let full = text(
            &r,
            &TextOptions {
                verbose: true,
                color: false,
            },
        );
        assert!(full.contains("Second sentence"));
    }

    #[test]
    fn item_lines() {
        let r = sample_report();
        assert_eq!(
            item_line(item(&r, "office-firewall")),
            "🔴 FortiOS 7.2.5 (Office firewall)  1 today  →  upgrade to 7.2.7 (fixes it)"
        );
        assert_eq!(
            item_line(item(&r, "postgresql")),
            "⚫ PostgreSQL 13.12  1 end of life  →  upgrade to a supported release"
        );
        let mut i = item(&r, "nextcloud").clone();
        i.counts.now = 14;
        i.counts.week = 36;
        i.upgrade_to = Some("7.2.12".into());
        i.fixes = 48;
        i.of = 50;
        assert_eq!(
            item_line(&i),
            "🔴 Nextcloud 29.0.3  14 today · 36 this week  →  upgrade to 7.2.12 (fixes 48 of 50; 2 have no fix on 7.2)"
        );
        i.fixes = 50;
        assert_eq!(item_advice(&i).unwrap(), "upgrade to 7.2.12 (fixes all 50)");
        i.fixes = 49;
        assert_eq!(
            item_advice(&i).unwrap(),
            "upgrade to 7.2.12 (fixes 49 of 50; 1 has no fix on 7.2)"
        );
    }

    #[test]
    fn counts_say_what_to_act_on_and_what_is_fyi() {
        let r = sample_report();
        assert_eq!(
            counts_line(&r),
            "5 to act on (1 today, 2 this week, 1 end of life, 1 unknown), 1 FYI"
        );
        assert_eq!(counts_line(&report(vec![])), "Nothing to act on");
        let hidden = text(&r, &TextOptions::default());
        assert!(!hidden.contains("CVE-2025-1111"), "{hidden}");
        assert!(hidden.contains("1 FYI not shown: run with -v or --format json"));
        let shown = text(
            &r,
            &TextOptions {
                verbose: true,
                color: false,
            },
        );
        assert!(shown.contains("CVE-2025-1111"), "{shown}");
        assert!(!shown.contains("FYI not shown"));
        assert!(!markdown_summary(&r).contains("CVE-2025-1111"));
        assert!(markdown_summary_with(&r, true).contains("CVE-2025-1111"));
        assert!(!markdown_status(&r, &DeliveryState::default()).contains("CVE-2025-1111"));
    }

    #[test]
    fn issues_carry_the_ignore_hint() {
        let r = sample_report();
        let (_, body) = markdown_item_issue(item(&r, "office-firewall"), &r);
        assert!(
            body.contains("To accept this risk, add to unpatched.yml"),
            "{body}"
        );
        assert!(body.contains("until: YYYY-MM-DD"));
    }

    #[test]
    fn fixed_after_advice() {
        let mut f = fortios();
        f.fixed_in = None;
        f.fixed_after = Some("9.8".into());
        f.latest_in_cycle = None;
        assert_eq!(action(&f), "Upgrade to a release after 9.8.");
        f.latest_in_cycle = Some("9.9p2".into());
        assert_eq!(
            action(&f),
            "Upgrade to a release after 9.8 (latest in this cycle: 9.9p2)."
        );
        f.latest_in_cycle = Some("9.7".into());
        assert_eq!(action(&f), "Upgrade to a release after 9.8.");
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
        s.items.get_mut("nextcloud").unwrap().closed_by_human = true;
        let body = markdown_status(&r, &s);
        assert_eq!(parse_state_block(&body).unwrap(), s);
        insta::assert_snapshot!("status", body);
    }

    #[test]
    fn status_issue_quiet() {
        let r = report(vec![]);
        let body = markdown_status(&r, &DeliveryState::default());
        assert!(
            body.contains("🟢 1,412 vulnerabilities checked against your versions: not affected")
        );
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
