//! The command line, end to end, against the frozen smoke database.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

const NOW: &str = "2026-11-24T00:00:00Z";

const STACK: &str = "\
version: 1
stack:
  - product: fortios
    version: 7.2.5
    exposure: internet
    name: Office firewall
  - product: nextcloud
    version: 29.0.3
    exposure: internet
";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn smoke_db() -> PathBuf {
    root().join("fixtures/smoke/unpatched-db.sqlite")
}

fn unpatched(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("unpatched").unwrap();
    c.current_dir(dir)
        .env_remove("GITHUB_ACTIONS")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GITHUB_STEP_SUMMARY")
        .env_remove("UNPATCHED_DB")
        .env("UNPATCHED_CACHE_DIR", dir.join("cache"))
        .env("NO_COLOR", "1")
        .args(["--color", "never"]);
    c
}

/// A temp folder with `unpatched.yml` in it.
fn workspace(stack: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("unpatched.yml"), stack).unwrap();
    dir
}

fn check_at(dir: &Path, now: &str) -> Command {
    let mut c = unpatched(dir);
    c.args(["--offline", "--db"])
        .arg(smoke_db())
        .args(["check", "--now", now]);
    c
}

fn check(dir: &Path) -> Command {
    check_at(dir, NOW)
}

fn stdout_of(mut c: Command) -> String {
    String::from_utf8(c.assert().success().get_output().stdout.clone()).unwrap()
}

#[test]
fn version_and_help() {
    let dir = tempfile::tempdir().unwrap();
    unpatched(dir.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("unpatched "));
    unpatched(dir.path())
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Exit codes:"));
}

#[test]
fn check_text() {
    let ws = workspace(STACK);
    insta::assert_snapshot!("check_text", stdout_of(check(ws.path())));
}

#[test]
fn check_json() {
    let ws = workspace(STACK);
    let out = stdout_of({
        let mut c = check(ws.path());
        c.args(["--format", "json"]);
        c
    });
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["summary"]["now"], 1);
    let f = &v["findings"][0];
    assert_eq!(f["key"], "office-firewall/CVE-2024-21762");
    assert_eq!(f["product"], "fortios");
    assert_eq!(f["product_name"], "FortiOS");
    assert_eq!(f["bucket"], "now");
    assert_eq!(f["fixed_in"], "7.2.7");
    assert_eq!(v["generated_at"], NOW);
    insta::assert_snapshot!("check_json", out);
}

#[test]
fn check_sarif() {
    let ws = workspace(STACK);
    let out = stdout_of({
        let mut c = check(ws.path());
        c.args(["--format", "sarif"]);
        c
    });
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    insta::assert_snapshot!("check_sarif", out);
}

#[test]
fn check_markdown_to_a_file() {
    let ws = workspace(STACK);
    let out = ws.path().join("summary.md");
    check(ws.path())
        .args(["--format", "markdown", "--output"])
        .arg(&out)
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains("1 fix today"));
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.starts_with("## unpatched"));
    assert!(text.contains("FortiOS 7.2.5 (Office firewall)"));
}

#[test]
fn output_to_the_step_summary_appends() {
    let ws = workspace(STACK);
    let out = ws.path().join("step-summary.md");
    std::fs::write(&out, "earlier step\n").unwrap();
    check(ws.path())
        .env("GITHUB_STEP_SUMMARY", &out)
        .args(["--format", "markdown", "--output"])
        .arg(&out)
        .assert()
        .success();
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.starts_with("earlier step\n## unpatched"), "{text}");
}

#[test]
fn exit_code_flag() {
    let ws = workspace(STACK);
    check(ws.path()).assert().code(0);
    check(ws.path()).arg("--exit-code").assert().code(1);
    let quiet = workspace("version: 1\nstack:\n  - product: fortios\n    version: 7.4.3\n");
    check(quiet.path())
        .arg("--exit-code")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Nothing to fix."));
}

#[test]
fn unknown_product_suggests_three() {
    let ws = workspace("version: 1\nstack:\n  - product: fortios7\n    version: \"1\"\n");
    check(ws.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown product \"fortios7\""))
        .stderr(predicate::str::contains("Did you mean: fortios (FortiOS)"));
}

#[test]
fn missing_and_broken_config_are_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    check(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unpatched init"));
    let ws = workspace("version: 1\nstack:\n  - product: fortios\n");
    check(ws.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("needs a version"));
    let ws = workspace("version: 1\nstack: [\n");
    check(ws.path()).assert().code(2);
}

#[test]
fn usage_errors_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    unpatched(dir.path()).arg("bogus").assert().code(2);
    unpatched(dir.path())
        .args(["check", "--dry-run"])
        .assert()
        .code(2);
}

#[test]
fn data_errors_exit_3() {
    let ws = workspace(STACK);
    // No database.
    unpatched(ws.path())
        .args(["--offline", "--db", "nowhere.sqlite", "check"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("unpatched db update"));
    // Older than stale_fail_days (7).
    check_at(ws.path(), "2026-12-10T00:00:00Z")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("days old"));
    // Unless told to carry on.
    check_at(ws.path(), "2026-12-10T00:00:00Z")
        .arg("--allow-stale")
        .assert()
        .success();
}

#[test]
fn notify_dry_run_writes_nothing() {
    let ws = workspace(STACK);
    check(ws.path())
        .args(["--notify", "--dry-run"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "dry run: would save the delivery state",
        ));
    assert!(!ws.path().join(".unpatched").exists());
}

#[test]
fn notify_saves_state_in_a_file_next_to_the_config() {
    let ws = workspace(STACK);
    check(ws.path()).arg("--notify").assert().success();
    let state = std::fs::read_to_string(ws.path().join(".unpatched/state.json")).unwrap();
    assert!(state.contains("office-firewall/CVE-2024-21762"), "{state}");
}

#[test]
fn notify_with_github_needs_a_token() {
    let ws = workspace(STACK);
    check(ws.path())
        .args(["--notify", "--github"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("GITHUB_TOKEN"));
}

#[test]
fn notify_with_a_missing_secret_is_a_usage_error() {
    let ws = workspace(&format!("{STACK}notify:\n  slack: true\n"));
    check(ws.path())
        .arg("--notify")
        .env_remove("UNPATCHED_SLACK_WEBHOOK")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("UNPATCHED_SLACK_WEBHOOK"));
}

#[test]
fn explain_a_rule() {
    let dir = tempfile::tempdir().unwrap();
    let out = stdout_of({
        let mut c = unpatched(dir.path());
        c.args(["explain", "UNP-KEV"]);
        c
    });
    insta::assert_snapshot!("explain_rule", out);
    unpatched(dir.path())
        .args(["explain", "kev"])
        .assert()
        .success();
}

#[test]
fn explain_a_cve_with_the_stack() {
    let ws = workspace(STACK);
    let mut c = unpatched(ws.path());
    c.args(["--offline", "--db"])
        .arg(smoke_db())
        .args(["explain", "CVE-2024-21762"]);
    c.assert()
        .success()
        .stdout(predicate::str::contains("CISA KEV: added 2024-02-09"))
        .stdout(predicate::str::contains("Office firewall 7.2.5"))
        .stdout(predicate::str::contains("Verdict: affected"))
        // The vulnerability is not about Nextcloud: say so in one line, and do
        // not claim "not affected" without a source that had ranges for it.
        .stdout(predicate::str::contains(
            "1 other stack item is not concerned",
        ))
        .stdout(predicate::str::contains("nextcloud"))
        .stdout(predicate::str::contains("no version data for this product").not());
}

#[test]
fn explain_a_finding_key() {
    let ws = workspace(STACK);
    let mut c = unpatched(ws.path());
    c.args(["--offline", "--db"])
        .arg(smoke_db())
        .args(["explain", "office-firewall/CVE-2024-21762"]);
    c.assert()
        .success()
        .stdout(predicate::str::contains("FortiOS 7.2.5 (Office firewall)"))
        .stdout(predicate::str::contains("UNP-KEV"));
}

#[test]
fn explain_something_unknown() {
    let ws = workspace(STACK);
    let mut c = unpatched(ws.path());
    c.args(["--offline", "--db"])
        .arg(smoke_db())
        .args(["explain", "CVE-1999-0001"]);
    c.assert().code(3);
    unpatched(ws.path())
        .args(["explain", "hello"])
        .assert()
        .code(2);
}

#[test]
fn search_and_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let out = stdout_of({
        let mut c = unpatched(dir.path());
        c.args(["search", "fortigate"]);
        c
    });
    assert!(out.contains("fortios"), "{out}");
    unpatched(dir.path())
        .args(["search", "zzzzzz"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No product matches"));
    unpatched(dir.path())
        .args(["catalog", "list", "--kind", "database"])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgresql"))
        .stdout(predicate::str::contains("fortios").not());
    unpatched(dir.path())
        .args(["catalog", "show", "fortigate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("id: fortios"));
    unpatched(dir.path())
        .args(["catalog", "show", "nope"])
        .assert()
        .code(2);
}

#[test]
fn db_info() {
    let dir = tempfile::tempdir().unwrap();
    let out = stdout_of({
        let mut c = unpatched(dir.path());
        c.args(["db", "info", "--db"]).arg(smoke_db());
        c
    });
    assert!(out.contains("Schema version:   1"), "{out}");
    assert!(out.contains("2026-11-23 12:00 UTC"));
    assert!(out.contains("CISA KEV"));
    // Not a database: a data error.
    let junk = dir.path().join("junk.sqlite");
    std::fs::write(&junk, "not a database").unwrap();
    unpatched(dir.path())
        .args(["db", "info", "--db"])
        .arg(&junk)
        .assert()
        .code(3);
    unpatched(dir.path())
        .args(["db", "info", "--db", "missing.sqlite"])
        .assert()
        .code(3);
}

#[test]
fn db_commands_that_need_the_network_refuse_offline() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["db", "update"],
        vec!["db", "sources-health"],
        vec!["db", "build", "--out", "x.sqlite"],
    ] {
        unpatched(dir.path())
            .arg("--offline")
            .args(&args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--offline"));
    }
}

#[test]
fn init_writes_the_template_when_not_interactive() {
    let dir = tempfile::tempdir().unwrap();
    unpatched(dir.path())
        .arg("init")
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains("Next steps"));
    let text = std::fs::read_to_string(dir.path().join("unpatched.yml")).unwrap();
    assert!(text.contains("product: fortios"));
    // The file it wrote works.
    check(dir.path()).assert().success();
    // It does not overwrite.
    unpatched(dir.path())
        .arg("init")
        .write_stdin("")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--force"));
    unpatched(dir.path())
        .args(["init", "--force"])
        .write_stdin("")
        .assert()
        .success();
}

#[test]
fn init_github_writes_the_workflow() {
    let dir = tempfile::tempdir().unwrap();
    unpatched(dir.path())
        .args(["init", "--github"])
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains("PRIVATE"));
    let wf = std::fs::read_to_string(dir.path().join(".github/workflows/unpatched.yml")).unwrap();
    assert!(wf.contains("amet13/unpatched@v0"));
    assert!(wf.contains("17 6 * * *"));
}

#[test]
fn schemas_match_the_generated_files() {
    let dir = tempfile::tempdir().unwrap();
    for (which, file) in [
        ("config", "unpatched.schema.json"),
        ("report", "report.schema.json"),
    ] {
        let out = stdout_of({
            let mut c = unpatched(dir.path());
            c.args(["schema", which]);
            c
        });
        let want = std::fs::read_to_string(root().join("schema").join(file)).unwrap();
        assert_eq!(out, want, "run `cargo xtask schema`");
    }
}

#[test]
fn the_copies_of_the_templates_agree() {
    // `init` embeds the files in crates/unpatched/templates; people read templates/github.
    for file in ["unpatched.yml", "workflow.yml"] {
        let a = std::fs::read_to_string(root().join("templates/github").join(file)).unwrap();
        let b = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .join(file),
        )
        .unwrap();
        assert_eq!(a, b, "{file}");
    }
}

#[test]
fn help_pages_have_no_trailing_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let paths: [&[&str]; 12] = [
        &[],
        &["check"],
        &["init"],
        &["explain"],
        &["search"],
        &["catalog"],
        &["catalog", "list"],
        &["catalog", "show"],
        &["db"],
        &["db", "build"],
        &["mcp"],
        &["schema"],
    ];
    for args in paths {
        let out = stdout_of({
            let mut c = unpatched(dir.path());
            c.args(args).arg("--help");
            c
        });
        for (n, line) in out.lines().enumerate() {
            assert!(!line.ends_with(' '), "{args:?} line {}: {line:?}", n + 1);
        }
    }
    let out = stdout_of({
        let mut c = unpatched(dir.path());
        c.args(["catalog", "show", "--help"]);
        c
    });
    assert!(out.contains("A product id or alias"), "{out}");
}
