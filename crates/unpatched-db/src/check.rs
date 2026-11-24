//! The one way to run a check: config + database (+ OSV for packages) → report.
//! The CLI, the GitHub Action and the MCP server all call [`run_check`].

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use unpatched_core::{Config, Report, Vulnerability, evaluate};
use unpatched_sources::{Http, osv};

use crate::{Db, Result};

/// Evaluate `config` against `db`. Package (`purl`) items are looked up in
/// OSV when `http` is given; with `None` (offline) they are skipped and the
/// report says so in its notes.
pub fn run_check(
    config: &Config,
    db: &Db,
    http: Option<&Http>,
    now: DateTime<Utc>,
) -> Result<Report> {
    let purls: Vec<String> = config.stack.iter().filter_map(|i| i.purl.clone()).collect();
    let mut packages: HashMap<String, Vec<Vulnerability>> = HashMap::new();
    if !purls.is_empty()
        && let Some(http) = http
    {
        packages = osv::query_batch(http, &purls)?;
    }
    let mut report = evaluate(config, db, &packages, now);
    if http.is_none() && !purls.is_empty() {
        report.notes.push(format!(
            "{} package item(s) were not checked: OSV lookups are off (offline mode)",
            purls.len()
        ));
    }
    Ok(report)
}
