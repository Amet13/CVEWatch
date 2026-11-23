//! From stack + data to findings. See ADR-0005 for how sources combine.

use chrono::{DateTime, Utc};

use crate::catalog::CatalogEntry;
use crate::config::Config;
use crate::model::{DbInfo, EolCycle, Signals, Vulnerability};
use crate::report::Report;

/// Read access to vulnerability data. `unpatched-db` implements it over
/// SQLite; tests implement it in memory.
pub trait Dataset {
    /// Catalog entry by id or alias.
    fn product(&self, id: &str) -> Option<CatalogEntry>;
    /// All vulnerabilities with a range for this catalog product.
    fn vulns_for_product(&self, product_id: &str) -> Vec<Vulnerability>;
    /// Exploitation signals for a CVE id.
    fn signals(&self, vuln_id: &str) -> Signals;
    /// endoflife.date cycles for a catalog product.
    fn eol_cycles(&self, product_id: &str) -> Vec<EolCycle>;
    /// True when at least one record in the data matched this product's keys.
    fn product_verified(&self, product_id: &str) -> bool;
    fn info(&self) -> Option<DbInfo>;
}

/// Evaluate a whole config. `package_vulns` holds OSV results per purl stack
/// item (queried by the caller, since core does no I/O). `now` is passed in
/// so results are reproducible.
pub fn evaluate(
    config: &Config,
    data: &dyn Dataset,
    package_vulns: &std::collections::HashMap<String, Vec<Vulnerability>>,
    now: DateTime<Utc>,
) -> Report {
    let _ = (config, data, package_vulns, now);
    unimplemented!("matching::evaluate")
}
