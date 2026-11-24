//! An in-memory [`Dataset`], for tests, the corpus and anything that already
//! holds its data in memory. Build it with the `with_*` methods or load it
//! from JSON or YAML.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::Dataset;
use crate::catalog::CatalogEntry;
use crate::model::{DbInfo, EolCycle, Signals, Vulnerability};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDataset {
    #[serde(default)]
    pub products: Vec<CatalogEntry>,
    #[serde(default)]
    pub vulns: Vec<Vulnerability>,
    /// Signals by vulnerability id.
    #[serde(default)]
    pub signals: BTreeMap<String, Signals>,
    /// EOL cycles by catalog product id.
    #[serde(default)]
    pub eol: BTreeMap<String, Vec<EolCycle>>,
    /// Catalog product ids that match nothing in the data. Every other
    /// product counts as verified.
    #[serde(default)]
    pub unverified: Vec<String>,
    #[serde(default)]
    pub info: Option<DbInfo>,
}

impl MemoryDataset {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_product(mut self, entry: CatalogEntry) -> Self {
        self.products.push(entry);
        self
    }

    #[must_use]
    pub fn with_vuln(mut self, vuln: Vulnerability) -> Self {
        self.vulns.push(vuln);
        self
    }

    #[must_use]
    pub fn with_signals(mut self, vuln_id: impl Into<String>, signals: Signals) -> Self {
        self.signals.insert(vuln_id.into(), signals);
        self
    }

    #[must_use]
    pub fn with_eol(mut self, product_id: impl Into<String>, cycles: Vec<EolCycle>) -> Self {
        self.eol.insert(product_id.into(), cycles);
        self
    }

    #[must_use]
    pub fn with_unverified(mut self, product_id: impl Into<String>) -> Self {
        self.unverified.push(product_id.into());
        self
    }

    #[must_use]
    pub fn with_info(mut self, info: DbInfo) -> Self {
        self.info = Some(info);
        self
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    pub fn from_yaml(text: &str) -> Result<Self, serde_norway::Error> {
        serde_norway::from_str(text)
    }
}

impl Dataset for MemoryDataset {
    fn product(&self, id: &str) -> Option<CatalogEntry> {
        self.products
            .iter()
            .find(|p| {
                p.id.eq_ignore_ascii_case(id)
                    || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(id))
            })
            .cloned()
    }

    fn vulns_for_product(&self, product_id: &str) -> Vec<Vulnerability> {
        self.vulns
            .iter()
            .filter(|v| v.ranges.iter().any(|r| r.product == product_id))
            .cloned()
            .collect()
    }

    fn signals(&self, vuln_id: &str) -> Signals {
        self.signals
            .get(vuln_id)
            .or_else(|| self.signals.get(&vuln_id.to_ascii_uppercase()))
            .cloned()
            .unwrap_or_default()
    }

    fn eol_cycles(&self, product_id: &str) -> Vec<EolCycle> {
        self.eol.get(product_id).cloned().unwrap_or_default()
    }

    fn product_verified(&self, product_id: &str) -> bool {
        !self.unverified.iter().any(|u| u == product_id)
    }

    fn info(&self) -> Option<DbInfo> {
        self.info.clone()
    }
}
