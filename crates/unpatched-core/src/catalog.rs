//! A catalog entry ties together the names one product has in each source.
//! Entries live in `catalog/*.yml`; `unpatched-catalog` loads and checks them.

use chrono::NaiveDate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::version::Scheme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ProductKind {
    Appliance,
    App,
    Os,
    Database,
    Server,
    Library,
    Desktop,
    Cms,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CnaKey {
    pub vendor: String,
    pub product: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KevKey {
    pub vendor_project: String,
    pub product: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchKeys {
    /// `vendor:product` as in CPE 2.3 (`fortinet:fortios`).
    #[serde(default)]
    pub cpe: Vec<String>,
    /// Vendor and product exactly as CNAs write them in CVE records.
    #[serde(default)]
    pub cna: Vec<CnaKey>,
    /// `vendorProject` and `product` as in CISA KEV.
    #[serde(default)]
    pub kev: Vec<KevKey>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    /// Lowercase id used in `unpatched.yml` (`fortios`, `nextcloud`).
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub kind: ProductKind,
    pub versioning: Scheme,
    #[serde(rename = "match")]
    pub keys: MatchKeys,
    /// endoflife.date product slug.
    #[serde(default)]
    pub eol: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    /// When a person last checked this entry against real data.
    pub checked: NaiveDate,
}
