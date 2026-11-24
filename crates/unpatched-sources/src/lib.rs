//! Fetch and parse vulnerability sources for unpatched (CVE.org, NVD, OSV, KEV, EPSS, endoflife.date, exploits).
//!
//! One module per source. `parse_*` functions are pure: bytes in, core types
//! out. `fetch_*` functions do the network, through a shared [`Http`] client.

pub mod cve_org;
pub mod endoflife;
pub mod epss;
mod error;
pub mod exploits;
mod http;
pub mod kev;
pub mod nvd;
pub mod osv;
pub mod par;
mod util;

#[cfg(test)]
mod testutil;

pub use error::{Result, SourceError};
pub use http::Http;
pub use util::CatalogIndex;
