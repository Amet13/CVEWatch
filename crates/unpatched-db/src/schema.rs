//! The SQLite schema. `meta.schema_version` is the major version: a reader
//! refuses a larger number. Adding tables or columns that old readers can
//! ignore does not bump it.
//!
//! | table | content |
//! | --- | --- |
//! | `meta(key, value)` | `schema_version`, `built_at` (RFC 3339), `sources` (JSON `SourceStatus` list), `builder` |
//! | `products(id, entry, verified)` | catalog entry JSON at build time; `verified` = a record matched its keys |
//! | `product_names(name, product_id)` | lower-case ids and aliases, for lookups |
//! | `vulns(id, json)` | `Vulnerability` JSON with `ranges` left empty |
//! | `aliases(alias, vuln_id)` | other ids of a vulnerability |
//! | `ranges(vuln_id, product, source, json)` | `AffectedRange` JSON, indexed by `product` |
//! | `kev(cve, json)` | `KevEntry` JSON |
//! | `epss(cve, score, percentile, date)` | every scored CVE |
//! | `ssvc(cve, exploitation, automatable)` | CISA ADP SSVC decision points |
//! | `exploits(cve, source, id, url)` | Exploit-DB and Metasploit |
//! | `eol(product_id, json)` | endoflife.date cycles |

/// The major schema version this crate writes and reads.
pub const SCHEMA_VERSION: u32 = 1;

// `vulns` and `ranges` hold JSON of a few KB per row: they are rowid tables, since
// WITHOUT ROWID stores large rows in overflow pages (twice the size on disk). The
// small lookup tables stay WITHOUT ROWID.
pub(crate) const CREATE: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE products (id TEXT PRIMARY KEY, entry TEXT NOT NULL, verified INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE product_names (name TEXT PRIMARY KEY, product_id TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE vulns (id TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE aliases (alias TEXT NOT NULL, vuln_id TEXT NOT NULL, PRIMARY KEY (alias, vuln_id)) WITHOUT ROWID;
CREATE TABLE ranges (vuln_id TEXT NOT NULL, product TEXT NOT NULL, source TEXT NOT NULL, json TEXT NOT NULL);
CREATE INDEX ranges_product ON ranges (product);
CREATE INDEX ranges_vuln ON ranges (vuln_id);
CREATE TABLE kev (cve TEXT PRIMARY KEY, json TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE epss (cve TEXT PRIMARY KEY, score REAL NOT NULL, percentile REAL NOT NULL, date TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE ssvc (cve TEXT PRIMARY KEY, exploitation TEXT, automatable INTEGER) WITHOUT ROWID;
CREATE TABLE exploits (cve TEXT NOT NULL, source TEXT NOT NULL, id TEXT NOT NULL, url TEXT);
CREATE INDEX exploits_cve ON exploits (cve);
CREATE TABLE eol (product_id TEXT PRIMARY KEY, json TEXT NOT NULL) WITHOUT ROWID;
";
