//! NVD CVE JSON 2.0 bulk feeds (yearly files and the `modified` feed).
//!
//! The files are big (hundreds of MB unpacked). They are read as a stream, one
//! record at a time, into structs that keep only the fields we use, so memory
//! stays small. The SHA-256 in the `.meta` file is checked over the unpacked JSON.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as _};
use std::io::{self, BufReader, Read};

use chrono::NaiveDate;
use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use unpatched_core::{
    AffectedRange, Bound, Constraint, Cvss, Reference, SourceId, VulnStatus, Vulnerability,
};

use crate::error::{Result, SourceError};
use crate::http::Http;
use crate::util::{date_prefix, push_unique};

pub const NVD_FEED_BASE: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";

/// One feed file on nvd.nist.gov.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvdFeed {
    /// `nvdcve-2.0-<year>` (2002 and later).
    Year(u16),
    /// Records changed in the last 8 days, rebuilt every 2 hours.
    Modified,
    /// Records added in the last 8 days.
    Recent,
}

impl NvdFeed {
    /// File name without extension, such as `nvdcve-2.0-2024`.
    pub fn name(self) -> String {
        match self {
            Self::Year(y) => format!("nvdcve-2.0-{y}"),
            Self::Modified => "nvdcve-2.0-modified".to_owned(),
            Self::Recent => "nvdcve-2.0-recent".to_owned(),
        }
    }

    /// Every yearly feed from 2002 to `current_year`.
    pub fn years(current_year: u16) -> impl Iterator<Item = Self> {
        (2002..=current_year).map(Self::Year)
    }
}

impl fmt::Display for NvdFeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

/// The `.meta` file next to each feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvdMeta {
    pub last_modified: String,
    /// Size of the unpacked JSON in bytes.
    pub size: u64,
    pub gz_size: u64,
    /// SHA-256 of the unpacked JSON, lower-case hex.
    pub sha256: String,
}

pub fn parse_nvd_meta(text: &str) -> Result<NvdMeta> {
    let what = "an NVD .meta file";
    let mut fields: HashMap<&str, &str> = HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            fields.insert(k.trim(), v.trim());
        }
    }
    let get = |k: &str| {
        fields
            .get(k)
            .copied()
            .ok_or_else(|| SourceError::parse(what, format!("no '{k}' line")))
    };
    let num = |k: &str| {
        get(k)?
            .parse::<u64>()
            .map_err(|_| SourceError::parse(what, format!("'{k}' is not a number")))
    };
    Ok(NvdMeta {
        last_modified: get("lastModifiedDate")?.to_owned(),
        size: num("size")?,
        gz_size: num("gzSize")?,
        sha256: get("sha256")?.to_ascii_lowercase(),
    })
}

/// One affected-software statement of a record, reduced to a product and a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeRange {
    /// `vendor:product`, lower case, as in the CPE name.
    pub vendor_product: String,
    /// CPE part: `a` (application), `o` (operating system) or `h` (hardware).
    pub part: String,
    pub constraint: Constraint,
    /// The CPE name and bounds as NVD wrote them, for `explain`.
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NvdRecord {
    pub id: String,
    pub status: VulnStatus,
    /// English description.
    pub summary: String,
    pub published: Option<NaiveDate>,
    pub modified: Option<NaiveDate>,
    /// Best score: v4.0, then v3.1, v3.0, v2; NVD's own (primary) first.
    pub cvss: Option<Cvss>,
    pub references: Vec<Reference>,
    /// Only `vulnerable: true` matches; platform context is left out.
    pub cpe_ranges: Vec<CpeRange>,
}

impl NvdRecord {
    /// Make a core [`Vulnerability`]. `cpe_to_products` maps `vendor:product`
    /// to catalog ids (see [`crate::CatalogIndex`]); ranges for products the
    /// catalog does not know are left out, so the result may have no ranges.
    pub fn to_vulnerability(
        &self,
        cpe_to_products: &HashMap<String, Vec<String>>,
    ) -> Vulnerability {
        let mut ranges: Vec<AffectedRange> = Vec::new();
        for r in &self.cpe_ranges {
            let Some(products) = cpe_to_products.get(&r.vendor_product) else {
                continue;
            };
            for product in products {
                let idx = if let Some(i) = ranges.iter().position(|a| a.product == *product) {
                    i
                } else {
                    ranges.push(AffectedRange {
                        source: SourceId::Nvd,
                        product: product.clone(),
                        constraints: Vec::new(),
                        unaffected: Vec::new(),
                        raw: String::new(),
                    });
                    ranges.len() - 1
                };
                let a = &mut ranges[idx];
                push_unique(&mut a.constraints, r.constraint.clone());
                if !a.raw.is_empty() {
                    a.raw.push('\n');
                }
                a.raw.push_str(&r.raw);
            }
        }
        Vulnerability {
            id: self.id.clone(),
            aliases: Vec::new(),
            summary: self.summary.clone(),
            published: self.published,
            modified: self.modified,
            status: self.status,
            cvss: self.cvss.clone(),
            ranges,
            references: self.references.clone(),
        }
    }
}

// ---- raw JSON shapes: only the fields we keep ----

#[derive(Deserialize)]
struct RawVuln {
    cve: RawCve,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCve {
    id: String,
    #[serde(default)]
    vuln_status: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    descriptions: Vec<RawText>,
    #[serde(default)]
    metrics: RawMetrics,
    #[serde(default)]
    references: Vec<RawRef>,
    #[serde(default)]
    configurations: Vec<RawConfig>,
    #[serde(default)]
    cve_tags: Vec<RawTags>,
}

#[derive(Deserialize)]
struct RawText {
    lang: String,
    value: String,
}

#[derive(Deserialize)]
struct RawTags {
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawMetrics {
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<RawMetric>,
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<RawMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<RawMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<RawMetric>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMetric {
    #[serde(default)]
    source: String,
    #[serde(default, rename = "type")]
    kind: String,
    cvss_data: RawCvssData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCvssData {
    version: String,
    #[serde(default)]
    vector_string: Option<String>,
    base_score: f32,
}

#[derive(Deserialize)]
struct RawRef {
    url: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    nodes: Vec<RawNode>,
}

#[derive(Deserialize)]
struct RawNode {
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<RawMatch>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMatch {
    vulnerable: bool,
    criteria: String,
    #[serde(default)]
    version_start_including: Option<String>,
    #[serde(default)]
    version_start_excluding: Option<String>,
    #[serde(default)]
    version_end_including: Option<String>,
    #[serde(default)]
    version_end_excluding: Option<String>,
}

/// Split a CPE 2.3 name at unescaped colons and drop the escaping backslashes.
fn split_cpe(s: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    parts.last_mut().unwrap().push(n);
                }
            }
            ':' => parts.push(String::new()),
            _ => parts.last_mut().unwrap().push(c),
        }
    }
    parts
}

fn cpe_range(m: &RawMatch) -> Option<CpeRange> {
    if !m.vulnerable {
        return None;
    }
    let parts = split_cpe(&m.criteria);
    if parts.len() < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
        tracing::debug!(criteria = %m.criteria, "skipping a CPE name that is not 2.3 formatted");
        return None;
    }
    let version = parts[5].as_str();
    let update = parts.get(6).map_or("*", String::as_str);

    let start = match (&m.version_start_including, &m.version_start_excluding) {
        (Some(v), _) => Some(Bound {
            version: v.clone(),
            inclusive: true,
        }),
        (None, Some(v)) => Some(Bound {
            version: v.clone(),
            inclusive: false,
        }),
        _ => None,
    };
    let end = match (&m.version_end_including, &m.version_end_excluding) {
        (Some(v), _) => Some(Bound {
            version: v.clone(),
            inclusive: true,
        }),
        (None, Some(v)) => Some(Bound {
            version: v.clone(),
            inclusive: false,
        }),
        _ => None,
    };

    let mut raw = m.criteria.clone();
    if let Some(b) = &start {
        let _ = write!(
            raw,
            " {}{}",
            if b.inclusive { ">=" } else { ">" },
            b.version
        );
    }
    if let Some(b) = &end {
        let _ = write!(
            raw,
            " {}{}",
            if b.inclusive { "<=" } else { "<" },
            b.version
        );
    }

    let constraint = if start.is_some() || end.is_some() {
        Constraint::Range { start, end }
    } else if version == "*" {
        Constraint::All
    } else if version == "-" {
        raw.push_str(" (version '-' means not applicable; treated as all versions)");
        Constraint::All
    } else if version.is_empty() {
        Constraint::All
    } else {
        if update != "*" && update != "-" && !update.is_empty() {
            let _ = write!(raw, " (update '{update}' ignored)");
        }
        Constraint::Exact {
            version: version.to_owned(),
        }
    };
    Some(CpeRange {
        vendor_product: format!("{}:{}", parts[3], parts[4]).to_ascii_lowercase(),
        part: parts[2].clone(),
        constraint,
        raw,
    })
}

fn pick_cvss(m: &RawMetrics) -> Option<Cvss> {
    for list in [&m.v40, &m.v31, &m.v30, &m.v2] {
        // min_by_key keeps the first of equals: NVD's primary score wins.
        let best = list
            .iter()
            .min_by_key(|x| (x.kind != "Primary", x.source != "nvd@nist.gov"));
        if let Some(x) = best {
            return Some(Cvss {
                version: x.cvss_data.version.clone(),
                score: x.cvss_data.base_score,
                vector: x.cvss_data.vector_string.clone(),
            });
        }
    }
    None
}

impl From<RawVuln> for NvdRecord {
    fn from(v: RawVuln) -> Self {
        let c = v.cve;
        let disputed = c
            .cve_tags
            .iter()
            .any(|t| t.tags.iter().any(|t| t == "disputed"));
        let status = match c.vuln_status.as_deref() {
            Some("Rejected") => VulnStatus::Rejected,
            _ if disputed => VulnStatus::Disputed,
            _ => VulnStatus::Published,
        };
        let summary = c
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .or_else(|| c.descriptions.first())
            .map(|d| d.value.clone())
            .unwrap_or_default();
        let cpe_ranges = c
            .configurations
            .iter()
            .flat_map(|cf| &cf.nodes)
            .flat_map(|n| &n.cpe_match)
            .filter_map(cpe_range)
            .collect();
        Self {
            cvss: pick_cvss(&c.metrics),
            status,
            summary,
            published: c.published.as_deref().and_then(date_prefix),
            modified: c.last_modified.as_deref().and_then(date_prefix),
            references: c
                .references
                .into_iter()
                .map(|r| Reference {
                    url: r.url,
                    tags: r.tags,
                })
                .collect(),
            cpe_ranges,
            id: c.id,
        }
    }
}

/// Facts about a parsed feed file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvdFeedInfo {
    /// The `timestamp` field of the file.
    pub timestamp: Option<String>,
    /// How many records the file holds.
    pub records: u64,
    /// SHA-256 of the unpacked JSON, lower-case hex.
    pub sha256: String,
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

struct FeedSeed<'a, F> {
    on_record: &'a mut F,
    info: &'a mut NvdFeedInfo,
}

impl<'de, F: FnMut(NvdRecord)> DeserializeSeed<'de> for FeedSeed<'_, F> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de, F: FnMut(NvdRecord)> Visitor<'de> for FeedSeed<'_, F> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an NVD CVE 2.0 feed object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "vulnerabilities" => map.next_value_seed(RecordsSeed {
                    on_record: &mut *self.on_record,
                    count: &mut self.info.records,
                })?,
                "timestamp" => self.info.timestamp = Some(map.next_value()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct RecordsSeed<'a, F> {
    on_record: &'a mut F,
    count: &'a mut u64,
}

impl<'de, F: FnMut(NvdRecord)> DeserializeSeed<'de> for RecordsSeed<'_, F> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de, F: FnMut(NvdRecord)> Visitor<'de> for RecordsSeed<'_, F> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of NVD records")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        while let Some(raw) = seq.next_element::<RawVuln>()? {
            *self.count += 1;
            (self.on_record)(raw.into());
        }
        Ok(())
    }
}

/// Read an unpacked NVD feed from `reader`, calling `on_record` for each
/// record as it is parsed. The whole file is read so the returned checksum
/// covers it all.
pub fn parse_nvd_feed<R: Read>(
    reader: R,
    mut on_record: impl FnMut(NvdRecord),
) -> Result<NvdFeedInfo> {
    let what = "an NVD feed";
    let mut hr = HashingReader {
        inner: reader,
        hasher: Sha256::new(),
    };
    let mut info = NvdFeedInfo::default();
    {
        let buffered = BufReader::with_capacity(1 << 16, &mut hr);
        let mut de = serde_json::Deserializer::from_reader(buffered);
        FeedSeed {
            on_record: &mut on_record,
            info: &mut info,
        }
        .deserialize(&mut de)
        .map_err(|e| SourceError::parse(what, e))?;
        de.end().map_err(|e| SourceError::parse(what, e))?;
    }
    io::copy(&mut hr, &mut io::sink()).map_err(|e| SourceError::parse(what, e))?;
    info.sha256 = hex::encode(hr.hasher.finalize());
    Ok(info)
}

/// Like [`parse_nvd_feed`] for a gzip file held in memory.
pub fn parse_nvd_feed_gz(gz: &[u8], on_record: impl FnMut(NvdRecord)) -> Result<NvdFeedInfo> {
    parse_nvd_feed(flate2::read::MultiGzDecoder::new(gz), on_record)
}

/// Read a feed and keep the records that have at least one range for a product
/// in `keys` (`vendor:product`, lower case). Each kept record holds only the
/// ranges of those products.
pub fn records_for<R: Read>(
    reader: R,
    keys: &HashSet<String>,
) -> Result<(Vec<NvdRecord>, NvdFeedInfo)> {
    let mut out = Vec::new();
    let info = parse_nvd_feed(reader, |mut rec| {
        rec.cpe_ranges.retain(|r| keys.contains(&r.vendor_product));
        if !rec.cpe_ranges.is_empty() {
            out.push(rec);
        }
    })?;
    Ok((out, info))
}

/// A feed downloaded and checked against its `.meta` file.
#[derive(Debug, Clone)]
pub struct NvdDownload {
    pub meta: NvdMeta,
    /// The gzip file as served; unpack it with [`parse_nvd_feed_gz`].
    pub gz: Vec<u8>,
}

/// Download a feed and verify the SHA-256 of its unpacked JSON. If the checksum
/// does not match (the feed was rebuilt between the two requests), the `.meta`
/// file is read once more before giving up.
pub fn fetch_nvd_download(http: &Http, feed: NvdFeed) -> Result<NvdDownload> {
    fetch_nvd_download_at(http, NVD_FEED_BASE, feed)
}

pub(crate) fn fetch_nvd_download_at(http: &Http, base: &str, feed: NvdFeed) -> Result<NvdDownload> {
    let name = feed.name();
    let gz = http.get(&format!("{base}/{name}.json.gz"))?;
    let mut last = None;
    for _ in 0..2 {
        let meta = parse_nvd_meta(&String::from_utf8_lossy(
            &http.get(&format!("{base}/{name}.meta"))?,
        ))?;
        let actual = hash_unpacked(&gz, &name)?;
        if actual == meta.sha256 {
            return Ok(NvdDownload { meta, gz });
        }
        last = Some(SourceError::Checksum {
            what: format!("{name}.json.gz"),
            expected: meta.sha256,
            actual,
        });
    }
    Err(last.expect("loop runs at least once"))
}

fn hash_unpacked(gz: &[u8], name: &str) -> Result<String> {
    let mut hr = HashingReader {
        inner: flate2::read::MultiGzDecoder::new(gz),
        hasher: Sha256::new(),
    };
    io::copy(&mut hr, &mut io::sink())
        .map_err(|e| SourceError::parse(format!("{name}.json.gz"), e))?;
    Ok(hex::encode(hr.hasher.finalize()))
}

/// Download, verify and parse one feed, calling `on_record` per record.
pub fn fetch_nvd_feed(
    http: &Http,
    feed: NvdFeed,
    on_record: impl FnMut(NvdRecord),
) -> Result<(NvdMeta, NvdFeedInfo)> {
    let dl = fetch_nvd_download(http, feed)?;
    let info = parse_nvd_feed_gz(&dl.gz, on_record)?;
    Ok((dl.meta, info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TestServer, fixture};
    use std::io::Write;

    fn slice() -> Vec<NvdRecord> {
        let mut v = Vec::new();
        parse_nvd_feed(fixture("nvd/nvdcve-2.0-slice.json").as_slice(), |r| {
            v.push(r);
        })
        .unwrap();
        v
    }

    fn get<'a>(v: &'a [NvdRecord], id: &str) -> &'a NvdRecord {
        v.iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id}"))
    }

    fn range(start: Option<(&str, bool)>, end: Option<(&str, bool)>) -> Constraint {
        let b = |(v, i): (&str, bool)| Bound {
            version: v.to_owned(),
            inclusive: i,
        };
        Constraint::Range {
            start: start.map(b),
            end: end.map(b),
        }
    }

    #[test]
    fn fortios_ranges() {
        let recs = slice();
        let r = get(&recs, "CVE-2024-21762");
        assert_eq!(r.status, VulnStatus::Published);
        assert!(r.summary.contains("out-of-bounds write"));
        let fortios: Vec<_> = r
            .cpe_ranges
            .iter()
            .filter(|c| c.vendor_product == "fortinet:fortios")
            .collect();
        assert!(fortios.len() >= 6);
        assert_eq!(fortios[0].part, "o");
        assert_eq!(
            fortios[0].constraint,
            range(Some(("6.0.0", true)), Some(("6.0.18", false)))
        );
        assert!(fortios[0].raw.starts_with("cpe:2.3:o:fortinet:fortios:"));
        assert!(
            r.cpe_ranges
                .iter()
                .any(|c| c.vendor_product == "fortinet:fortiproxy")
        );
        let cvss = r.cvss.as_ref().unwrap();
        assert_eq!(cvss.version, "3.1");
        assert!((cvss.score - 9.8).abs() < 0.01);
        assert!(cvss.vector.as_deref().unwrap().starts_with("CVSS:3.1/"));
        assert_eq!(r.published, NaiveDate::from_ymd_opt(2024, 2, 9));
        assert!(!r.references.is_empty());
    }

    #[test]
    fn rejected_record() {
        let recs = slice();
        let r = get(&recs, "CVE-2024-0069");
        assert_eq!(r.status, VulnStatus::Rejected);
        assert!(r.cpe_ranges.is_empty());
        assert!(r.summary.starts_with("Rejected reason"));
    }

    #[test]
    fn exact_versions_and_platform_context_ignored() {
        let recs = slice();
        // CVE-2024-0291: a firmware version (vulnerable) running on hardware (not vulnerable)
        let r = get(&recs, "CVE-2024-0291");
        assert_eq!(r.cpe_ranges.len(), 1);
        assert_eq!(r.cpe_ranges[0].vendor_product, "totolink:lr1200gb_firmware");
        assert_eq!(
            r.cpe_ranges[0].constraint,
            Constraint::Exact {
                version: "9.1.0u.6619_b20230130".into()
            }
        );
        // v4.0 is preferred over v3.1 and v2
        let r = get(&recs, "CVE-2024-0545");
        assert_eq!(r.cvss.as_ref().unwrap().version, "4.0");
    }

    #[test]
    fn mixed_range_and_exact_in_one_record() {
        let recs = slice();
        let r = get(&recs, "CVE-2024-0204");
        let ranges: Vec<_> = r.cpe_ranges.iter().map(|c| &c.constraint).collect();
        assert!(ranges.contains(&&range(Some(("7.0.0", true)), Some(("7.4.1", false)))));
        assert!(ranges.contains(&&Constraint::Exact {
            version: "6.0.0".into()
        }));
    }

    fn one(json: &str) -> NvdRecord {
        let wrapped = format!(r#"{{"vulnerabilities":[{json}]}}"#);
        let mut v = Vec::new();
        parse_nvd_feed(wrapped.as_bytes(), |r| v.push(r)).unwrap();
        v.pop().unwrap()
    }

    #[test]
    fn star_dash_and_bounds() {
        let r = one(
            r#"{"cve":{"id":"CVE-2020-1","descriptions":[{"lang":"es","value":"hola"},{"lang":"en","value":"hello"}],
            "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
              {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
              {"vulnerable":true,"criteria":"cpe:2.3:o:acme:os:-:*:*:*:*:*:*:*"},
              {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionStartExcluding":"1.0","versionEndIncluding":"1.5"},
              {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionEndExcluding":"0.9"},
              {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:2.0\\:rc1:beta:*:*:*:*:*:*"},
              {"vulnerable":false,"criteria":"cpe:2.3:h:acme:box:-:*:*:*:*:*:*:*"}
            ]}]}]}}"#,
        );
        assert_eq!(r.summary, "hello");
        let c: Vec<_> = r.cpe_ranges.iter().map(|c| c.constraint.clone()).collect();
        assert_eq!(
            c,
            vec![
                Constraint::All,
                Constraint::All,
                range(Some(("1.0", false)), Some(("1.5", true))),
                range(None, Some(("0.9", false))),
                Constraint::Exact {
                    version: "2.0:rc1".into()
                },
            ]
        );
        assert!(r.cpe_ranges[1].raw.contains("not applicable"));
        assert!(r.cpe_ranges[4].raw.contains("update 'beta' ignored"));
        assert_eq!(r.cpe_ranges[1].part, "o");
    }

    #[test]
    fn disputed_tag() {
        let r = one(
            r#"{"cve":{"id":"CVE-2020-2","vulnStatus":"Analyzed","cveTags":[{"sourceIdentifier":"x","tags":["disputed"]}]}}"#,
        );
        assert_eq!(r.status, VulnStatus::Disputed);
    }

    #[test]
    fn primary_nvd_score_wins() {
        let r = one(r#"{"cve":{"id":"CVE-2020-3","metrics":{"cvssMetricV31":[
              {"source":"cna@x","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":5.0}},
              {"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:L","baseScore":7.5}}]}}}"#);
        assert!((r.cvss.unwrap().score - 7.5).abs() < 0.01);
    }

    #[test]
    fn records_for_filters_records_and_ranges() {
        let keys: HashSet<String> = ["fortinet:fortios".to_owned()].into();
        let (recs, info) =
            records_for(fixture("nvd/nvdcve-2.0-slice.json").as_slice(), &keys).unwrap();
        assert_eq!(info.records, 7);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, "CVE-2024-21762");
        assert!(
            recs[0]
                .cpe_ranges
                .iter()
                .all(|r| r.vendor_product == "fortinet:fortios")
        );
    }

    #[test]
    fn to_vulnerability_groups_by_catalog_id() {
        let recs = slice();
        let r = get(&recs, "CVE-2024-21762");
        let mut map = HashMap::new();
        map.insert("fortinet:fortios".to_owned(), vec!["fortios".to_owned()]);
        let v = r.to_vulnerability(&map);
        assert_eq!(v.id, "CVE-2024-21762");
        assert_eq!(v.ranges.len(), 1);
        let a = &v.ranges[0];
        assert_eq!(a.source, SourceId::Nvd);
        assert_eq!(a.product, "fortios");
        assert!(a.constraints.len() >= 6);
        assert!(a.raw.contains("cpe:2.3:o:fortinet:fortios"));
        assert!(v.cvss.is_some());
        // unknown products give no ranges
        assert!(r.to_vulnerability(&HashMap::new()).ranges.is_empty());
    }

    #[test]
    fn meta_file() {
        let m =
            parse_nvd_meta(&String::from_utf8(fixture("nvd/nvdcve-2.0-modified.meta")).unwrap())
                .unwrap();
        assert_eq!(m.size, 48_858_987);
        assert_eq!(
            m.sha256,
            "8915007ad63d2b1e47590af787fe58182ecab8383cfe42292aa0a90d4d9ebdab"
        );
        assert!(parse_nvd_meta("size:1").is_err());
    }

    #[test]
    fn feed_names() {
        assert_eq!(NvdFeed::Year(2024).name(), "nvdcve-2.0-2024");
        assert_eq!(NvdFeed::Modified.to_string(), "nvdcve-2.0-modified");
        assert_eq!(NvdFeed::years(2004).count(), 3);
    }

    #[test]
    fn broken_json_is_a_clear_error() {
        let err = parse_nvd_feed(&b"{\"vulnerabilities\":[{\"cve\":"[..], |_| {})
            .unwrap_err()
            .to_string();
        assert!(err.contains("NVD feed"), "{err}");
    }

    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn feed_server(json: &[u8], sha: &str) -> TestServer {
        let packed = gz(json);
        let meta = format!(
            "lastModifiedDate:2026-11-23T03:01:56-05:00\nsize:{}\nzipSize:{}\ngzSize:{}\nsha256:{}\n",
            json.len(),
            packed.len(),
            packed.len(),
            sha.to_ascii_uppercase()
        );
        TestServer::start(move |req| match req.path.as_str() {
            "/f/nvdcve-2.0-2024.json.gz" => (200, packed.clone()),
            "/f/nvdcve-2.0-2024.meta" => (200, meta.clone().into_bytes()),
            _ => (404, Vec::new()),
        })
    }

    #[test]
    fn download_verifies_checksum() {
        let json = fixture("nvd/nvdcve-2.0-slice.json");
        let sha = hex::encode(Sha256::digest(&json));
        let srv = feed_server(&json, &sha);
        let http = Http::new().unwrap();
        let dl = fetch_nvd_download_at(&http, &srv.url("/f"), NvdFeed::Year(2024)).unwrap();
        let mut n = 0;
        let info = parse_nvd_feed_gz(&dl.gz, |_| n += 1).unwrap();
        assert_eq!(n, 7);
        assert_eq!(info.sha256, dl.meta.sha256);
    }

    #[test]
    fn download_rejects_wrong_checksum() {
        let json = fixture("nvd/nvdcve-2.0-slice.json");
        let srv = feed_server(&json, &"00".repeat(32));
        let http = Http::new().unwrap();
        let err = fetch_nvd_download_at(&http, &srv.url("/f"), NvdFeed::Year(2024)).unwrap_err();
        assert!(matches!(err, SourceError::Checksum { .. }), "{err}");
        assert!(err.to_string().contains("run it again"));
    }
}
