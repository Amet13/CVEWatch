//! FIRST EPSS: the daily CSV for every CVE, and the API for one CVE.

use std::io::Read;

use chrono::NaiveDate;
use serde::Deserialize;
use unpatched_core::Epss;

use crate::error::{Result, SourceError};
use crate::http::{Http, maybe_gunzip};
use crate::util::{date_prefix, normalize_cve};

pub const EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
pub const EPSS_API_URL: &str = "https://api.first.org/data/v1/epss";

#[derive(Debug, Clone, PartialEq)]
pub struct EpssFile {
    pub model_version: String,
    pub score_date: NaiveDate,
    pub scores: Vec<(String, Epss)>,
}

/// Parse the EPSS CSV. The input may be gzip or plain text.
pub fn parse_epss(bytes: &[u8]) -> Result<EpssFile> {
    let mut text = String::new();
    if bytes.starts_with(&[0x1f, 0x8b]) {
        flate2::read::MultiGzDecoder::new(bytes)
            .read_to_string(&mut text)
            .map_err(|e| SourceError::parse("the EPSS file", e))?;
    } else {
        text = String::from_utf8_lossy(bytes).into_owned();
    }
    let (first, rest) = text.split_once('\n').unwrap_or((text.as_str(), ""));
    let meta = first.trim().strip_prefix('#').ok_or_else(|| {
        SourceError::parse(
            "the EPSS file",
            "the first line should be a '#model_version:...,score_date:...' comment",
        )
    })?;
    let mut model_version = None;
    let mut score_date = None;
    for part in meta.split(',') {
        match part.split_once(':') {
            Some(("model_version", v)) => model_version = Some(v.trim().to_owned()),
            Some(("score_date", v)) => score_date = date_prefix(v.trim()),
            _ => {}
        }
    }
    let (Some(model_version), Some(score_date)) = (model_version, score_date) else {
        return Err(SourceError::parse(
            "the EPSS file",
            format!("cannot find model_version and score_date in {first:?}"),
        ));
    };

    let mut rdr = csv::ReaderBuilder::new()
        .flexible(false)
        .from_reader(rest.as_bytes());
    let headers = rdr
        .headers()
        .map_err(|e| SourceError::parse("the EPSS file", e))?
        .clone();
    if headers.iter().collect::<Vec<_>>() != ["cve", "epss", "percentile"] {
        return Err(SourceError::parse(
            "the EPSS file",
            format!("unexpected columns {headers:?}"),
        ));
    }
    let mut scores = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| SourceError::parse("the EPSS file", e))?;
        let cve = normalize_cve(&rec[0]).ok_or_else(|| {
            SourceError::parse("the EPSS file", format!("bad CVE id {:?}", &rec[0]))
        })?;
        let score: f32 = rec[1].parse().map_err(|_| {
            SourceError::parse(
                "the EPSS file",
                format!("bad score for {cve}: {:?}", &rec[1]),
            )
        })?;
        let percentile: f32 = rec[2].parse().map_err(|_| {
            SourceError::parse(
                "the EPSS file",
                format!("bad percentile for {cve}: {:?}", &rec[2]),
            )
        })?;
        scores.push((
            cve,
            Epss {
                score,
                percentile,
                date: score_date,
            },
        ));
    }
    Ok(EpssFile {
        model_version,
        score_date,
        scores,
    })
}

pub fn fetch_epss(http: &Http) -> Result<EpssFile> {
    parse_epss(&maybe_gunzip(http.get(EPSS_URL)?)?)
}

#[derive(Deserialize)]
struct ApiResponse {
    #[serde(default)]
    data: Vec<ApiRow>,
}

#[derive(Deserialize)]
struct ApiRow {
    epss: String,
    percentile: String,
    date: String,
}

/// Read the answer of the FIRST API for one CVE. `None` when it has no score.
pub fn parse_epss_api(bytes: &[u8]) -> Result<Option<Epss>> {
    let resp: ApiResponse =
        serde_json::from_slice(bytes).map_err(|e| SourceError::parse("the EPSS API answer", e))?;
    let Some(row) = resp.data.into_iter().next() else {
        return Ok(None);
    };
    let bad = |what: &str, v: &str| {
        SourceError::parse("the EPSS API answer", format!("bad {what} {v:?}"))
    };
    Ok(Some(Epss {
        score: row.epss.parse().map_err(|_| bad("score", &row.epss))?,
        percentile: row
            .percentile
            .parse()
            .map_err(|_| bad("percentile", &row.percentile))?,
        date: date_prefix(&row.date).ok_or_else(|| bad("date", &row.date))?,
    }))
}

/// Ask the FIRST API for one CVE (for ad-hoc use; builds use the daily file).
pub fn fetch_epss_one(http: &Http, cve: &str) -> Result<Option<Epss>> {
    fetch_epss_one_at(http, EPSS_API_URL, cve)
}

pub(crate) fn fetch_epss_one_at(http: &Http, base: &str, cve: &str) -> Result<Option<Epss>> {
    let id = normalize_cve(cve).ok_or_else(|| SourceError::NotFound {
        what: format!("CVE id {cve:?} (it should look like CVE-2024-21762)"),
    })?;
    parse_epss_api(&http.get(&format!("{base}?cve={id}"))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TestServer, fixture};

    #[test]
    fn parses_gz_fixture() {
        let f = parse_epss(&fixture("epss/epss_scores-current.csv.gz")).unwrap();
        assert_eq!(f.model_version, "v2026.06.15");
        assert_eq!(f.score_date, NaiveDate::from_ymd_opt(2026, 11, 23).unwrap());
        assert_eq!(f.scores.len(), 8);
        let (cve, e) = f
            .scores
            .iter()
            .find(|(c, _)| c == "CVE-2024-21762")
            .unwrap();
        assert_eq!(cve, "CVE-2024-21762");
        assert!((e.score - 0.84589).abs() < 1e-6);
        assert!((e.percentile - 0.99711).abs() < 1e-6);
        assert_eq!(e.date, f.score_date);
    }

    #[test]
    fn plain_text_works_too() {
        let csv = "#model_version:v1,score_date:2026-01-02T00:00:00Z\ncve,epss,percentile\nCVE-2020-0001,0.5,0.9\n";
        let f = parse_epss(csv.as_bytes()).unwrap();
        assert_eq!(f.scores.len(), 1);
    }

    #[test]
    fn missing_comment_line_is_an_error() {
        let err = parse_epss(b"cve,epss,percentile\nCVE-2020-0001,0.5,0.9\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("model_version"), "{err}");
    }

    #[test]
    fn api_answer() {
        let json = br#"{"status":"OK","status-code":200,"total":1,"data":[{"cve":"CVE-2024-21762","epss":"0.845890000","percentile":"0.997110000","date":"2026-11-22"}]}"#;
        let e = parse_epss_api(json).unwrap().unwrap();
        assert!((e.score - 0.84589).abs() < 1e-6);
        assert_eq!(e.date, NaiveDate::from_ymd_opt(2026, 11, 22).unwrap());
        assert_eq!(parse_epss_api(br#"{"data":[]}"#).unwrap(), None);
    }

    #[test]
    fn fetch_one_asks_the_api() {
        let srv = TestServer::start(|req| {
            assert_eq!(req.path, "/epss?cve=CVE-2024-21762");
            (
                200,
                br#"{"data":[{"cve":"CVE-2024-21762","epss":"0.1","percentile":"0.2","date":"2026-11-22"}]}"#
                    .to_vec(),
            )
        });
        let http = Http::new().unwrap();
        let e = fetch_epss_one_at(&http, &srv.url("/epss"), "cve-2024-21762")
            .unwrap()
            .unwrap();
        assert!((e.percentile - 0.2).abs() < 1e-6);
        assert!(fetch_epss_one_at(&http, &srv.url("/epss"), "nope").is_err());
    }
}
