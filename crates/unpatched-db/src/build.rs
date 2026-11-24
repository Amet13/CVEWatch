//! Build the database from the sources.
//!
//! A failing source is recorded (`ok = false`, with the error) and the build
//! goes on, except for KEV and NVD: without them the data would silently
//! lack the "exploited" signal or the version ranges, so the build fails and
//! nothing is published.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike, Utc};
use rusqlite::{Connection, params};
use unpatched_core::{
    CatalogEntry, EolCycle, Epss, ExploitRef, SourceId, SourceStatus, SsvcExploitation, VulnStatus,
    Vulnerability,
};
use unpatched_sources::nvd::{NvdFeed, NvdRecord, parse_nvd_meta, records_for};
use unpatched_sources::{CatalogIndex, Http, cve_org, endoflife, epss, exploits, kev, nvd};

use crate::codec::{source_to_str, ssvc_to_str};
use crate::error::{DbError, Result, io_err};
use crate::schema::{CREATE, SCHEMA_VERSION};

#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    /// A `cvelistV5` checkout. `None` skips CVE.org.
    pub cvelist: Option<PathBuf>,
    /// NVD yearly feeds to read. Default: 2002 up to the current year.
    pub nvd_years: Option<RangeInclusive<u16>>,
    /// Keep downloaded NVD feeds here and reuse them when their SHA-256 has not changed.
    pub nvd_cache_dir: Option<PathBuf>,
    /// Where to write. A name ending in `.zst` is compressed (level 19).
    pub out: PathBuf,
    /// Tests: read every source from this directory (laid out like the
    /// repository's `fixtures/`) instead of the network.
    pub offline_fixtures: Option<PathBuf>,
    /// Fail, and write nothing, when any source failed (the daily build uses this, so
    /// a partial database is never published).
    pub strict: bool,
    /// Build time to record. Default: now. Fixed in tests so output is reproducible.
    pub built_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct BuildSummary {
    pub out: PathBuf,
    pub built_at: DateTime<Utc>,
    /// One entry per source, in build order. `records` counts what was stored.
    pub sources: Vec<SourceStatus>,
    pub products: usize,
    pub verified_products: usize,
    pub vulns: usize,
    pub ranges: usize,
    pub kev: usize,
    pub epss: usize,
    pub ssvc: usize,
    pub exploits: usize,
    pub eol_products: usize,
    /// Size of the SQLite file after `VACUUM`.
    pub raw_bytes: u64,
    /// Size of the file written to `out`.
    pub out_bytes: u64,
    pub elapsed: Duration,
}

/// Where the builder reads from.
struct Src<'a> {
    http: &'a Http,
    offline: Option<&'a Path>,
}

impl Src<'_> {
    fn fixture(&self, rel: &str) -> Result<Option<Vec<u8>>> {
        let Some(dir) = self.offline else {
            return Ok(None);
        };
        let path = dir.join(rel);
        std::fs::read(&path).map(Some).map_err(io_err(path))
    }

    fn kev(&self) -> Result<kev::KevCatalog> {
        Ok(
            match self.fixture("kev/known_exploited_vulnerabilities.json")? {
                Some(b) => kev::parse_kev(&b)?,
                None => kev::fetch_kev(self.http)?,
            },
        )
    }

    fn epss(&self) -> Result<epss::EpssFile> {
        Ok(match self.fixture("epss/epss_scores-current.csv.gz")? {
            Some(b) => epss::parse_epss(&b)?,
            None => epss::fetch_epss(self.http)?,
        })
    }

    fn eol(&self, slug: &str) -> Result<Vec<EolCycle>> {
        Ok(match self.fixture(&format!("endoflife/{slug}.json"))? {
            Some(b) => endoflife::parse_eol(&b)?,
            None => endoflife::fetch_eol(self.http, slug)?,
        })
    }

    fn exploitdb(&self) -> Result<Vec<(String, ExploitRef)>> {
        Ok(match self.fixture("exploits/files_exploits.csv")? {
            Some(b) => exploits::parse_exploitdb(&b)?,
            None => exploits::fetch_exploitdb(self.http)?,
        })
    }

    fn metasploit(&self) -> Result<Vec<(String, ExploitRef)>> {
        Ok(match self.fixture("exploits/modules_metadata_base.json")? {
            Some(b) => exploits::parse_metasploit(&b)?,
            None => exploits::fetch_metasploit(self.http)?,
        })
    }
}

fn status(
    source: SourceId,
    records: usize,
    outcome: &std::result::Result<(), String>,
) -> SourceStatus {
    SourceStatus {
        source,
        fetched_at: Utc::now(),
        records: records as u64,
        ok: outcome.is_ok(),
        note: outcome.as_ref().err().cloned(),
    }
}

fn ok_note(source: SourceId, records: usize, note: String) -> SourceStatus {
    SourceStatus {
        note: Some(note),
        ..status(source, records, &Ok(()))
    }
}

/// Everything collected, ready to write.
#[derive(Default)]
struct Data {
    vulns: BTreeMap<String, Vulnerability>,
    kev: Vec<(String, unpatched_core::KevEntry)>,
    epss: Vec<(String, Epss)>,
    ssvc: HashMap<String, (Option<SsvcExploitation>, Option<bool>)>,
    exploits: Vec<(String, ExploitRef)>,
    eol: BTreeMap<String, Vec<EolCycle>>,
}

pub fn build(opts: &BuildOptions, catalog: &[CatalogEntry], http: &Http) -> Result<BuildSummary> {
    let started = Instant::now();
    let built_at = opts.built_at.unwrap_or_else(Utc::now);
    let src = Src {
        http,
        offline: opts.offline_fixtures.as_deref(),
    };
    let index = CatalogIndex::from_catalog(catalog);
    let mut data = Data::default();
    let mut statuses: Vec<SourceStatus> = Vec::new();

    // KEV (required).
    tracing::info!("reading CISA KEV");
    let kev = src.kev().map_err(|e| DbError::RequiredSource {
        source_name: "CISA KEV",
        message: e.to_string(),
    })?;
    statuses.push(status(SourceId::Kev, kev.entries.len(), &Ok(())));
    data.kev = kev.entries;

    // EPSS (optional).
    tracing::info!("reading EPSS");
    match src.epss() {
        Ok(f) => {
            statuses.push(status(SourceId::Epss, f.scores.len(), &Ok(())));
            data.epss = f.scores;
        }
        Err(e) => {
            tracing::warn!("EPSS failed: {e}");
            statuses.push(status(SourceId::Epss, 0, &Err(e.to_string())));
        }
    }

    // NVD (required).
    let nvd_vulns = read_nvd(opts, &src, &index).map_err(|e| DbError::RequiredSource {
        source_name: "NVD",
        message: e.to_string(),
    })?;
    statuses.push(ok_note(
        SourceId::Nvd,
        nvd_vulns.vulns.len(),
        format!(
            "{} feeds, {} records scanned",
            nvd_vulns.feeds, nvd_vulns.scanned
        ),
    ));
    let nvd_ids: HashSet<String> = nvd_vulns.vulns.iter().map(|v| v.id.clone()).collect();
    for v in nvd_vulns.vulns {
        merge_nvd(&mut data.vulns, v);
    }

    // CVE.org (optional).
    match &opts.cvelist {
        None => {
            tracing::info!("no cvelistV5 checkout given: skipping CVE.org");
        }
        Some(dir) => match read_cvelist(dir, &index, &nvd_ids, &mut data) {
            Ok((walked, bad)) => {
                let mut s = status(SourceId::CveOrg, walked, &Ok(()));
                if bad > 0 {
                    s.note = Some(format!("{bad} records could not be read"));
                }
                statuses.push(s);
            }
            Err(e) => {
                tracing::warn!("CVE.org failed: {e}");
                statuses.push(status(SourceId::CveOrg, 0, &Err(e)));
            }
        },
    }

    // Products: verified when at least one range came from their keys.
    let in_ranges: HashSet<&str> = data
        .vulns
        .values()
        .flat_map(|v| v.ranges.iter().map(|r| r.product.as_str()))
        .collect();

    // endoflife.date (optional, per product).
    tracing::info!("reading endoflife.date");
    let mut eol_failed = Vec::new();
    let mut slug_cache: HashMap<String, Vec<EolCycle>> = HashMap::new();
    for entry in catalog {
        let Some(slug) = entry.eol.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        let cycles = if let Some(c) = slug_cache.get(slug) {
            c.clone()
        } else {
            match src.eol(slug) {
                Ok(c) => {
                    slug_cache.insert(slug.to_owned(), c.clone());
                    c
                }
                Err(e) => {
                    tracing::warn!("endoflife.date {slug}: {e}");
                    eol_failed.push(format!("{slug}: {e}"));
                    continue;
                }
            }
        };
        data.eol.insert(entry.id.clone(), cycles);
    }
    let mut s = status(
        SourceId::Endoflife,
        data.eol.len(),
        &if eol_failed.is_empty() {
            Ok(())
        } else {
            Err(eol_failed.join("; "))
        },
    );
    if s.ok && data.eol.is_empty() {
        s.note = Some("no catalog entry has an eol slug".into());
    }
    statuses.push(s);

    // Exploits (optional, each on its own).
    tracing::info!("reading exploit indexes");
    for (id, result) in [
        (SourceId::ExploitDb, src.exploitdb()),
        (SourceId::Metasploit, src.metasploit()),
    ] {
        match result {
            Ok(list) => {
                statuses.push(status(id, list.len(), &Ok(())));
                data.exploits.extend(list);
            }
            Err(e) => {
                tracing::warn!("{id:?} failed: {e}");
                statuses.push(status(id, 0, &Err(e.to_string())));
            }
        }
    }

    if opts.built_at.is_some() {
        for s in &mut statuses {
            s.fetched_at = built_at;
        }
    }

    if opts.strict {
        let failed: Vec<String> = statuses
            .iter()
            .filter(|s| !s.ok)
            .map(|s| format!("{:?}: {}", s.source, s.note.as_deref().unwrap_or("failed")))
            .collect();
        if !failed.is_empty() {
            return Err(DbError::Other(format!(
                "--strict: {} source(s) failed ({}). Run `unpatched db sources-health` and try again later",
                failed.len(),
                failed.join("; ")
            )));
        }
    }

    // Write.
    let out_dir = opts
        .out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    std::fs::create_dir_all(&out_dir).map_err(io_err(&out_dir))?;
    let tmp = tempfile::Builder::new()
        .prefix(".unpatched-build-")
        .suffix(".sqlite")
        .tempfile_in(&out_dir)
        .map_err(io_err(&out_dir))?;
    tracing::info!("writing the database");
    let counts = write_db(tmp.path(), &data, catalog, &in_ranges, &statuses, built_at)?;
    let raw_bytes = std::fs::metadata(tmp.path())
        .map_err(io_err(tmp.path()))?
        .len();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644));
    }
    let is_zst = opts.out.extension().is_some_and(|e| e == "zst");
    if is_zst {
        tracing::info!("compressing (zstd level 19)");
        let zst_tmp = tempfile::Builder::new()
            .prefix(".unpatched-build-")
            .suffix(".zst")
            .tempfile_in(&out_dir)
            .map_err(io_err(&out_dir))?;
        compress(tmp.path(), zst_tmp.path())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(zst_tmp.path(), std::fs::Permissions::from_mode(0o644));
        }
        zst_tmp
            .persist(&opts.out)
            .map_err(|e| io_err(&opts.out)(e.error))?;
    } else {
        tmp.persist(&opts.out)
            .map_err(|e| io_err(&opts.out)(e.error))?;
    }
    let out_bytes = std::fs::metadata(&opts.out)
        .map_err(io_err(&opts.out))?
        .len();

    let summary = BuildSummary {
        out: opts.out.clone(),
        built_at,
        sources: statuses,
        products: catalog.len(),
        verified_products: counts.verified,
        vulns: counts.vulns,
        ranges: counts.ranges,
        kev: counts.kev,
        epss: counts.epss,
        ssvc: counts.ssvc,
        exploits: counts.exploits,
        eol_products: data.eol.len(),
        raw_bytes,
        out_bytes,
        elapsed: started.elapsed(),
    };
    tracing::info!(
        vulns = summary.vulns,
        ranges = summary.ranges,
        raw_bytes,
        out_bytes,
        secs = summary.elapsed.as_secs(),
        "database built"
    );
    Ok(summary)
}

fn compress(raw: &Path, out: &Path) -> Result<()> {
    let input = File::open(raw).map_err(io_err(raw))?;
    let output = BufWriter::new(File::create(out).map_err(io_err(out))?);
    let mut enc = zstd::Encoder::new(output, 19).map_err(io_err(out))?;
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    if let Ok(n) = u32::try_from(threads) {
        enc.multithread(n).map_err(io_err(out))?;
    }
    enc.include_checksum(true).map_err(io_err(out))?;
    std::io::copy(&mut BufReader::new(input), &mut enc).map_err(io_err(out))?;
    let mut w = enc.finish().map_err(io_err(out))?;
    std::io::Write::flush(&mut w).map_err(io_err(out))?;
    Ok(())
}

// ---- NVD ----------------------------------------------------------------

struct NvdResult {
    vulns: Vec<Vulnerability>,
    feeds: usize,
    scanned: u64,
}

fn read_nvd(opts: &BuildOptions, src: &Src, index: &CatalogIndex) -> Result<NvdResult> {
    let keys: HashSet<String> = index.cpe.keys().cloned().collect();
    let mut out = NvdResult {
        vulns: Vec::new(),
        feeds: 0,
        scanned: 0,
    };
    let mut take = |records: Vec<NvdRecord>, scanned: u64| {
        out.feeds += 1;
        out.scanned += scanned;
        for r in records {
            let v = r.to_vulnerability(&index.cpe);
            if !v.ranges.is_empty() {
                out.vulns.push(v);
            }
        }
    };

    if let Some(dir) = src.offline {
        let nvd_dir = dir.join("nvd");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&nvd_dir)
            .map_err(io_err(&nvd_dir))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let n = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                n.starts_with("nvdcve-2.0-") && (n.ends_with("json") || n.ends_with("json.gz"))
            })
            .collect();
        files.sort();
        for path in files {
            tracing::info!(file = %path.display(), "reading NVD fixture");
            let f = BufReader::new(File::open(&path).map_err(io_err(&path))?);
            let gz = path.extension().is_some_and(|e| e == "gz");
            let (recs, info) = if gz {
                records_for(flate2::read::MultiGzDecoder::new(f), &keys)?
            } else {
                records_for(f, &keys)?
            };
            take(recs, info.records);
        }
        return Ok(out);
    }

    let years = opts
        .nvd_years
        .clone()
        .unwrap_or_else(|| 2002..=u16::try_from(Utc::now().year()).unwrap_or(2026));
    if let Some(dir) = &opts.nvd_cache_dir {
        std::fs::create_dir_all(dir).map_err(io_err(dir))?;
    }
    for year in years {
        let feed = NvdFeed::Year(year);
        tracing::info!(%feed, "reading NVD feed");
        let (recs, info) = nvd_year(src.http, feed, opts.nvd_cache_dir.as_deref(), &keys)?;
        tracing::info!(%feed, scanned = info.records, kept = recs.len(), "NVD feed done");
        take(recs, info.records);
    }
    Ok(out)
}

fn nvd_year(
    http: &Http,
    feed: NvdFeed,
    cache: Option<&Path>,
    keys: &HashSet<String>,
) -> Result<(Vec<NvdRecord>, nvd::NvdFeedInfo)> {
    let name = feed.name();
    let Some(cache) = cache else {
        let dl = nvd::fetch_nvd_download(http, feed)?;
        return Ok(records_from_gz(&dl.gz, keys)?);
    };
    let meta_url = format!("{}/{name}.meta", nvd::NVD_FEED_BASE);
    let meta = parse_nvd_meta(&String::from_utf8_lossy(&http.get(&meta_url)?))?;
    let cached = cache.join(format!("{name}.{}.json.gz", meta.sha256));
    if cached.is_file() {
        let f = BufReader::new(File::open(&cached).map_err(io_err(&cached))?);
        match records_for(flate2::read::MultiGzDecoder::new(f), keys) {
            Ok((recs, info)) if info.sha256 == meta.sha256 => {
                tracing::info!(%feed, "NVD feed reused from the cache");
                return Ok((recs, info));
            }
            _ => {
                tracing::warn!(file = %cached.display(), "cached NVD feed is damaged; downloading again");
                let _ = std::fs::remove_file(&cached);
            }
        }
    }
    let dl = nvd::fetch_nvd_download(http, feed)?;
    // Drop older copies of this feed, then keep the new one.
    if let Ok(rd) = std::fs::read_dir(cache) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(&format!("{name}.")) && n.ends_with(".json.gz") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let target = cache.join(format!("{name}.{}.json.gz", dl.meta.sha256));
    let part = cache.join(format!("{name}.part"));
    std::fs::write(&part, &dl.gz).map_err(io_err(&part))?;
    std::fs::rename(&part, &target).map_err(io_err(&target))?;
    Ok(records_from_gz(&dl.gz, keys)?)
}

fn records_from_gz(
    gz: &[u8],
    keys: &HashSet<String>,
) -> unpatched_sources::Result<(Vec<NvdRecord>, nvd::NvdFeedInfo)> {
    records_for(flate2::read::MultiGzDecoder::new(gz), keys)
}

// ---- merging ------------------------------------------------------------

fn merge_nvd(map: &mut BTreeMap<String, Vulnerability>, v: Vulnerability) {
    match map.get_mut(&v.id) {
        None => {
            map.insert(v.id.clone(), v);
        }
        Some(base) => {
            // Same id in two NVD feeds: keep what we have, add the ranges.
            base.ranges.extend(v.ranges);
        }
    }
}

fn status_rank(s: VulnStatus) -> u8 {
    match s {
        VulnStatus::Published => 0,
        VulnStatus::Disputed => 1,
        VulnStatus::Rejected => 2,
    }
}

/// Fold a CVE.org vulnerability into an existing (NVD) one. CVE.org's CNA text,
/// dates and score win when present; ranges from both sources are kept, since
/// the matcher judges each source on its own.
fn merge_cna(base: &mut Vulnerability, cna: Vulnerability) {
    if !cna.summary.is_empty() {
        base.summary = cna.summary;
    }
    base.published = cna.published.or(base.published);
    base.modified = cna.modified.or(base.modified);
    if cna.cvss.is_some() {
        base.cvss = cna.cvss;
    }
    if status_rank(cna.status) > status_rank(base.status) {
        base.status = cna.status;
    }
    for a in cna.aliases {
        if !base.aliases.contains(&a) {
            base.aliases.push(a);
        }
    }
    for r in cna.references {
        if !base.references.iter().any(|x| x.url == r.url) {
            base.references.push(r);
        }
    }
    base.ranges.extend(cna.ranges);
}

/// Returns (records walked, unreadable files).
fn read_cvelist(
    dir: &Path,
    index: &CatalogIndex,
    nvd_ids: &HashSet<String>,
    data: &mut Data,
) -> std::result::Result<(usize, usize), String> {
    if !dir.is_dir() {
        return Err(format!(
            "{} is not a directory. Clone https://github.com/CVEProject/cvelistV5 and pass its path",
            dir.display()
        ));
    }
    tracing::info!(dir = %dir.display(), "walking the CVE list");
    let (mut walked, mut bad) = (0usize, 0usize);
    for rec in cve_org::walk_cvelist_dir(dir) {
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("{e}");
                bad += 1;
                continue;
            }
        };
        walked += 1;
        if rec.ssvc_exploitation.is_some() || rec.ssvc_automatable.is_some() {
            data.ssvc.insert(
                rec.id.clone(),
                (rec.ssvc_exploitation, rec.ssvc_automatable),
            );
        }
        let v = rec.to_vulnerability(index);
        if v.ranges.is_empty() && !nvd_ids.contains(&v.id) {
            continue;
        }
        match data.vulns.get_mut(&v.id) {
            Some(base) => merge_cna(base, v),
            None => {
                data.vulns.insert(v.id.clone(), v);
            }
        }
    }
    if walked == 0 {
        return Err(format!(
            "no CVE-*.json files found under {}. Is it a cvelistV5 checkout?",
            dir.display()
        ));
    }
    Ok((walked, bad))
}

// ---- writing ------------------------------------------------------------

struct Counts {
    vulns: usize,
    ranges: usize,
    kev: usize,
    epss: usize,
    ssvc: usize,
    exploits: usize,
    verified: usize,
}

fn write_db(
    path: &Path,
    data: &Data,
    catalog: &[CatalogEntry],
    in_ranges: &HashSet<&str>,
    statuses: &[SourceStatus],
    built_at: DateTime<Utc>,
) -> Result<Counts> {
    let mut conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA locking_mode = EXCLUSIVE;",
    )?;
    conn.execute_batch(CREATE)?;
    let tx = conn.transaction()?;
    let mut counts = Counts {
        vulns: 0,
        ranges: 0,
        kev: 0,
        epss: 0,
        ssvc: 0,
        exploits: 0,
        verified: 0,
    };

    {
        let mut meta = tx.prepare("INSERT INTO meta (key, value) VALUES (?1, ?2)")?;
        meta.execute(params!["schema_version", SCHEMA_VERSION.to_string()])?;
        meta.execute(params!["built_at", built_at.to_rfc3339()])?;
        meta.execute(params!["sources", serde_json::to_string(statuses)?])?;
        meta.execute(params![
            "builder",
            format!("unpatched-db {}", env!("CARGO_PKG_VERSION"))
        ])?;
    }

    {
        let mut p = tx
            .prepare("INSERT OR REPLACE INTO products (id, entry, verified) VALUES (?1, ?2, ?3)")?;
        let mut n =
            tx.prepare("INSERT OR IGNORE INTO product_names (name, product_id) VALUES (?1, ?2)")?;
        for e in catalog {
            let verified = in_ranges.contains(e.id.as_str());
            counts.verified += usize::from(verified);
            p.execute(params![e.id, serde_json::to_string(e)?, verified])?;
            n.execute(params![e.id.to_ascii_lowercase(), e.id])?;
        }
        for e in catalog {
            for a in &e.aliases {
                n.execute(params![a.to_ascii_lowercase(), e.id])?;
            }
        }
    }

    {
        let mut v = tx.prepare("INSERT OR REPLACE INTO vulns (id, json) VALUES (?1, ?2)")?;
        let mut a = tx.prepare("INSERT OR IGNORE INTO aliases (alias, vuln_id) VALUES (?1, ?2)")?;
        let mut r = tx.prepare(
            "INSERT INTO ranges (vuln_id, product, source, json) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for vuln in data.vulns.values() {
            let mut head = vuln.clone();
            head.ranges.clear();
            v.execute(params![vuln.id, serde_json::to_string(&head)?])?;
            counts.vulns += 1;
            for alias in &vuln.aliases {
                a.execute(params![alias.to_ascii_uppercase(), vuln.id])?;
            }
            for range in &vuln.ranges {
                r.execute(params![
                    vuln.id,
                    range.product,
                    source_to_str(range.source),
                    serde_json::to_string(range)?
                ])?;
                counts.ranges += 1;
            }
        }
    }

    {
        let mut k = tx.prepare("INSERT OR REPLACE INTO kev (cve, json) VALUES (?1, ?2)")?;
        for (cve, e) in &data.kev {
            k.execute(params![cve, serde_json::to_string(e)?])?;
            counts.kev += 1;
        }
        let mut s = tx.prepare(
            "INSERT OR REPLACE INTO epss (cve, score, percentile, date) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (cve, e) in &data.epss {
            s.execute(params![cve, e.score, e.percentile, e.date.to_string()])?;
            counts.epss += 1;
        }
    }

    {
        // SSVC for every CVE we store a vulnerability for, and for all of KEV.
        let kev_ids: HashSet<&str> = data.kev.iter().map(|(c, _)| c.as_str()).collect();
        let mut s = tx.prepare(
            "INSERT OR REPLACE INTO ssvc (cve, exploitation, automatable) VALUES (?1, ?2, ?3)",
        )?;
        let mut ids: Vec<&String> = data.ssvc.keys().collect();
        ids.sort();
        for cve in ids {
            if !data.vulns.contains_key(cve) && !kev_ids.contains(cve.as_str()) {
                continue;
            }
            let (exploitation, automatable) = data.ssvc[cve];
            s.execute(params![cve, exploitation.map(ssvc_to_str), automatable])?;
            counts.ssvc += 1;
        }
    }

    {
        let mut x =
            tx.prepare("INSERT INTO exploits (cve, source, id, url) VALUES (?1, ?2, ?3, ?4)")?;
        for (cve, e) in &data.exploits {
            x.execute(params![cve, source_to_str(e.source), e.id, e.url])?;
            counts.exploits += 1;
        }
        let mut o = tx.prepare("INSERT OR REPLACE INTO eol (product_id, json) VALUES (?1, ?2)")?;
        for (id, cycles) in &data.eol {
            o.execute(params![id, serde_json::to_string(cycles)?])?;
        }
    }

    tx.commit()?;
    conn.execute_batch("PRAGMA journal_mode = DELETE;")?;
    conn.execute_batch("VACUUM;")?;
    conn.close().map_err(|(_, e)| e)?;
    // Make sure the file ends up closed and complete before it is moved.
    let mut probe = [0u8; 16];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut probe))
        .map_err(io_err(path))?;
    Ok(counts)
}
