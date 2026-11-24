//! Read access to a built database, as a [`Dataset`].

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, NaiveDate, Utc};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use sha2::{Digest, Sha256};
use unpatched_core::{
    AffectedRange, CatalogEntry, Dataset, DbInfo, EolCycle, Epss, ExploitRef, KevEntry, Signals,
    SourceStatus, Vulnerability,
};

use crate::codec::{source_from_str, ssvc_from_str};
use crate::error::{DbError, Result, io_err};
use crate::schema::SCHEMA_VERSION;

/// An open database. Read only.
#[derive(Debug)]
pub struct Db {
    conn: Mutex<Connection>,
    path: PathBuf,
    info: DbInfo,
}

impl Db {
    /// Open a `.sqlite` file, or a `.sqlite.zst` (unpacked once next to it, or
    /// under the temp directory when that is not writable, and reused while
    /// the compressed file is unchanged).
    pub fn open(path: &Path) -> Result<Db> {
        if !path.is_file() {
            return Err(DbError::NotADatabase {
                path: path.to_path_buf(),
                reason: "no such file".into(),
            });
        }
        let file = if path.extension().is_some_and(|e| e == "zst") {
            unpack_cached(path)?
        } else {
            path.to_path_buf()
        };
        let conn = Connection::open_with_flags(
            &file,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let not_db = |reason: String| DbError::NotADatabase {
            path: path.to_path_buf(),
            reason,
        };
        let meta = |key: &str| -> Result<Option<String>> {
            conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
                .optional()
                .map_err(|e| not_db(e.to_string()))
        };
        let version: u32 = meta("schema_version")?
            .ok_or_else(|| not_db("it has no schema_version".into()))?
            .parse()
            .map_err(|_| not_db("schema_version is not a number".into()))?;
        if version > SCHEMA_VERSION {
            return Err(DbError::NewerSchema {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        if version == 0 {
            return Err(not_db("schema_version is 0".into()));
        }
        let built_at: DateTime<Utc> = meta("built_at")?
            .ok_or_else(|| not_db("it has no built_at".into()))
            .and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| not_db(format!("built_at: {e}")))
            })?;
        let sources: Vec<SourceStatus> = match meta("sources")? {
            Some(s) => serde_json::from_str(&s)?,
            None => Vec::new(),
        };
        Ok(Db {
            conn: Mutex::new(conn),
            path: file,
            info: DbInfo {
                schema_version: version,
                built_at,
                sources,
            },
        })
    }

    /// The SQLite file in use (the unpacked copy for a `.zst`).
    pub fn file(&self) -> &Path {
        &self.path
    }

    pub fn info(&self) -> DbInfo {
        self.info.clone()
    }

    /// Catalog ids stored in the database, sorted.
    pub fn product_ids(&self) -> Vec<String> {
        self.collect("SELECT id FROM products ORDER BY id", [], |r| r.get(0))
    }

    /// Every catalog entry with its `verified` flag, sorted by id.
    pub fn products(&self) -> Vec<(CatalogEntry, bool)> {
        self.collect(
            "SELECT entry, verified FROM products ORDER BY id",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
        )
        .into_iter()
        .filter_map(|(json, v)| serde_json::from_str(&json).ok().map(|e| (e, v)))
        .collect()
    }

    /// One vulnerability with all its ranges, by id (case-insensitive).
    pub fn vuln(&self, id: &str) -> Option<Vulnerability> {
        let id = id.trim().to_ascii_uppercase();
        let conn = self.conn();
        match load_vuln(&conn, &id) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("reading {id}: {e}");
                None
            }
        }
    }

    /// Vulnerabilities that list `alias` (a GHSA or other id) as an alias.
    pub fn vulns_by_alias(&self, alias: &str) -> Vec<Vulnerability> {
        let alias = alias.trim().to_ascii_uppercase();
        let ids: Vec<String> = self.collect(
            "SELECT vuln_id FROM aliases WHERE alias = ?1 ORDER BY vuln_id",
            [alias],
            |r| r.get(0),
        );
        ids.iter().filter_map(|id| self.vuln(id)).collect()
    }

    /// Ids of every stored vulnerability, sorted. For tools and tests.
    pub fn vuln_ids(&self) -> Vec<String> {
        self.collect("SELECT id FROM vulns ORDER BY id", [], |r| r.get(0))
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Run a query and collect the rows. A failing query is logged and gives
    /// no rows: the trait this serves cannot return errors.
    fn collect<T, P: rusqlite::Params>(
        &self,
        sql: &str,
        p: P,
        f: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Vec<T> {
        let conn = self.conn();
        let run = || -> rusqlite::Result<Vec<T>> {
            conn.prepare_cached(sql)?
                .query_map(p, f)?
                .collect::<rusqlite::Result<Vec<T>>>()
        };
        run().unwrap_or_else(|e| {
            tracing::error!("database query failed: {e}");
            Vec::new()
        })
    }

    fn json_rows<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        p: impl rusqlite::Params,
    ) -> Vec<T> {
        self.collect(sql, p, |r| r.get::<_, String>(0))
            .into_iter()
            .filter_map(|s| match serde_json::from_str(&s) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::error!("bad JSON in the database: {e}");
                    None
                }
            })
            .collect()
    }
}

fn load_vuln(conn: &Connection, id: &str) -> Result<Option<Vulnerability>> {
    let Some(json) = conn
        .query_row("SELECT json FROM vulns WHERE id = ?1", [id], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
    else {
        return Ok(None);
    };
    let mut v: Vulnerability = serde_json::from_str(&json)?;
    let mut st =
        conn.prepare_cached("SELECT json FROM ranges WHERE vuln_id = ?1 ORDER BY rowid")?;
    let rows = st.query_map([id], |r| r.get::<_, String>(0))?;
    for row in rows {
        v.ranges.push(serde_json::from_str::<AffectedRange>(&row?)?);
    }
    Ok(Some(v))
}

impl Dataset for Db {
    fn product(&self, id: &str) -> Option<CatalogEntry> {
        let name = id.trim().to_ascii_lowercase();
        let json: Option<String> = self
            .collect(
                "SELECT p.entry FROM product_names n JOIN products p ON p.id = n.product_id \
                 WHERE n.name = ?1",
                [name],
                |r| r.get(0),
            )
            .into_iter()
            .next();
        serde_json::from_str(&json?).ok()
    }

    fn vulns_for_product(&self, product_id: &str) -> Vec<Vulnerability> {
        let conn = self.conn();
        let run = || -> Result<Vec<Vulnerability>> {
            let mut ids = conn.prepare_cached(
                "SELECT DISTINCT vuln_id FROM ranges WHERE product = ?1 ORDER BY vuln_id",
            )?;
            let ids: Vec<String> = ids
                .query_map([product_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(v) = load_vuln(&conn, &id)? {
                    out.push(v);
                }
            }
            Ok(out)
        };
        run().unwrap_or_else(|e| {
            tracing::error!("reading vulnerabilities for {product_id}: {e}");
            Vec::new()
        })
    }

    fn signals(&self, vuln_id: &str) -> Signals {
        let cve = vuln_id.trim().to_ascii_uppercase();
        let kev = self
            .json_rows::<KevEntry>("SELECT json FROM kev WHERE cve = ?1", [&cve])
            .into_iter()
            .next();
        let epss = self
            .collect(
                "SELECT score, percentile, date FROM epss WHERE cve = ?1",
                [&cve],
                |r| {
                    Ok((
                        r.get::<_, f64>(0)?,
                        r.get::<_, f64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .into_iter()
            .find_map(|(score, percentile, date)| {
                Some(Epss {
                    score,
                    percentile,
                    date: NaiveDate::parse_from_str(&date, "%Y-%m-%d").ok()?,
                })
            });
        let (ssvc_exploitation, ssvc_automatable) = self
            .collect(
                "SELECT exploitation, automatable FROM ssvc WHERE cve = ?1",
                [&cve],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<bool>>(1)?)),
            )
            .into_iter()
            .next()
            .map_or((None, None), |(e, a)| {
                (e.as_deref().and_then(ssvc_from_str), a)
            });
        let exploits = self
            .collect(
                "SELECT source, id, url FROM exploits WHERE cve = ?1 ORDER BY source, id",
                [&cve],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .into_iter()
            .filter_map(|(source, id, url)| {
                Some(ExploitRef {
                    source: source_from_str(&source)?,
                    id,
                    url,
                })
            })
            .collect();
        Signals {
            kev,
            epss,
            ssvc_exploitation,
            ssvc_automatable,
            exploits,
        }
    }

    fn eol_cycles(&self, product_id: &str) -> Vec<EolCycle> {
        self.json_rows::<Vec<EolCycle>>("SELECT json FROM eol WHERE product_id = ?1", [product_id])
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    fn product_verified(&self, product_id: &str) -> bool {
        self.collect(
            "SELECT verified FROM products WHERE id = ?1",
            params![product_id],
            |r| r.get::<_, bool>(0),
        )
        .first()
        .copied()
        .unwrap_or(false)
    }

    fn info(&self) -> Option<DbInfo> {
        Some(Db::info(self))
    }
}

// ---- unpacking ----------------------------------------------------------

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = BufReader::new(File::open(path).map_err(io_err(path))?);
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).map_err(io_err(path))?;
    Ok(hex::encode(h.finalize()))
}

fn unpack_cached(zst: &Path) -> Result<PathBuf> {
    let sha = sha256_file(zst)?;
    let name = zst.file_name().map_or_else(
        || "unpatched-db".into(),
        |n| n.to_string_lossy().into_owned(),
    );
    let stem = name.strip_suffix(".zst").unwrap_or(&name);
    let stem = stem.strip_suffix(".sqlite").unwrap_or(stem);
    let target_name = format!("{stem}.{}.sqlite", &sha[..16]);

    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(parent) = zst.parent() {
        dirs.push(if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        });
    }
    dirs.push(std::env::temp_dir().join("unpatched-db"));

    let mut last_err = None;
    for dir in dirs {
        let target = dir.join(&target_name);
        if target.metadata().is_ok_and(|m| m.len() > 0) {
            return Ok(target);
        }
        match unpack_to(zst, &dir, &target) {
            Ok(()) => {
                remove_old_copies(&dir, stem, &target);
                return Ok(target);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("at least one directory was tried"))
}

fn unpack_to(zst: &Path, dir: &Path, target: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(io_err(dir))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".unpatched-unpack-")
        .tempfile_in(dir)
        .map_err(io_err(dir))?;
    let input = BufReader::new(File::open(zst).map_err(io_err(zst))?);
    zstd::stream::copy_decode(input, tmp.as_file_mut()).map_err(io_err(zst))?;
    tmp.persist(target).map_err(|e| io_err(target)(e.error))?;
    Ok(())
}

/// Delete unpacked copies of older versions of the same file.
fn remove_old_copies(dir: &Path, stem: &str, keep: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let prefix = format!("{stem}.");
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let middle = n
            .strip_prefix(&prefix)
            .and_then(|r| r.strip_suffix(".sqlite"));
        if let Some(m) = middle
            && m.len() == 16
            && m.bytes().all(|b| b.is_ascii_hexdigit())
            && e.path() != keep
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
}
