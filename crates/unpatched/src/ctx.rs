//! What every command shares: the global options, the config file and the database.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use miette::{Diagnostic, NamedSource, Report, SourceSpan};
use unpatched_core::Config;
use unpatched_core::config::edit_distance;
use unpatched_db::Db;
use unpatched_sources::Http;

use crate::error::{EXIT_USAGE, Failure, Res};

/// A downloaded database younger than this is used as it is.
const FRESH: Duration = Duration::from_secs(20 * 3600);

#[derive(Debug, Clone)]
pub struct Ctx {
    pub config: PathBuf,
    pub db: PathBuf,
    pub offline: bool,
    pub verbose: u8,
    pub quiet: bool,
    /// Colour on stdout.
    pub color: bool,
    /// The time of this run: `--now`, else the clock.
    pub now: DateTime<Utc>,
}

impl Ctx {
    pub fn http() -> Res<Http> {
        Http::new().map_err(|e| {
            Failure::data(
                format!("cannot start the HTTP client: {e}"),
                "Check your TLS and proxy settings.",
            )
        })
    }

    pub fn require_online(&self, what: &str) -> Res<()> {
        if self.offline {
            Err(Failure::usage(
                format!("{what} needs the network, but --offline is set"),
                "Run it again without --offline.",
            ))
        } else {
            Ok(())
        }
    }

    /// The directory that holds the config file (for the local state file).
    pub fn config_dir(&self) -> PathBuf {
        match self.config.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }

    /// Download the database to `self.db` (a `.zst` path).
    pub fn download_db(&self) -> Res<()> {
        let http = Self::http()?;
        let dir = match self.db.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        if self.db.extension().is_none_or(|e| e != "zst") {
            return Err(Failure::usage(
                format!(
                    "{} is not a .zst path, so a download cannot go there",
                    self.db.display()
                ),
                "Use --db <dir>/unpatched-db.sqlite.zst, or leave --db out.",
            ));
        }
        let got = unpatched_db::download(&unpatched_db::db_url(), &dir, &http).map_err(|e| {
            Failure::data(
                format!("could not download the database: {e}"),
                "Check your network, or build one with `unpatched db build`, or pass --db <file> and --offline.",
            )
        })?;
        if got != self.db {
            std::fs::rename(&got, &self.db).map_err(|e| {
                Failure::data(
                    format!("cannot move the database to {}: {e}", self.db.display()),
                    "Check that you can write there.",
                )
            })?;
        }
        // Remember when we last looked, so the next run does not ask again at once.
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&self.db) {
            let _ = f.set_modified(SystemTime::now());
        }
        Ok(())
    }

    /// Open the database, fetching it first when it is missing or older than 20 hours
    /// (unless offline). A failed refresh is only a warning when an older file exists.
    pub fn open_db(&self) -> Res<Db> {
        let exists = self.db.is_file();
        let old = exists
            && std::fs::metadata(&self.db)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age > FRESH);
        if !self.offline && (!exists || old) {
            match self.download_db() {
                Ok(()) => {}
                Err(e) if exists => {
                    tracing::warn!(
                        "could not refresh the database, using the one on disk: {}",
                        e.report
                    );
                }
                Err(e) => return Err(e),
            }
        }
        if !self.db.is_file() {
            return Err(Failure::data(
                format!("there is no database at {}", self.db.display()),
                "Run `unpatched db update` to download one, or pass --db <file>.",
            ));
        }
        Db::open(&self.db).map_err(|e| {
            Failure::data(
                format!("cannot open the database {}: {e}", self.db.display()),
                "Run `unpatched db update` to fetch a fresh copy.",
            )
        })
    }
}

/// A YAML problem, shown with the line.
#[derive(Debug, thiserror::Error, Diagnostic)]
#[error("{message}")]
#[diagnostic(help(
    "Fix the file and run the command again. `unpatched schema config` prints the format."
))]
struct ConfigProblem {
    message: String,
    #[source_code]
    src: NamedSource<String>,
    #[label("here")]
    at: Option<SourceSpan>,
}

/// Length of the line that holds byte `index`.
fn line_len_at(text: &str, index: usize) -> usize {
    let index = index.min(text.len());
    let start = text[..index].rfind('\n').map_or(0, |i| i + 1);
    let end = text[index..].find('\n').map_or(text.len(), |i| index + i);
    text[start..end].chars().count()
}

pub fn read_config_text(path: &Path) -> Res<String> {
    std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Failure::usage(
                format!("{} does not exist", path.display()),
                "Run `unpatched init` to write one, or pass --config <file>.",
            )
        } else {
            Failure::usage(
                format!("cannot read {}: {e}", path.display()),
                "Check the path and the file's permissions.",
            )
        }
    })
}

/// Read `unpatched.yml`, check its structure and that every product is in the catalog.
pub fn load_config(path: &Path) -> Res<Config> {
    let text = read_config_text(path)?;
    let cfg = Config::from_yaml(&text).map_err(|e| {
        // A log or a binary file named by mistake must not flood the terminal:
        // show the snippet only when the file and the offending line are small.
        let span = e
            .index()
            .filter(|i| text.len() <= 64 * 1024 && line_len_at(&text, *i) <= 300)
            .map(|i| SourceSpan::from((i, 1)));
        let shown = if span.is_some() {
            text.clone()
        } else {
            String::new()
        };
        Failure::with_report(
            EXIT_USAGE,
            Report::new(ConfigProblem {
                message: e.short_message(),
                src: NamedSource::new(path.display().to_string(), shown),
                at: span,
            }),
        )
    })?;
    check_products(&cfg)?;
    Ok(cfg)
}

/// Words of a catalog entry's id, name, vendor and aliases, lowercase.
fn entry_words(e: &unpatched_core::CatalogEntry) -> Vec<String> {
    std::iter::once(&e.id)
        .chain(std::iter::once(&e.name))
        .chain(std::iter::once(&e.vendor))
        .chain(&e.aliases)
        .flat_map(|n| {
            n.to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Up to three catalog entries close to `text`: the words match, or the
/// spelling is a typo away. Nothing is returned when nothing is close.
pub fn suggest(text: &str) -> Vec<&'static unpatched_core::CatalogEntry> {
    let mut found = unpatched_catalog::search(text);
    if found.is_empty() {
        // Token overlap: a whole word of the query is a whole word of the entry.
        for token in text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 3)
        {
            let token = token.to_lowercase();
            for e in unpatched_catalog::all() {
                if entry_words(e).contains(&token) && !found.iter().any(|f| f.id == e.id) {
                    found.push(e);
                }
            }
        }
    }
    if found.is_empty() {
        // A typo: a small edit distance to an id, alias or name.
        let lowered = text.trim().to_lowercase();
        let allowed = match lowered.chars().count() {
            0..=3 => 0,
            4..=5 => 1,
            6..=9 => 2,
            _ => 3,
        };
        let mut scored: Vec<(usize, &'static unpatched_core::CatalogEntry)> =
            unpatched_catalog::all()
                .iter()
                .map(|e| {
                    let d = std::iter::once(&e.id)
                        .chain(std::iter::once(&e.name))
                        .chain(&e.aliases)
                        .map(|n| edit_distance(&lowered, &n.to_lowercase()))
                        .min()
                        .unwrap_or(usize::MAX);
                    (d, e)
                })
                .filter(|(d, _)| *d <= allowed)
                .collect();
        scored.sort_by_key(|(d, e)| (*d, e.id.clone()));
        found = scored.into_iter().map(|(_, e)| e).collect();
    }
    found.truncate(3);
    found
}

/// A package URL that works, for messages.
pub const PURL_EXAMPLE: &str = unpatched_core::config::PURL_EXAMPLE;

/// Where to ask for a product.
pub const NEW_PRODUCT_URL: &str = "https://github.com/Amet13/unpatched/issues/new/choose";

/// What to say when a name is not in the catalog: close matches (only when
/// they are close), the purl route and where to ask.
pub fn suggestion_text(id: &str) -> String {
    let s = suggest(id);
    let mut text = String::from("Not in the catalog. ");
    if !s.is_empty() {
        let list: Vec<String> = s.iter().map(|e| format!("{} ({})", e.id, e.name)).collect();
        text.push_str(&format!("Did you mean: {}? ", list.join(", ")));
    }
    text.push_str(&format!(
        "For OS packages use a purl, e.g. `{PURL_EXAMPLE}`. \
         To ask for a product: {NEW_PRODUCT_URL}"
    ));
    text
}

fn check_products(cfg: &Config) -> Res<()> {
    let mut lines = Vec::new();
    for (i, item) in cfg.stack.iter().enumerate() {
        if let Some(id) = &item.product
            && unpatched_catalog::get(id).is_none()
        {
            lines.push(format!(
                "stack[{i}]: unknown product {id:?}. {}",
                suggestion_text(id)
            ));
        }
    }
    if lines.is_empty() {
        Ok(())
    } else {
        Err(Failure::usage(
            lines.join("\n"),
            "Use a catalog id in `product:`, or `purl:` for a package.",
        ))
    }
}

pub fn parse_now(text: Option<&str>) -> Res<DateTime<Utc>> {
    match text {
        None => Ok(Utc::now()),
        Some(t) => DateTime::parse_from_rfc3339(t)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                Failure::usage(
                    format!("--now {t:?}: {e}"),
                    "Use RFC 3339, like 2026-11-24T00:00:00Z.",
                )
            }),
    }
}
