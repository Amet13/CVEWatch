//! Download the prebuilt database and check it against `SHA256SUMS`.

use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use unpatched_sources::Http;

use crate::error::{DbError, Result, io_err};

pub const DEFAULT_DB_URL: &str =
    "https://github.com/Amet13/unpatched/releases/download/db/unpatched-db.sqlite.zst";

/// `$UNPATCHED_DB_URL` or [`DEFAULT_DB_URL`].
pub fn db_url() -> String {
    std::env::var("UNPATCHED_DB_URL")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_DB_URL.to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Find the hash for `name` in a `sha256sum` style listing.
fn parse_sums(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (hash, file) = line.split_once(char::is_whitespace)?;
        let file = file.trim().trim_start_matches('*');
        let file = file.strip_prefix("./").unwrap_or(file);
        (file == name && hash.len() == 64).then(|| hash.to_ascii_lowercase())
    })
}

/// Download `url` into `dest_dir` and return the file's path. The `SHA256SUMS`
/// file next to the asset is read first; a file already in `dest_dir` with the
/// right hash is not downloaded again. A mismatch is retried once, since the
/// release is not published in one step.
pub fn download(url: &str, dest_dir: &Path, http: &Http) -> Result<PathBuf> {
    let clean = url.split(['?', '#']).next().unwrap_or(url);
    let (base, name) = clean
        .rsplit_once('/')
        .filter(|(_, n)| !n.is_empty())
        .ok_or_else(|| {
            DbError::Other(format!(
                "{url:?} does not look like a file URL. Use a URL like {DEFAULT_DB_URL}"
            ))
        })?;
    let sums_url = format!("{base}/SHA256SUMS");
    std::fs::create_dir_all(dest_dir).map_err(io_err(dest_dir))?;
    let dest = dest_dir.join(name);

    let mut last = None;
    for attempt in 1..=2 {
        let sums = http.get(&sums_url)?;
        let expected = parse_sums(&String::from_utf8_lossy(&sums), name).ok_or_else(|| {
            DbError::Other(format!(
                "{sums_url} has no checksum for {name}. The release is incomplete; try again later"
            ))
        })?;
        if dest.is_file()
            && let Ok(local) = std::fs::read(&dest)
            && sha256_hex(&local) == expected
        {
            tracing::info!(file = %dest.display(), "database is up to date");
            return Ok(dest);
        }
        tracing::info!(%url, "downloading the database");
        let bytes = http.get(url)?;
        let actual = sha256_hex(&bytes);
        if actual == expected {
            let mut tmp = tempfile::Builder::new()
                .prefix(".unpatched-download-")
                .tempfile_in(dest_dir)
                .map_err(io_err(dest_dir))?;
            tmp.write_all(&bytes).map_err(io_err(&dest))?;
            tmp.persist(&dest).map_err(|e| io_err(&dest)(e.error))?;
            return Ok(dest);
        }
        tracing::warn!(attempt, %expected, %actual, "checksum mismatch");
        last = Some(DbError::Checksum {
            what: name.to_owned(),
            expected,
            actual,
        });
    }
    Err(last.expect("two attempts were made"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_parsing() {
        let h = "a".repeat(64);
        let text = format!(
            "{h}  other.txt\n{}  *unpatched-db.sqlite.zst\n",
            "B".repeat(64)
        );
        assert_eq!(
            parse_sums(&text, "unpatched-db.sqlite.zst"),
            Some("b".repeat(64))
        );
        assert_eq!(parse_sums(&text, "missing"), None);
    }
}
