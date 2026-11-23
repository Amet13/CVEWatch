//! `download` against a local server. No network.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use unpatched_db::{DEFAULT_DB_URL, DbError, db_url, download};
use unpatched_sources::Http;

type Handler = Box<dyn FnMut(&str) -> (u16, Vec<u8>) + Send>;

fn serve(mut handler: Handler) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
            }
            let (status, body) = handler(&path);
            let head = format!(
                "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    format!("http://{addr}")
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn http() -> Http {
    Http::new().unwrap().with_backoff(Duration::from_millis(1))
}

#[test]
fn downloads_verifies_and_skips_when_present() {
    let body = b"pretend database".to_vec();
    let sums = format!("{}  unpatched-db.sqlite.zst\n", sha(&body));
    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = hits.clone();
    let base = serve(Box::new(move |path| {
        seen.lock().unwrap().push(path.to_owned());
        match path {
            "/db/SHA256SUMS" => (200, sums.clone().into_bytes()),
            "/db/unpatched-db.sqlite.zst" => (200, body.clone()),
            _ => (404, Vec::new()),
        }
    }));
    let dir = tempfile::tempdir().unwrap();
    let url = format!("{base}/db/unpatched-db.sqlite.zst");
    let path = download(&url, dir.path(), &http()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"pretend database");
    assert_eq!(hits.lock().unwrap().len(), 2);

    // Second call: the sums are read, the asset is not fetched again.
    download(&url, dir.path(), &http()).unwrap();
    let hits = hits.lock().unwrap();
    assert_eq!(hits.len(), 3, "{hits:?}");
    assert_eq!(hits[2], "/db/SHA256SUMS");
}

#[test]
fn retries_once_when_the_release_is_half_published() {
    let good = b"the new database".to_vec();
    let sums = format!("{}  a.zst\n", sha(&good));
    let mut asset_calls = 0;
    let base = serve(Box::new(move |path| match path {
        "/SHA256SUMS" => (200, sums.clone().into_bytes()),
        "/a.zst" => {
            asset_calls += 1;
            if asset_calls == 1 {
                (200, b"the old database".to_vec())
            } else {
                (200, good.clone())
            }
        }
        _ => (404, Vec::new()),
    }));
    let dir = tempfile::tempdir().unwrap();
    let path = download(&format!("{base}/a.zst"), dir.path(), &http()).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"the new database");
}

#[test]
fn bad_checksum_twice_fails_and_writes_nothing() {
    let sums = format!("{}  a.zst\n", sha(b"expected"));
    let base = serve(Box::new(move |path| match path {
        "/SHA256SUMS" => (200, sums.clone().into_bytes()),
        _ => (200, b"something else".to_vec()),
    }));
    let dir = tempfile::tempdir().unwrap();
    let err = download(&format!("{base}/a.zst"), dir.path(), &http()).unwrap_err();
    assert!(matches!(err, DbError::Checksum { .. }), "{err}");
    assert!(!dir.path().join("a.zst").exists());
}

#[test]
fn missing_sums_entry_is_an_error() {
    let base = serve(Box::new(|path| match path {
        "/SHA256SUMS" => (200, format!("{}  other.zst\n", "0".repeat(64)).into_bytes()),
        _ => (200, b"x".to_vec()),
    }));
    let dir = tempfile::tempdir().unwrap();
    let err = download(&format!("{base}/a.zst"), dir.path(), &http()).unwrap_err();
    assert!(err.to_string().contains("no checksum for a.zst"), "{err}");
}

#[test]
fn default_url() {
    // Not setting the variable here: tests run in parallel. Only the shape is checked.
    assert!(DEFAULT_DB_URL.ends_with("/db/unpatched-db.sqlite.zst"));
    if std::env::var_os("UNPATCHED_DB_URL").is_none() {
        assert_eq!(db_url(), DEFAULT_DB_URL);
    }
}
