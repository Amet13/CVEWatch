//! A small blocking HTTP client shared by every `fetch_*` function.

use std::io::Read;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder};

use crate::error::{Result, SourceError};

/// How many times a failed request is tried again (so 4 attempts in all).
const RETRIES: u32 = 3;

/// Shared HTTP client: fixed User-Agent, timeouts, gzip, and retries with
/// backoff on 429, 5xx and connection errors.
#[derive(Debug, Clone)]
pub struct Http {
    client: Client,
    backoff: Duration,
}

impl Http {
    pub fn new() -> Result<Self> {
        let ua = format!(
            "unpatched/{} (+https://github.com/Amet13/unpatched)",
            env!("CARGO_PKG_VERSION")
        );
        let client = Client::builder()
            .user_agent(ua)
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(600))
            .gzip(true)
            .build()
            .map_err(|source| SourceError::Network {
                url: "(client setup)".into(),
                source,
            })?;
        Ok(Self {
            client,
            backoff: Duration::from_secs(2),
        })
    }

    /// Change the first backoff delay (it doubles on each retry). Tests use a tiny value.
    #[must_use]
    pub fn with_backoff(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }

    /// GET a URL and return the body.
    pub fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.send(url, |c| c.get(url))
    }

    /// GET a URL, `None` on 404.
    pub fn get_optional(&self, url: &str) -> Result<Option<Vec<u8>>> {
        match self.get(url) {
            Ok(b) => Ok(Some(b)),
            Err(SourceError::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// POST a JSON body and return the response body.
    pub fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<Vec<u8>> {
        self.send(url, |c| c.post(url).json(body))
    }

    fn send(&self, url: &str, build: impl Fn(&Client) -> RequestBuilder) -> Result<Vec<u8>> {
        let mut delay = self.backoff;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let outcome = build(&self.client).send().and_then(|resp| {
                let status = resp.status();
                if status.is_success() {
                    resp.bytes().map(|b| Ok(b.to_vec()))
                } else {
                    Ok(Err(status))
                }
            });
            match outcome {
                Ok(Ok(bytes)) => return Ok(bytes),
                Ok(Err(status)) if retryable(status) && attempt <= RETRIES => {
                    tracing::warn!(%url, status = status.as_u16(), attempt, "retrying after backoff");
                }
                Ok(Err(status)) => {
                    return Err(SourceError::Status {
                        url: url.to_owned(),
                        status: status.as_u16(),
                        attempts: attempt,
                    });
                }
                Err(source) if attempt <= RETRIES => {
                    tracing::warn!(%url, error = %source, attempt, "request failed, will retry");
                }
                Err(source) => {
                    return Err(SourceError::Network {
                        url: url.to_owned(),
                        source,
                    });
                }
            }
            std::thread::sleep(delay);
            delay = delay.saturating_mul(2);
        }
    }
}

fn retryable(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Return the bytes unpacked when they are gzip data, as they are otherwise.
/// Servers differ on whether they send `.gz` files with `Content-Encoding: gzip`
/// (the client then unpacks them for us), so we look at the data itself.
pub(crate) fn maybe_gunzip(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(bytes.as_slice())
            .read_to_end(&mut out)
            .map_err(|e| SourceError::parse("gzip data", e))?;
        Ok(out)
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestServer;

    fn fast() -> Http {
        Http::new().unwrap().with_backoff(Duration::from_millis(1))
    }

    #[test]
    fn retries_on_503_then_succeeds() {
        let mut calls = 0;
        let srv = TestServer::start(move |_| {
            calls += 1;
            if calls < 3 {
                (503, b"busy".to_vec())
            } else {
                (200, b"ok".to_vec())
            }
        });
        assert_eq!(fast().get(&srv.url("/x")).unwrap(), b"ok");
    }

    #[test]
    fn gives_up_after_three_retries() {
        let srv = TestServer::start(|_| (429, Vec::new()));
        match fast().get(&srv.url("/x")) {
            Err(SourceError::Status {
                status, attempts, ..
            }) => {
                assert_eq!(status, 429);
                assert_eq!(attempts, 4);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn does_not_retry_404() {
        let srv = TestServer::start(|_| (404, Vec::new()));
        let http = fast();
        assert!(http.get_optional(&srv.url("/x")).unwrap().is_none());
        match http.get(&srv.url("/x")) {
            Err(SourceError::Status { attempts, .. }) => assert_eq!(attempts, 1),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn gunzip_only_when_gzip() {
        assert_eq!(maybe_gunzip(b"plain".to_vec()).unwrap(), b"plain");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, b"packed").unwrap();
        assert_eq!(maybe_gunzip(gz.finish().unwrap()).unwrap(), b"packed");
    }
}
