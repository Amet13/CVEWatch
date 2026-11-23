//! Small HTTP helpers shared by every channel. Errors never carry URLs or tokens.

use std::fmt;
use std::time::Duration;

use reqwest::blocking::{Client, Response};

use crate::error::{Error, Result};

/// A secret that never prints.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

pub fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("unpatched/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Http {
            service: "http".into(),
            message: e.without_url().to_string(),
        })
}

/// Turn a transport error into our error type, dropping the URL (it may hold a token).
pub fn http_err(service: &str, e: reqwest::Error) -> Error {
    Error::Http {
        service: service.into(),
        message: e.without_url().to_string(),
    }
}

/// Replace every secret in `text` with `***`.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_owned();
    for s in secrets.iter().filter(|s| s.len() >= 4) {
        out = out.replace(s, "***");
    }
    out
}

/// Pass 2xx responses through; turn everything else into [`Error::Api`].
pub fn check(service: &str, resp: Response, secrets: &[&str]) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().unwrap_or_default();
    let body = redact(body.trim(), secrets);
    let message: String = body.chars().take(200).collect();
    Err(Error::Api {
        service: service.into(),
        status: status.as_u16(),
        message,
    })
}

/// Cut `s` to at most `max` characters, ending with `…` when cut.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_do_not_print() {
        let s = Secret::new("hunter2hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(
            redact("token hunter2hunter2 x", &["hunter2hunter2"]),
            "token *** x"
        );
    }

    #[test]
    fn truncate_counts_chars() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }
}
