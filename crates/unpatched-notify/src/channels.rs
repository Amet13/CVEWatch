//! Chat channels. Secrets come from environment variables and never reach logs
//! or error messages.

use std::fmt;

use reqwest::blocking::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use unpatched_core::Config;

use crate::error::{Error, Result};
use crate::http::{Secret, check, client, http_err};
use crate::message::{DISCORD_MAX, Dialect, Event, Message, SLACK_MAX, TELEGRAM_MAX};

pub const ENV_TELEGRAM_TOKEN: &str = "UNPATCHED_TELEGRAM_TOKEN";
pub const ENV_SLACK_WEBHOOK: &str = "UNPATCHED_SLACK_WEBHOOK";
pub const ENV_DISCORD_WEBHOOK: &str = "UNPATCHED_DISCORD_WEBHOOK";
pub const ENV_NTFY_TOKEN: &str = "UNPATCHED_NTFY_TOKEN";
pub const ENV_WEBHOOK_URL: &str = "UNPATCHED_WEBHOOK_URL";
pub const ENV_WEBHOOK_SECRET: &str = "UNPATCHED_WEBHOOK_SECRET";

pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// One place a message can go.
pub trait Channel: fmt::Debug {
    /// Short stable name: `telegram`, `slack`, `discord`, `ntfy`, `webhook`.
    fn name(&self) -> &str;
    fn send(&self, msg: &Message) -> Result<()>;
}

// ---------------------------------------------------------------- telegram

#[derive(Debug)]
pub struct Telegram {
    http: Client,
    base: String,
    token: Secret,
    chat: String,
}

impl Telegram {
    pub fn new(token: impl Into<String>, chat: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: client()?,
            base: TELEGRAM_API.into(),
            token: Secret::new(token),
            chat: chat.into(),
        })
    }

    /// Point at another API server (tests, a local Bot API server).
    #[must_use]
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        let base = base.into();
        base.trim_end_matches('/').clone_into(&mut self.base);
        self
    }
}

impl Channel for Telegram {
    fn name(&self) -> &'static str {
        "telegram"
    }

    fn send(&self, msg: &Message) -> Result<()> {
        let url = format!("{}/bot{}/sendMessage", self.base, self.token.expose());
        let body = json!({
            "chat_id": self.chat,
            "text": msg.render(Dialect::Telegram, TELEGRAM_MAX),
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": true,
        });
        let resp = self
            .http
            .post(url)
            .json(&body)
            .send()
            .map_err(|e| http_err("telegram", e))?;
        check("telegram", resp, &[self.token.expose()]).map(drop)
    }
}

// ---------------------------------------------------------------- slack, discord

#[derive(Debug)]
pub struct Slack {
    http: Client,
    url: Secret,
}

impl Slack {
    /// `url` is the incoming webhook URL.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: client()?,
            url: Secret::new(url),
        })
    }
}

impl Channel for Slack {
    fn name(&self) -> &'static str {
        "slack"
    }

    fn send(&self, msg: &Message) -> Result<()> {
        let body = json!({ "text": msg.render(Dialect::Slack, SLACK_MAX), "mrkdwn": true });
        let resp = self
            .http
            .post(self.url.expose())
            .json(&body)
            .send()
            .map_err(|e| http_err("slack", e))?;
        check("slack", resp, &[self.url.expose()]).map(drop)
    }
}

#[derive(Debug)]
pub struct Discord {
    http: Client,
    url: Secret,
}

impl Discord {
    /// `url` is the webhook URL.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: client()?,
            url: Secret::new(url),
        })
    }
}

impl Channel for Discord {
    fn name(&self) -> &'static str {
        "discord"
    }

    fn send(&self, msg: &Message) -> Result<()> {
        let body = json!({
            "content": msg.render(Dialect::Discord, DISCORD_MAX),
            "allowed_mentions": { "parse": [] },
        });
        let resp = self
            .http
            .post(self.url.expose())
            .json(&body)
            .send()
            .map_err(|e| http_err("discord", e))?;
        check("discord", resp, &[self.url.expose()]).map(drop)
    }
}

// ---------------------------------------------------------------- ntfy

#[derive(Debug)]
pub struct Ntfy {
    http: Client,
    server: String,
    topic: String,
    token: Option<Secret>,
}

impl Ntfy {
    pub fn new(
        server: impl Into<String>,
        topic: impl Into<String>,
        token: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            http: client()?,
            server: server.into().trim_end_matches('/').to_owned(),
            topic: topic.into(),
            token: token.map(Secret::new),
        })
    }
}

impl Channel for Ntfy {
    fn name(&self) -> &'static str {
        "ntfy"
    }

    fn send(&self, msg: &Message) -> Result<()> {
        let (priority, tags) = match msg.event {
            Event::Resolved => (3, vec!["white_check_mark"]),
            _ if msg.has_now() => (5, vec!["rotating_light", "unpatched"]),
            _ => (3, vec!["warning", "unpatched"]),
        };
        // The JSON publish API keeps emoji and non-ASCII text intact.
        let body = json!({
            "topic": self.topic,
            "title": msg.headline(),
            "message": msg.render(Dialect::Plain, 4000),
            "priority": priority,
            "tags": tags,
        });
        let mut req = self.http.post(&self.server).json(&body);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t.expose());
        }
        let resp = req.send().map_err(|e| http_err("ntfy", e))?;
        let secrets: Vec<&str> = self.token.iter().map(Secret::expose).collect();
        check("ntfy", resp, &secrets).map(drop)
    }
}

// ---------------------------------------------------------------- webhook

#[derive(Debug)]
pub struct Webhook {
    http: Client,
    url: Secret,
    secret: Option<Secret>,
}

impl Webhook {
    pub fn new(url: impl Into<String>, secret: Option<String>) -> Result<Self> {
        Ok(Self {
            http: client()?,
            url: Secret::new(url),
            secret: secret.map(Secret::new),
        })
    }

    /// The JSON body: `{event, summary, findings[], report_url?}`.
    pub fn payload(msg: &Message) -> serde_json::Value {
        let mut v = json!({
            "event": msg.event.as_str(),
            "generated_at": msg.generated_at,
            "summary": msg.summary,
            "findings": msg.findings,
        });
        if !msg.resolved.is_empty() {
            v["resolved"] = json!(msg.resolved);
        }
        if let Some(u) = &msg.report_url {
            v["report_url"] = json!(u);
        }
        v
    }
}

impl Channel for Webhook {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn send(&self, msg: &Message) -> Result<()> {
        let body = serde_json::to_vec(&Self::payload(msg))
            .map_err(|e| Error::Config(format!("webhook: cannot encode the payload: {e}")))?;
        let mut req = self
            .http
            .post(self.url.expose())
            .header("content-type", "application/json");
        if let Some(s) = &self.secret {
            let sig = hmac_sha256(s.expose().as_bytes(), &body);
            req = req.header(
                "X-Unpatched-Signature",
                format!("sha256={}", hex::encode(sig)),
            );
        }
        let resp = req.body(body).send().map_err(|e| http_err("webhook", e))?;
        let mut secrets = vec![self.url.expose()];
        secrets.extend(self.secret.iter().map(Secret::expose));
        check("webhook", resp, &secrets).map(drop)
    }
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

// ---------------------------------------------------------------- from config

/// The enabled channels, with secrets from the process environment.
pub fn channels_from_config(config: &Config) -> Result<Vec<Box<dyn Channel>>> {
    channels_with(config, |k| std::env::var(k).ok())
}

/// The channels of a dry run, and the names of the secrets that were missing.
pub type DryRunChannels = (Vec<Box<dyn Channel>>, Vec<&'static str>);

/// The enabled channels for a dry run: a missing secret does not stop it. The
/// channel gets a placeholder (it is never used to send), and the names of the
/// missing variables come back so the caller can warn.
pub fn channels_for_dry_run(config: &Config) -> Result<DryRunChannels> {
    let missing = std::cell::RefCell::new(Vec::new());
    let channels = channels_with(config, |k| {
        let set = std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        if set.is_some() {
            return set;
        }
        let (name, placeholder) = match k {
            ENV_TELEGRAM_TOKEN => (ENV_TELEGRAM_TOKEN, "dry-run"),
            ENV_SLACK_WEBHOOK => (ENV_SLACK_WEBHOOK, "https://dry-run.invalid/slack"),
            ENV_DISCORD_WEBHOOK => (ENV_DISCORD_WEBHOOK, "https://dry-run.invalid/discord"),
            ENV_WEBHOOK_URL => (ENV_WEBHOOK_URL, "https://dry-run.invalid/webhook"),
            _ => return None,
        };
        missing.borrow_mut().push(name);
        Some(placeholder.to_owned())
    })?;
    Ok((channels, missing.into_inner()))
}

/// Like [`channels_from_config`] with a custom environment lookup.
///
/// Every missing secret is reported at once.
pub fn channels_with(
    config: &Config,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Vec<Box<dyn Channel>>> {
    let get = |k: &str| {
        env(k)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let mut out: Vec<Box<dyn Channel>> = Vec::new();
    let mut missing: Vec<Error> = Vec::new();
    let n = &config.notify;
    if let Some(t) = &n.telegram {
        match get(ENV_TELEGRAM_TOKEN) {
            Some(token) => out.push(Box::new(Telegram::new(token, &t.chat)?)),
            None => missing.push(Error::MissingEnv {
                var: ENV_TELEGRAM_TOKEN,
                what: "telegram",
            }),
        }
    }
    if n.slack {
        match get(ENV_SLACK_WEBHOOK) {
            Some(url) => out.push(Box::new(Slack::new(url)?)),
            None => missing.push(Error::MissingEnv {
                var: ENV_SLACK_WEBHOOK,
                what: "slack",
            }),
        }
    }
    if n.discord {
        match get(ENV_DISCORD_WEBHOOK) {
            Some(url) => out.push(Box::new(Discord::new(url)?)),
            None => missing.push(Error::MissingEnv {
                var: ENV_DISCORD_WEBHOOK,
                what: "discord",
            }),
        }
    }
    if let Some(nt) = &n.ntfy {
        out.push(Box::new(Ntfy::new(
            &nt.server,
            &nt.topic,
            get(ENV_NTFY_TOKEN),
        )?));
    }
    if n.webhook {
        match get(ENV_WEBHOOK_URL) {
            Some(url) => out.push(Box::new(Webhook::new(url, get(ENV_WEBHOOK_SECRET))?)),
            None => missing.push(Error::MissingEnv {
                var: ENV_WEBHOOK_URL,
                what: "webhook",
            }),
        }
    }
    if missing.is_empty() {
        Ok(out)
    } else {
        let text: Vec<String> = missing.iter().map(ToString::to_string).collect();
        Err(Error::Config(text.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use unpatched_core::config::{Ntfy as NtfyCfg, Telegram as TelegramCfg};

    use super::*;
    use crate::fixture::{fortios, report, sample_report};
    use crate::testutil::TestServer;

    fn alert() -> Message {
        Message::alert(&sample_report(), vec![fortios()])
    }

    fn config() -> Config {
        Config::from_yaml("version: 1\nstack:\n  - product: nextcloud\n    version: '1'\n").unwrap()
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let long_key = [0xaa; 131];
        let mac = hmac_sha256(
            &long_key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn telegram_sends_markdown_v2() {
        let srv = TestServer::ok();
        let ch = Telegram::new("123:SECRETTOKEN", "42")
            .unwrap()
            .with_base_url(srv.base());
        ch.send(&alert()).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].path, "/bot123:SECRETTOKEN/sendMessage");
        let body = reqs[0].json();
        assert_eq!(body["chat_id"], "42");
        assert_eq!(body["parse_mode"], "MarkdownV2");
        let text = body["text"].as_str().unwrap();
        assert!(text.contains("\\(Office firewall\\)"), "{text}");
        assert!(text.chars().count() <= TELEGRAM_MAX);
    }

    #[test]
    fn telegram_errors_hide_the_token() {
        let srv =
            TestServer::start(|_| (401, r#"{"description":"bad token 123:SECRETTOKEN"}"#.into()));
        let ch = Telegram::new("123:SECRETTOKEN", "42")
            .unwrap()
            .with_base_url(srv.base());
        let err = ch.send(&alert()).unwrap_err().to_string();
        assert!(err.contains("401"), "{err}");
        assert!(!err.contains("SECRETTOKEN"), "{err}");
        // A dead server: the transport error must not carry the URL either.
        let dead = Telegram::new("123:SECRETTOKEN", "42")
            .unwrap()
            .with_base_url("http://127.0.0.1:1");
        let err = dead.send(&alert()).unwrap_err().to_string();
        assert!(!err.contains("SECRETTOKEN"), "{err}");
    }

    #[test]
    fn slack_and_discord_post_json() {
        let srv = TestServer::ok();
        Slack::new(format!("{}/services/T/B/x", srv.base()))
            .unwrap()
            .send(&alert())
            .unwrap();
        Discord::new(format!("{}/api/webhooks/1/y", srv.base()))
            .unwrap()
            .send(&alert())
            .unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[0].path, "/services/T/B/x");
        assert!(
            reqs[0].json()["text"]
                .as_str()
                .unwrap()
                .contains("*unpatched")
        );
        assert_eq!(reqs[1].path, "/api/webhooks/1/y");
        let d = reqs[1].json();
        assert!(d["content"].as_str().unwrap().chars().count() <= DISCORD_MAX);
        assert_eq!(d["allowed_mentions"]["parse"], json!([]));
    }

    #[test]
    fn webhook_errors_hide_the_url() {
        let srv = TestServer::start(|_| (500, "boom".into()));
        let url = format!("{}/hook/SECRETPATH", srv.base());
        let err = Slack::new(url)
            .unwrap()
            .send(&alert())
            .unwrap_err()
            .to_string();
        assert!(!err.contains("SECRETPATH"), "{err}");
    }

    #[test]
    fn ntfy_priority_and_auth() {
        let srv = TestServer::ok();
        let ch = Ntfy::new(srv.base(), "my-topic", Some("tk_secret".into())).unwrap();
        ch.send(&alert()).unwrap();
        ch.send(&Message::digest(&report(vec![]), None)).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[0].header("authorization"), Some("Bearer tk_secret"));
        let a = reqs[0].json();
        assert_eq!(a["topic"], "my-topic");
        assert_eq!(a["priority"], 5);
        assert_eq!(reqs[1].json()["priority"], 3);
    }

    #[test]
    fn webhook_signs_the_body() {
        let srv = TestServer::ok();
        let ch = Webhook::new(srv.base(), Some("shh-secret".into())).unwrap();
        let mut msg = alert();
        msg.report_url = Some("https://example.com/run/1".into());
        ch.send(&msg).unwrap();
        let req = &srv.requests()[0];
        let sig = req.header("x-unpatched-signature").unwrap();
        let want = format!(
            "sha256={}",
            hex::encode(hmac_sha256(b"shh-secret", &req.body))
        );
        assert_eq!(sig, want);
        let v = req.json();
        assert_eq!(v["event"], "alert");
        assert_eq!(v["report_url"], "https://example.com/run/1");
        assert_eq!(v["findings"][0]["vuln"], "CVE-2024-21762");
        assert!(v["summary"]["now"].is_number());
        // No secret, no header.
        let plain = TestServer::ok();
        Webhook::new(plain.base(), None)
            .unwrap()
            .send(&alert())
            .unwrap();
        assert!(
            plain.requests()[0]
                .header("x-unpatched-signature")
                .is_none()
        );
    }

    #[test]
    fn missing_secrets_are_named() {
        let mut cfg = config();
        cfg.notify.telegram = Some(TelegramCfg { chat: "1".into() });
        cfg.notify.slack = true;
        cfg.notify.webhook = true;
        let err = channels_with(&cfg, |_| None).unwrap_err().to_string();
        for var in [ENV_TELEGRAM_TOKEN, ENV_SLACK_WEBHOOK, ENV_WEBHOOK_URL] {
            assert!(err.contains(var), "{err}");
        }
        assert!(!err.contains(ENV_DISCORD_WEBHOOK));
    }

    #[test]
    fn channels_are_built_from_config() {
        let mut cfg = config();
        cfg.notify.telegram = Some(TelegramCfg { chat: "1".into() });
        cfg.notify.discord = true;
        cfg.notify.ntfy = Some(NtfyCfg {
            topic: "t".into(),
            server: "https://ntfy.example".into(),
        });
        let chans = channels_with(&cfg, |k| Some(format!("value-of-{k}"))).unwrap();
        let names: Vec<&str> = chans.iter().map(|c| c.name()).collect();
        assert_eq!(names, ["telegram", "discord", "ntfy"]);
        assert!(!format!("{chans:?}").contains("value-of"));
        // Nothing enabled, nothing built, no secrets needed.
        assert!(channels_with(&config(), |_| None).unwrap().is_empty());
    }
}
