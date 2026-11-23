//! Render unpatched reports and deliver them (GitHub Issues, Telegram, Slack,
//! Discord, ntfy, webhook).
//!
//! - [`render`]: pure functions from a [`unpatched_core::Report`] to text,
//!   Markdown, JSON and SARIF.
//! - [`state`]: what was already delivered, and what is new since.
//! - [`github`]: one issue per finding plus a pinned status issue.
//! - [`channels`]: chat channels behind the [`channels::Channel`] trait.
//! - [`deliver`]: the orchestration the CLI calls.
//!
//! Secrets only come from environment variables and never reach logs or errors.

pub mod channels;
pub mod deliver;
mod error;
pub mod github;
mod http;
pub mod message;
pub mod render;
pub mod state;

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod testutil;

pub use channels::{Channel, channels_from_config};
pub use deliver::{DeliverOptions, DeliveryOutcome, deliver};
pub use error::{Error, Result};
pub use github::{GitHub, IssuesStore};
pub use message::{Dialect, Event, Message};
pub use state::{DeliveryPlan, DeliveryState, FileStore, SentRecord, StateStore, plan};
