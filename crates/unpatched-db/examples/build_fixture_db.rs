//! Rebuild `fixtures/smoke/unpatched-db.sqlite` from the frozen fixtures.
//! No network. Run it after changing `fixtures/db/` and commit the result.
//!
//!     cargo run -p unpatched-db --example build_fixture_db

use std::path::PathBuf;

use chrono::{TimeZone, Utc};
use unpatched_core::CatalogEntry;
use unpatched_db::{BuildOptions, build};
use unpatched_sources::Http;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let catalog: Vec<CatalogEntry> =
        serde_norway::from_str(&std::fs::read_to_string(root.join("db/catalog.yml"))?)?;
    let out = root.join("smoke/unpatched-db.sqlite");
    let summary = build(
        &BuildOptions {
            cvelist: Some(root.join("db/cvelist")),
            out,
            offline_fixtures: Some(root.clone()),
            built_at: Some(Utc.with_ymd_and_hms(2026, 11, 23, 12, 0, 0).unwrap()),
            ..BuildOptions::default()
        },
        &catalog,
        &Http::new()?,
    )?;
    println!("{summary:#?}");
    Ok(())
}
