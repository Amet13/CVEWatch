//! A real build against the live sources with a small catalog, to measure
//! time and size. Needs the network. Not a test.
//!
//!     cargo run --release -p unpatched-db --example live_build -- \
//!         <out.sqlite.zst> [path/to/cvelistV5] [first-nvd-year]

use std::path::PathBuf;

use chrono::{Datelike, Utc};
use unpatched_core::CatalogEntry;
use unpatched_db::{BuildOptions, build};
use unpatched_sources::Http;

const CATALOG: &str = r"
- { id: fortios, name: FortiOS, vendor: Fortinet, kind: appliance, versioning: dotted, eol: fortios, checked: 2026-11-23,
    match: { cpe: [fortinet:fortios], cna: [{ vendor: Fortinet, product: FortiOS }] } }
- { id: nextcloud, name: Nextcloud, vendor: Nextcloud, kind: app, versioning: dotted, eol: nextcloud, checked: 2026-11-23,
    match: { cpe: [nextcloud:nextcloud_server], cna: [{ vendor: nextcloud, product: server }] } }
- { id: ivanti-connect-secure, name: Ivanti Connect Secure, vendor: Ivanti, kind: appliance, versioning: dotted, checked: 2026-11-23,
    match: { cpe: [ivanti:connect_secure], cna: [{ vendor: Ivanti, product: ICS }] } }
- { id: citrix-netscaler, name: Citrix NetScaler, vendor: Citrix, kind: appliance, versioning: dotted, checked: 2026-11-23,
    match: { cpe: [citrix:netscaler_application_delivery_controller, citrix:netscaler_gateway], cna: [{ vendor: Citrix, product: NetScaler ADC }] } }
- { id: apache-httpd, name: Apache HTTP Server, vendor: Apache, kind: server, versioning: dotted, checked: 2026-11-23,
    match: { cpe: [apache:http_server], cna: [{ vendor: Apache Software Foundation, product: Apache HTTP Server }] } }
- { id: linux-kernel, name: Linux kernel, vendor: Linux, kind: os, versioning: dotted, eol: linux, checked: 2026-11-23,
    match: { cpe: [linux:linux_kernel], cna: [{ vendor: Linux, product: Linux }] } }
- { id: postgresql, name: PostgreSQL, vendor: PostgreSQL, kind: database, versioning: dotted, eol: postgresql, checked: 2026-11-23,
    match: { cpe: [postgresql:postgresql], cna: [{ vendor: PostgreSQL, product: PostgreSQL }] } }
- { id: wordpress, name: WordPress, vendor: WordPress, kind: cms, versioning: dotted, eol: wordpress, checked: 2026-11-23,
    match: { cpe: [wordpress:wordpress], cna: [{ vendor: WordPress, product: WordPress }] } }
- { id: synology-dsm, name: Synology DSM, vendor: Synology, kind: appliance, versioning: dotted, checked: 2026-11-23,
    match: { cpe: [synology:diskstation_manager], cna: [{ vendor: Synology, product: DiskStation Manager }] } }
- { id: php, name: PHP, vendor: PHP, kind: server, versioning: dotted, eol: php, checked: 2026-11-23,
    match: { cpe: [php:php], cna: [{ vendor: PHP Group, product: PHP }] } }
";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let mut args = std::env::args().skip(1);
    let out = PathBuf::from(
        args.next()
            .ok_or("usage: live_build <out> [cvelist] [year]")?,
    );
    let cvelist = args.next().map(PathBuf::from);
    let first: u16 = args.next().map_or(Ok(2020), |s| s.parse())?;
    let catalog: Vec<CatalogEntry> = serde_norway::from_str(CATALOG)?;
    let cache = out.parent().map(|p| p.join("nvd-cache"));
    let summary = build(
        &BuildOptions {
            cvelist,
            nvd_years: Some(first..=u16::try_from(Utc::now().year())?),
            nvd_cache_dir: cache,
            out,
            ..BuildOptions::default()
        },
        &catalog,
        &Http::new()?,
    )?;
    println!("{summary:#?}");
    Ok(())
}
