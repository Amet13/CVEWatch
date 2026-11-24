//! `unpatched db ...`.

use std::fmt::Write as _;
use std::ops::RangeInclusive;

use unpatched_core::SourceStatus;
use unpatched_db::BuildOptions;
use unpatched_notify::render::source_name;

use super::{out, table};
use crate::cli::DbCommand;
use crate::ctx::Ctx;
use crate::error::{Failure, Res};

pub fn run(ctx: &Ctx, cmd: DbCommand) -> Res<u8> {
    match cmd {
        DbCommand::Update => update(ctx),
        DbCommand::Info => info(ctx),
        DbCommand::Build {
            out,
            cvelist,
            nvd_years,
            nvd_cache,
        } => build(ctx, out, cvelist, nvd_years.as_deref(), nvd_cache),
        DbCommand::SourcesHealth => health(ctx),
    }
}

fn update(ctx: &Ctx) -> Res<u8> {
    ctx.require_online("`db update`")?;
    ctx.download_db()?;
    let db = unpatched_db::Db::open(&ctx.db).map_err(|e| {
        Failure::data(
            format!("the downloaded database cannot be read: {e}"),
            "Try again in a few minutes; the release may still be publishing.",
        )
    })?;
    let info = db.info();
    if !ctx.quiet {
        out(&format!(
            "Database updated: {}\nBuilt {}\n",
            ctx.db.display(),
            info.built_at.format("%Y-%m-%d %H:%M UTC")
        ));
    }
    Ok(0)
}

fn status_line(s: &SourceStatus) -> Vec<String> {
    vec![
        format!("  {}", source_name(s.source)),
        if s.ok { "ok".into() } else { "FAILED".into() },
        format!("{} records", s.records),
        s.fetched_at.format("%Y-%m-%d %H:%M UTC").to_string(),
        s.note.clone().unwrap_or_default(),
    ]
}

fn info(ctx: &Ctx) -> Res<u8> {
    if !ctx.db.is_file() {
        return Err(Failure::data(
            format!("there is no database at {}", ctx.db.display()),
            "Run `unpatched db update`, or pass --db <file>.",
        ));
    }
    let db = unpatched_db::Db::open(&ctx.db).map_err(|e| {
        Failure::data(
            format!("cannot read the database {}: {e}", ctx.db.display()),
            "Run `unpatched db update` to fetch a fresh copy.",
        )
    })?;
    let info = db.info();
    let age = (ctx.now - info.built_at).num_days().max(0);
    let products = db.products();
    let verified = products.iter().filter(|(_, v)| *v).count();
    let mut s = String::new();
    let _ = writeln!(s, "File:             {}", ctx.db.display());
    let _ = writeln!(s, "Schema version:   {}", info.schema_version);
    let _ = writeln!(
        s,
        "Built:            {} ({age} day{} old)",
        info.built_at.format("%Y-%m-%d %H:%M UTC"),
        if age == 1 { "" } else { "s" }
    );
    let _ = writeln!(
        s,
        "Products:         {} ({verified} found in the data)",
        products.len()
    );
    let _ = writeln!(s, "Vulnerabilities:  {}", db.vuln_ids().len());
    let _ = writeln!(s, "Sources:");
    let rows: Vec<Vec<String>> = info.sources.iter().map(status_line).collect();
    s.push_str(&table(&rows));
    out(&s);
    Ok(0)
}

fn parse_years(text: &str) -> Res<RangeInclusive<u16>> {
    let bad = || {
        Failure::usage(
            format!("--nvd-years {text:?} is not a year range"),
            "Use `2018..2026`, or one year like `2024`.",
        )
    };
    let (a, b) = text.split_once("..").unwrap_or((text, text));
    let a: u16 = a.trim().parse().map_err(|_| bad())?;
    let b: u16 = b.trim().parse().map_err(|_| bad())?;
    if a > b {
        return Err(bad());
    }
    Ok(a..=b)
}

fn build(
    ctx: &Ctx,
    out_file: std::path::PathBuf,
    cvelist: Option<std::path::PathBuf>,
    years: Option<&str>,
    nvd_cache: Option<std::path::PathBuf>,
) -> Res<u8> {
    ctx.require_online("`db build`")?;
    let nvd_years = years.map(parse_years).transpose()?;
    let http = Ctx::http()?;
    let opts = BuildOptions {
        cvelist,
        nvd_years,
        nvd_cache_dir: nvd_cache,
        out: out_file,
        ..BuildOptions::default()
    };
    let sum = unpatched_db::build(&opts, unpatched_catalog::all(), &http).map_err(|e| {
        Failure::data(
            format!("the database was not built: {e}"),
            "Nothing was written. Run `unpatched db sources-health` to see which source fails.",
        )
    })?;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Wrote {} ({} bytes, {} bytes unpacked)",
        sum.out.display(),
        sum.out_bytes,
        sum.raw_bytes
    );
    let _ = writeln!(
        s,
        "{} products ({} found in the data), {} vulnerabilities, {} ranges",
        sum.products, sum.verified_products, sum.vulns, sum.ranges
    );
    let _ = writeln!(
        s,
        "{} KEV, {} EPSS, {} SSVC, {} exploits, EOL for {} products",
        sum.kev, sum.epss, sum.ssvc, sum.exploits, sum.eol_products
    );
    let rows: Vec<Vec<String>> = sum.sources.iter().map(status_line).collect();
    s.push_str(&table(&rows));
    out(&s);
    Ok(0)
}

fn health(ctx: &Ctx) -> Res<u8> {
    ctx.require_online("`db sources-health`")?;
    let http = Ctx::http()?;
    let statuses = unpatched_db::sources_health(&http);
    let rows: Vec<Vec<String>> = statuses.iter().map(status_line).collect();
    out(&table(&rows));
    let failed: Vec<&str> = statuses
        .iter()
        .filter(|s| !s.ok)
        .map(|s| source_name(s.source))
        .collect();
    if failed.is_empty() {
        Ok(0)
    } else {
        Err(Failure::data(
            format!("{} source(s) failed: {}", failed.len(), failed.join(", ")),
            "A source may be down for a while. The daily database build keeps the last good data.",
        ))
    }
}
