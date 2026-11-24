//! One module per command.

mod catalog;
mod check;
mod db;
mod explain;
mod init;

use std::io::Write;

use crate::cli::{CatalogCommand, Command, SchemaKind};
use crate::ctx::Ctx;
use crate::error::{Failure, Res};

/// Run a command. The `Ok` value is the exit code.
pub fn run(ctx: &Ctx, command: Command) -> Res<u8> {
    match command {
        Command::Check(args) => check::run(ctx, &args),
        Command::Init(args) => init::run(ctx, &args),
        Command::Explain { target, rules } => match target {
            Some(t) if !rules => explain::run(ctx, &t),
            _ => {
                out(&explain::rules_list());
                Ok(0)
            }
        },
        Command::Search { text } => Ok(catalog::search(&text.join(" "))),
        Command::Catalog(CatalogCommand::List { kind }) => Ok(catalog::list(kind.map(Into::into))),
        Command::Catalog(CatalogCommand::Show { id }) => catalog::show(&id),
        Command::Db(c) => db::run(ctx, c),
        Command::Mcp => mcp(ctx),
        Command::Schema { which } => {
            let text = match which {
                SchemaKind::Config => schema_text(&schemars::schema_for!(unpatched_core::Config)),
                SchemaKind::Report => schema_text(&schemars::schema_for!(unpatched_core::Report)),
            };
            print!("{text}");
            Ok(0)
        }
    }
}

/// The same bytes `cargo xtask schema` writes to `schema/*.json`.
fn schema_text(schema: &schemars::Schema) -> String {
    let mut s = serde_json::to_string_pretty(schema).unwrap_or_default();
    s.push('\n');
    s
}

fn mcp(ctx: &Ctx) -> Res<u8> {
    if !ctx.offline && !ctx.db.is_file() {
        // stdout belongs to the protocol; a failure only shows in the log.
        if let Err(e) = ctx.download_db() {
            tracing::warn!("no database yet: {}", e.report);
        }
    }
    unpatched_mcp::serve_stdio(unpatched_mcp::ServerContext {
        db_path: ctx.db.clone(),
        config_path: ctx.config.clone(),
        offline: ctx.offline,
    })
    .map_err(|e| {
        Failure::data(
            format!("the MCP server stopped: {e:#}"),
            "Run it from an MCP client, for example `claude mcp add unpatched -- unpatched mcp`.",
        )
    })?;
    Ok(0)
}

/// Print to stdout and ignore a closed pipe (`unpatched ... | head`).
pub fn out(text: &str) {
    let mut so = std::io::stdout().lock();
    let _ = so.write_all(text.as_bytes());
}

/// Left-aligned table with a header row.
pub fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut s = String::new();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                if i + 1 == r.len() {
                    cell.clone()
                } else {
                    format!("{cell:<w$}", w = widths[i])
                }
            })
            .collect();
        s.push_str(line.join("  ").trim_end());
        s.push('\n');
    }
    s
}
