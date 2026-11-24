//! The `unpatched` command line.

mod cli;
mod cmd;
mod ctx;
mod error;

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;
use miette::MietteHandlerOpts;
use tracing_subscriber::EnvFilter;

use cli::{Cli, ColorArg};
use ctx::Ctx;

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// clap writes the global options you passed (`--db <FILE>`) into the usage
/// line of an error as if they were required. Take them out again.
fn clean_usage(text: &str) -> String {
    const GLOBALS: [&str; 7] = [
        " --config <FILE>",
        " --db <FILE>",
        " --offline",
        " --quiet",
        " --color <WHEN>",
        " --now <TIME>",
        " --verbose",
    ];
    text.lines()
        .map(|line| {
            let mut line = line.to_owned();
            if line.trim_start().starts_with("Usage:") {
                for g in GLOBALS {
                    line = line.replace(g, "");
                }
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = e.exit_code();
            if e.use_stderr() {
                eprint!("{}", clean_usage(&e.render().to_string()));
            } else {
                let _ = e.print();
            }
            return ExitCode::from(u8::try_from(code).unwrap_or(2));
        }
    };

    let (out_color, err_color) = match cli.color {
        ColorArg::Always => (true, true),
        ColorArg::Never => (false, false),
        ColorArg::Auto => (
            std::io::stdout().is_terminal() && !no_color(),
            std::io::stderr().is_terminal() && !no_color(),
        ),
    };

    let level = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(err_color)
        .without_time()
        .with_target(false)
        .try_init();

    let unicode = std::io::stderr().is_terminal();
    let _ = miette::set_hook(Box::new(move |_| {
        Box::new(
            MietteHandlerOpts::new()
                .color(err_color)
                .unicode(unicode)
                .wrap_lines(false)
                .terminal_links(false)
                .build(),
        )
    }));

    let db = cli.db.clone().unwrap_or_else(unpatched_db::default_db_path);
    let now = match ctx::parse_now(cli.now.as_deref()) {
        Ok(n) => n,
        Err(f) => {
            eprintln!("{:?}", f.report);
            return ExitCode::from(f.code);
        }
    };
    let ctx = Ctx {
        config: cli.config.clone(),
        db,
        offline: cli.offline,
        verbose: cli.verbose,
        quiet: cli.quiet,
        color: out_color,
        now,
    };
    match cmd::run(&ctx, cli.command) {
        Ok(code) => ExitCode::from(code),
        Err(f) => {
            eprintln!("{:?}", f.report);
            ExitCode::from(f.code)
        }
    }
}
