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

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = e.exit_code();
            let _ = e.print();
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
    let ctx = Ctx {
        config: cli.config.clone(),
        db,
        offline: cli.offline,
        verbose: cli.verbose,
        quiet: cli.quiet,
        color: out_color,
    };
    match cmd::run(&ctx, cli.command) {
        Ok(code) => ExitCode::from(code),
        Err(f) => {
            eprintln!("{:?}", f.report);
            ExitCode::from(f.code)
        }
    }
}
