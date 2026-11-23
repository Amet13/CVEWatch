//! Repo tasks: `cargo xtask <task>`.
//!
//! - `catalog build`: turn `catalog/*.yml` into the generated JSON and schema.
//! - `catalog check`: fail if the generated files are out of date.
//! - `catalog verify`: (network) check keys against NVD, KEV and endoflife.date.
//! - `check`: everything CI runs (fmt, clippy, tests, generated-file checks).

mod catalog;
mod check;

use anyhow::{Result, bail};

const USAGE: &str = "usage: cargo xtask <task>

tasks:
  catalog build    write catalog.generated.json and schema/catalog.schema.json
  catalog check    fail if the generated catalog files are out of date
  catalog verify   check catalog keys against NVD, KEV and endoflife.date (network)
  check            fmt, clippy, tests and generated-file checks";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if let Err(e) = run(&args) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: &[&str]) -> Result<()> {
    match args {
        ["catalog", "build"] => catalog::build(),
        ["catalog", "check"] => catalog::check(),
        ["catalog", "verify"] => catalog::verify(),
        ["check"] => check::run(),
        ["help" | "--help" | "-h"] | [] => {
            println!("{USAGE}");
            Ok(())
        }
        other => bail!("unknown task {:?}\n\n{USAGE}", other.join(" ")),
    }
}
