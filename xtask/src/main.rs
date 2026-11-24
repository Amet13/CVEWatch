//! Repo tasks: `cargo xtask <task>`.
//!
//! - `catalog build`: turn `catalog/*.yml` into the generated JSON and schema.
//! - `catalog check`: fail if the generated files are out of date.
//! - `catalog verify`: (network) check keys against NVD, KEV and endoflife.date.
//! - `schema`: write schema/unpatched.schema.json and schema/report.schema.json.
//! - `corpus new <name>`: start a corpus case.
//! - `docs check`: fail if they are out of date.
//! - `docs`: regenerate the generated parts of the guide, `llms.txt` and `llms-full.txt`.
//! - `check`: everything CI runs (fmt, clippy, tests, generated-file checks).

mod catalog;
mod check;
mod corpus;
mod docs;
mod schema;

use std::path::PathBuf;

use anyhow::{Result, bail};

/// The workspace root, found at run time: walk up from the current folder to
/// the first `Cargo.toml` that has a `[workspace]` table. (Not the compile-time
/// path, which is wrong when the binary was built elsewhere or moved.)
pub fn repo_root() -> PathBuf {
    let start = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        if std::fs::read_to_string(&manifest).is_ok_and(|t| t.contains("[workspace]")) {
            return dir.to_path_buf();
        }
    }
    eprintln!(
        "error: run `cargo xtask` from inside the unpatched repository (no workspace Cargo.toml found above {}).",
        start.display()
    );
    std::process::exit(1);
}

const USAGE: &str = "usage: cargo xtask <task>

tasks:
  catalog build    write catalog.generated.json and schema/catalog.schema.json
  catalog check    fail if the generated catalog files are out of date
  catalog verify   check catalog keys against NVD, KEV and endoflife.date (network)
  schema           write schema/unpatched.schema.json and schema/report.schema.json
  docs check       fail if the generated docs are out of date
  docs             regenerate the generated parts of README.md and docs/guide/, and llms.txt
  corpus new NAME  start a corpus case in corpus/NAME/case.yml
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
        ["schema"] => schema::build(),
        ["docs"] => docs::build(),
        ["docs", "check"] => docs::check(),
        ["corpus", "new", name] => corpus::new(name),
        ["check"] => check::run(),
        ["help" | "--help" | "-h"] | [] => {
            println!("{USAGE}");
            Ok(())
        }
        other => bail!("unknown task {:?}\n\n{USAGE}", other.join(" ")),
    }
}
