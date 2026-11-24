//! The command line, as clap sees it.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use unpatched_core::ProductKind;

const AFTER_HELP: &str = "\
Exit codes:
  0  ok
  1  `check --exit-code` found something to fix today
  2  usage or configuration error
  3  data error (no database, database too old, a download or source failed)
  4  delivery error (a notification channel or GitHub issue failed)

Docs: https://amet13.github.io/unpatched/";

#[derive(Debug, Parser)]
#[command(
    name = "unpatched",
    version,
    about = "Tells you when software you run has a vulnerability you need to act on",
    after_help = AFTER_HELP,
    propagate_version = true
)]
pub struct Cli {
    /// Your stack and settings.
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        default_value = "unpatched.yml"
    )]
    pub config: PathBuf,

    /// The vulnerability database (default: $UNPATCHED_DB, else the cache directory).
    #[arg(long, global = true, value_name = "FILE", env = "UNPATCHED_DB")]
    pub db: Option<PathBuf>,

    /// Use no network: no database download and no package (OSV) lookups.
    #[arg(long, global = true)]
    pub offline: bool,

    /// More detail (FYI findings and evidence in reports, `-v` info logs, `-vv` debug logs).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Print nothing on stdout except errors. A report still goes to --output.
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// When to use colour.
    #[arg(long, global = true, value_enum, default_value_t = ColorArg::Auto, value_name = "WHEN")]
    pub color: ColorArg,

    /// Pretend it is this time (RFC 3339). For tests and docs.
    #[arg(long, global = true, hide = true, value_name = "TIME")]
    pub now: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorArg {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Match your stack against the database and print the report.
    Check(CheckArgs),
    /// Write a starting unpatched.yml (and, with --github, the workflow).
    Init(InitArgs),
    /// Show the evidence: a rule id, a CVE, or a finding key.
    Explain {
        /// `UNP-KEV`, `CVE-2024-21762` or a finding key such as `office-firewall/CVE-2024-21762`.
        #[arg(required_unless_present = "rules")]
        target: Option<String>,

        /// List every rule id with its title, and stop.
        #[arg(long, conflicts_with = "target")]
        rules: bool,
    },
    /// Find a product in the catalog.
    Search {
        /// Words from the product's name, vendor or alias.
        #[arg(required = true, num_args = 1..)]
        text: Vec<String>,
    },
    /// The products unpatched knows.
    #[command(subcommand)]
    Catalog(CatalogCommand),
    /// The vulnerability database.
    #[command(subcommand)]
    Db(DbCommand),
    /// Run the MCP server on stdio, for AI agents.
    Mcp,
    /// Print a JSON Schema.
    Schema {
        /// `config` (unpatched.yml) or `report` (check --format json).
        which: SchemaKind,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SchemaKind {
    Config,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Markdown,
    Sarif,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// How to print the report.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// Write the report to FILE instead of stdout. A file named by
    /// $GITHUB_STEP_SUMMARY is appended to, so other steps keep their text.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Exit with 1 when something has to be fixed today.
    #[arg(long)]
    pub exit_code: bool,

    /// Also send the findings to the configured channels (issues, chat).
    #[arg(long)]
    pub notify: bool,

    /// With --notify: send and write nothing; print each message and what would be written.
    #[arg(long, requires = "notify")]
    pub dry_run: bool,

    /// Keep delivery state and issues in GitHub (automatic inside GitHub Actions).
    #[arg(long)]
    pub github: bool,

    /// Do not fail when the database is older than `stale_fail_days`.
    #[arg(long)]
    pub allow_stale: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Also write .github/workflows/unpatched.yml.
    #[arg(long)]
    pub github: bool,

    /// Overwrite files that exist.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Subcommand)]
pub enum CatalogCommand {
    /// List the products.
    List {
        /// Only this kind of product.
        #[arg(long, value_enum)]
        kind: Option<KindArg>,
    },
    /// Show one product (id or alias).
    Show {
        /// A product id or alias, like `fortios` or `fortigate`.
        id: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KindArg {
    Appliance,
    App,
    Os,
    Database,
    Server,
    Library,
    Desktop,
    Cms,
}

impl From<KindArg> for ProductKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Appliance => ProductKind::Appliance,
            KindArg::App => ProductKind::App,
            KindArg::Os => ProductKind::Os,
            KindArg::Database => ProductKind::Database,
            KindArg::Server => ProductKind::Server,
            KindArg::Library => ProductKind::Library,
            KindArg::Desktop => ProductKind::Desktop,
            KindArg::Cms => ProductKind::Cms,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Download the latest prebuilt database now.
    Update,
    /// Show what is in the database and how old it is.
    Info {
        /// Print the counts and the sources as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Build the database from the sources (slow; CI does this daily).
    Build {
        /// Where to write. A name ending in `.zst` is compressed.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// A checkout of CVEProject/cvelistV5. Without it CVE.org is skipped.
        #[arg(long, value_name = "DIR")]
        cvelist: Option<PathBuf>,
        /// NVD years to read, like `2018..2026` (default: all).
        #[arg(long, value_name = "A..B")]
        nvd_years: Option<String>,
        /// Keep downloaded NVD feeds here between builds.
        #[arg(long, value_name = "DIR")]
        nvd_cache: Option<PathBuf>,
        /// Fail, and write nothing, when any source failed (CI uses this).
        #[arg(long)]
        strict: bool,
    },
    /// Ask every source for one known item; fails when any source fails.
    SourcesHealth,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    fn walk(cmd: &clap::Command, path: &str, problems: &mut Vec<String>) {
        let name = format!("{path} {}", cmd.get_name());
        if cmd.get_about().is_none() && !path.is_empty() {
            problems.push(format!("{name}: no description"));
        }
        for a in cmd.get_arguments() {
            if a.is_hide_set() || matches!(a.get_id().as_str(), "help" | "version") {
                continue;
            }
            if a.get_help().is_none() {
                problems.push(format!("{name}: --{} has no help line", a.get_id()));
            }
        }
        for sub in cmd.get_subcommands() {
            walk(sub, name.trim(), problems);
        }
    }

    #[test]
    fn every_command_and_argument_has_a_help_line() {
        let mut problems = Vec::new();
        walk(&Cli::command(), "", &mut problems);
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}
