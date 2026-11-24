//! `cargo xtask check`: the steps CI runs, in order.
//!
//! To add a generated-file check, add a [`Step`] to [`steps`].

use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{catalog, docs, schema};

enum Action {
    /// Run cargo with these arguments and fail if it exits non-zero.
    Cargo(&'static [&'static str]),
    /// Run code in this process.
    Func(fn() -> Result<()>),
}

struct Step {
    name: &'static str,
    action: Action,
}

fn steps() -> Vec<Step> {
    vec![
        Step {
            name: "fmt",
            action: Action::Cargo(&["fmt", "--all", "--", "--check"]),
        },
        Step {
            name: "clippy",
            action: Action::Cargo(&[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ]),
        },
        Step {
            name: "test",
            action: Action::Cargo(&["test", "--workspace"]),
        },
        Step {
            name: "catalog",
            action: Action::Func(catalog::check),
        },
        Step {
            name: "schema",
            action: Action::Func(schema::check),
        },
        Step {
            name: "docs",
            action: Action::Func(docs::check),
        },
    ]
}

pub fn run() -> Result<()> {
    let mut failed = Vec::new();
    for step in steps() {
        eprintln!("==> {}", step.name);
        let result = match step.action {
            Action::Cargo(args) => cargo(args),
            Action::Func(f) => f(),
        };
        if let Err(e) = result {
            eprintln!("step {} failed: {e:#}", step.name);
            failed.push(step.name);
        }
    }
    if failed.is_empty() {
        eprintln!("all checks passed");
        Ok(())
    } else {
        bail!("failed: {}", failed.join(", "))
    }
}

fn cargo(args: &[&str]) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .args(args)
        .status()
        .context("could not start cargo")?;
    if status.success() {
        Ok(())
    } else {
        bail!("`cargo {}` failed", args.join(" "))
    }
}
