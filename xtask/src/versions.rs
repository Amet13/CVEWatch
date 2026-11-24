//! `cargo xtask versions`: every place that repeats the release version must match
//! the workspace version in `Cargo.toml`. `.github/scripts/release.sh bump` sets them all.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

fn read(path: &str) -> Result<String> {
    std::fs::read_to_string(root().join(path)).with_context(|| format!("could not read {path}"))
}

fn json(path: &str) -> Result<Value> {
    serde_json::from_str(&read(path)?).with_context(|| format!("{path} is not valid JSON"))
}

/// `version = "x"` in `[workspace.package]`.
fn workspace_version(cargo_toml: &str) -> Result<String> {
    let mut in_pkg = false;
    for line in cargo_toml.lines() {
        if line.starts_with('[') {
            in_pkg = line.trim() == "[workspace.package]";
        } else if in_pkg && let Some(rest) = line.strip_prefix("version") {
            let value = rest.trim_start().trim_start_matches('=').trim();
            return Ok(value.trim_matches('"').to_owned());
        }
    }
    bail!("Cargo.toml has no version in [workspace.package]")
}

/// Every place that should say `version`, as `(where, found)`.
fn found() -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut add = |place: &str, v: Option<&str>| {
        out.push((place.to_owned(), v.unwrap_or("(missing)").to_owned()));
    };

    for line in read("Cargo.toml")?.lines() {
        if line.contains("path = \"crates/")
            && let Some(name) = line.split_whitespace().next()
        {
            let v = line
                .split("version = \"")
                .nth(1)
                .and_then(|rest| rest.split('"').next());
            add(&format!("Cargo.toml: {name}"), v);
        }
    }

    let server = json("server.json")?;
    add("server.json: version", server["version"].as_str());
    for (i, pkg) in server["packages"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let tag = pkg["identifier"]
            .as_str()
            .and_then(|id| id.rsplit_once(':'))
            .map(|(_, tag)| tag);
        add(&format!("server.json: packages[{i}].identifier tag"), tag);
        if let Some(v) = pkg["version"].as_str() {
            add(&format!("server.json: packages[{i}].version"), Some(v));
        }
    }

    add(
        "gemini-extension.json: version",
        json("gemini-extension.json")?["version"].as_str(),
    );
    add(
        ".claude-plugin/plugin.json: version",
        json(".claude-plugin/plugin.json")?["version"].as_str(),
    );
    let market = json(".claude-plugin/marketplace.json")?;
    if let Some(v) = market["version"].as_str() {
        add(".claude-plugin/marketplace.json: version", Some(v));
    }
    for (i, plugin) in market["plugins"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        if let Some(v) = plugin["version"].as_str() {
            add(
                &format!(".claude-plugin/marketplace.json: plugins[{i}].version"),
                Some(v),
            );
        }
    }
    Ok(out)
}

pub fn check() -> Result<()> {
    let version = workspace_version(&read("Cargo.toml")?)?;
    let wrong: Vec<String> = found()?
        .into_iter()
        .filter(|(_, v)| *v != version)
        .map(|(place, v)| format!("  {place} says {v}"))
        .collect();
    if wrong.is_empty() {
        Ok(())
    } else {
        bail!(
            "these differ from the workspace version {version}:\n{}\nRun `.github/scripts/release.sh bump {version} <last tag>` or fix them by hand.",
            wrong.join("\n")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_workspace_version() {
        let toml = "[package]\nversion = \"9.9.9\"\n[workspace.package]\nversion = \"3.0.0\"\n";
        assert_eq!(workspace_version(toml).unwrap(), "3.0.0");
        assert!(workspace_version("[package]\nversion = \"1.0.0\"\n").is_err());
    }

    #[test]
    fn the_repository_is_consistent() {
        check().unwrap();
    }
}
