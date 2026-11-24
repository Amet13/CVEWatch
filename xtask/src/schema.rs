//! `cargo xtask schema`: the JSON Schemas of `unpatched.yml` and the report.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

fn text<T: schemars::JsonSchema>() -> Result<String> {
    // Same bytes as `unpatched schema config|report`.
    let mut s = serde_json::to_string_pretty(&schemars::schema_for!(T))?;
    s.push('\n');
    Ok(s)
}

fn generated() -> Result<Vec<(PathBuf, String)>> {
    Ok(vec![
        (
            root().join("schema/unpatched.schema.json"),
            text::<unpatched_core::Config>()?,
        ),
        (
            root().join("schema/report.schema.json"),
            text::<unpatched_core::Report>()?,
        ),
    ])
}

pub fn build() -> Result<()> {
    for (path, content) in generated()? {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&path, content).with_context(|| format!("cannot write {}", path.display()))?;
        eprintln!(
            "wrote {}",
            path.strip_prefix(root()).unwrap_or(&path).display()
        );
    }
    Ok(())
}

pub fn check() -> Result<()> {
    let mut stale = Vec::new();
    for (path, content) in generated()? {
        if fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
            stale.push(
                path.strip_prefix(root())
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
        }
    }
    if stale.is_empty() {
        eprintln!("schema: generated files are up to date");
        Ok(())
    } else {
        bail!(
            "generated schemas are out of date: {}. Run `cargo xtask schema` and commit the result.",
            stale.join(", ")
        )
    }
}
