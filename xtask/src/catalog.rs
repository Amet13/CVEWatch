//! `cargo xtask catalog ...`

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use unpatched_core::CatalogEntry;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EOL_URL: &str = "https://endoflife.date/api/all.json";
const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

fn root() -> PathBuf {
    crate::repo_root()
}

/// Read, parse and validate `catalog/*.yml`. Sorted by id.
fn load() -> Result<Vec<CatalogEntry>> {
    let dir = root().join("catalog");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yml"))
        .collect();
    files.sort();

    let mut entries = Vec::new();
    let mut problems = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).with_context(|| format!("cannot read {}", f.display()))?;
        match serde_norway::from_str::<CatalogEntry>(&text) {
            Ok(e) => {
                let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
                if stem != e.id {
                    problems.push(format!(
                        "{}: file name must be <id>.yml (id is {:?})",
                        f.display(),
                        e.id
                    ));
                }
                entries.push(e);
            }
            Err(err) => problems.push(format!("{}: {err}", f.display())),
        }
    }
    problems.extend(unpatched_catalog::validate(&entries));
    if !problems.is_empty() {
        bail!("catalog has problems:\n  {}", problems.join("\n  "));
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(entries)
}

/// The two generated files: (path, content).
fn generated() -> Result<Vec<(PathBuf, String)>> {
    let entries = load()?;
    let mut catalog = serde_json::to_string_pretty(&entries)?;
    catalog.push('\n');
    let mut schema = serde_json::to_string_pretty(&schemars::schema_for!(CatalogEntry))?;
    schema.push('\n');
    Ok(vec![
        (
            root().join("crates/unpatched-catalog/src/catalog.generated.json"),
            catalog,
        ),
        (root().join("schema/catalog.schema.json"), schema),
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
        eprintln!("catalog: generated files are up to date");
        Ok(())
    } else {
        bail!(
            "generated files are out of date: {}. Run `cargo xtask catalog build` and commit the result.",
            stale.join(", ")
        )
    }
}

fn client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .user_agent("unpatched-xtask-catalog-verify")
        .timeout(Duration::from_secs(60))
        .build()?)
}

/// Total NVD results for a CPE `vendor:product`, retrying on rate limits.
fn nvd_hits(http: &reqwest::blocking::Client, cpe: &str) -> Result<u64> {
    let key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty());
    let mut last = String::new();
    for attempt in 0..4 {
        let mut req = http.get(NVD_URL).query(&[
            ("virtualMatchString", format!("cpe:2.3:*:{cpe}")),
            ("resultsPerPage", "1".into()),
        ]);
        if let Some(k) = &key {
            req = req.header("apiKey", k);
        }
        match req
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
        {
            Ok(resp) => {
                let v: serde_json::Value = resp.json()?;
                return Ok(v["totalResults"].as_u64().unwrap_or(0));
            }
            Err(e) => {
                last = e.to_string();
                sleep(Duration::from_secs(10 * (attempt + 1)));
            }
        }
    }
    bail!("NVD request failed: {last}")
}

pub fn verify() -> Result<()> {
    let entries = load()?;
    let http = client()?;
    let pause = if std::env::var_os("NVD_API_KEY").is_some() {
        Duration::from_millis(700)
    } else {
        Duration::from_secs(7)
    };

    let kev: serde_json::Value = http.get(KEV_URL).send()?.error_for_status()?.json()?;
    let kev_keys: HashSet<(String, String)> = kev["vulnerabilities"]
        .as_array()
        .context("KEV JSON has no vulnerabilities")?
        .iter()
        .map(|v| {
            (
                v["vendorProject"].as_str().unwrap_or_default().to_string(),
                v["product"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let eol: HashSet<String> = http
        .get(EOL_URL)
        .send()?
        .error_for_status()?
        .json::<Vec<String>>()?
        .into_iter()
        .collect();

    let mut failures = 0;
    println!("{:<28} {:<46} {:<8} RESULT", "PRODUCT", "KEY", "KIND");
    for e in &entries {
        let mut row = |kind: &str, key: &str, ok: bool, detail: String| {
            if !ok {
                failures += 1;
            }
            println!(
                "{:<28} {:<46} {:<8} {} {detail}",
                e.id,
                key,
                kind,
                if ok { "ok" } else { "FAIL" }
            );
        };
        for cpe in &e.keys.cpe {
            let result = nvd_hits(&http, cpe);
            sleep(pause);
            match result {
                Ok(n) => row("cpe", cpe, n > 0, format!("({n} CVEs)")),
                Err(err) => row("cpe", cpe, false, format!("({err:#})")),
            }
        }
        for k in &e.keys.kev {
            let ok = kev_keys.contains(&(k.vendor_project.clone(), k.product.clone()));
            row(
                "kev",
                &format!("{} | {}", k.vendor_project, k.product),
                ok,
                String::new(),
            );
        }
        if let Some(slug) = &e.eol {
            row("eol", slug, eol.contains(slug), String::new());
        }
    }
    if failures > 0 {
        bail!("{failures} catalog key(s) failed verification");
    }
    eprintln!("catalog: all keys verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_files_load_and_validate() {
        let entries = load().expect("catalog/*.yml must be valid");
        assert!(entries.len() >= 50, "v1 target is 50 products");
    }

    #[test]
    fn generated_files_are_current() {
        check().expect("run `cargo xtask catalog build`");
    }
}
