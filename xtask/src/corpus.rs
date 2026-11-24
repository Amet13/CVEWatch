//! `cargo xtask corpus new <name>`: start a corpus case.

use std::fs;

use anyhow::{Context, Result, bail};

const TEMPLATE: &str = r#"description: TODO say in one sentence what this case shows. The corpus test fails until you do.
now: 2026-11-24T00:00:00Z
config: |
  version: 1
  stack:
    - product: fortios
      version: "7.2.5"
data:
  products:
    - id: fortios
      name: FortiOS
      vendor: Fortinet
      kind: appliance
      versioning: dotted
      match:
        cpe: [fortinet:fortios]
      checked: 2026-11-01
  vulns:
    - id: CVE-2026-0001
      summary: A flaw in FortiOS
      published: 2026-10-01
      ranges:
        - source: cve-org
          product: fortios
          raw: ""
          constraints:
            - kind: range
              start: { version: "7.2.0", inclusive: true }
              end: { version: "7.2.7", inclusive: false }
  signals: {}
  info:
    schema_version: 1
    built_at: 2026-11-23T12:00:00Z
    sources: []
# Write what SHOULD come out (see corpus/README.md). A wrong verdict starts as a
# failing case: run `cargo test -p unpatched --test corpus`, see it fail, then fix the code.
expect:
  - key: fortios/CVE-2026-0001
    bucket: fyi
    verdict: affected
    rules: [UNP-AFFECTED]
    fixed_in: 7.2.7
"#;

pub fn new(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("{name:?}: use lowercase letters, digits and dashes, like `fortios-eol-with-latest`");
    }
    let dir = crate::repo_root().join("corpus").join(name);
    if dir.exists() {
        bail!("{} already exists", dir.display());
    }
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    fs::write(dir.join("case.yml"), TEMPLATE)?;
    eprintln!(
        "wrote corpus/{name}/case.yml. It fails on purpose until you replace the TODO description and write what should come out. Then run `cargo test -p unpatched --test corpus`."
    );
    Ok(())
}
