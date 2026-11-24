//! `unpatched search`, `unpatched catalog list|show`.

use unpatched_core::{CatalogEntry, ProductKind};

use super::{out, table};
use crate::ctx::suggestion_text;
use crate::error::{Failure, Res};

pub fn kind_name(k: ProductKind) -> &'static str {
    match k {
        ProductKind::Appliance => "appliance",
        ProductKind::App => "app",
        ProductKind::Os => "os",
        ProductKind::Database => "database",
        ProductKind::Server => "server",
        ProductKind::Library => "library",
        ProductKind::Desktop => "desktop",
        ProductKind::Cms => "cms",
    }
}

fn scheme_name(e: &CatalogEntry) -> String {
    serde_json::to_value(&e.versioning)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn rows(entries: &[&CatalogEntry]) -> String {
    let mut rows = vec![vec![
        "ID".to_owned(),
        "NAME".into(),
        "VENDOR".into(),
        "KIND".into(),
        "VERSIONS".into(),
    ]];
    for e in entries {
        rows.push(vec![
            e.id.clone(),
            e.name.clone(),
            e.vendor.clone(),
            kind_name(e.kind).into(),
            scheme_name(e),
        ]);
    }
    table(&rows)
}

pub fn search(text: &str) -> u8 {
    let found = unpatched_catalog::search(text);
    if found.is_empty() {
        out(&format!("{}\n", suggestion_text(text)));
        return 0;
    }
    out(&rows(&found));
    out("\nUse the id in unpatched.yml: `product: <id>`.\n");
    0
}

pub fn list(kind: Option<ProductKind>) -> u8 {
    let entries: Vec<&CatalogEntry> = unpatched_catalog::all()
        .iter()
        .filter(|e| kind.is_none_or(|k| e.kind == k))
        .collect();
    out(&rows(&entries));
    0
}

pub fn show(id: &str) -> Res<u8> {
    let Some(e) = unpatched_catalog::get(id) else {
        return Err(Failure::usage(
            format!("{id:?} is not in the catalog"),
            suggestion_text(id),
        ));
    };
    let yaml = serde_norway::to_string(e).unwrap_or_default();
    let hint = e
        .version_hint
        .as_deref()
        .map_or_else(String::new, |h| format!("# Write the version like: {h}\n"));
    out(&format!("# catalog/{}.yml\n{hint}{yaml}", e.id));
    Ok(0)
}
