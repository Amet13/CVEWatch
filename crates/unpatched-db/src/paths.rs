use std::path::PathBuf;

/// `$UNPATCHED_CACHE_DIR`, or the platform cache directory plus `unpatched`.
pub fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("UNPATCHED_CACHE_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("unpatched")
}

/// Where `unpatched db update` puts the database by default.
pub fn default_db_path() -> PathBuf {
    cache_dir().join("unpatched-db.sqlite.zst")
}
