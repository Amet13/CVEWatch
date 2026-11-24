//! Model Context Protocol server for unpatched.
//!
//! Temporary stub so the CLI compiles; the real server replaces this file.

use std::path::PathBuf;

/// What the server needs to know to answer questions.
#[derive(Debug, Clone)]
pub struct ServerContext {
    pub db_path: PathBuf,
    pub config_path: PathBuf,
    pub offline: bool,
}

/// Serve MCP over stdin and stdout until the client disconnects.
pub fn serve_stdio(_ctx: ServerContext) -> anyhow::Result<()> {
    anyhow::bail!("not built yet")
}
