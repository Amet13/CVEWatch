//! Model Context Protocol server for unpatched.
//!
//! Newline-delimited JSON-RPC 2.0 over stdio, written by hand: the protocol
//! surface we need (initialize, ping, tools/list, tools/call) is small, and
//! this keeps the dependency tree short. Every tool is read-only.
//!
//! Errors: a malformed request, an unknown method or an unknown tool is a
//! JSON-RPC error. A tool that runs and fails (missing database, bad
//! arguments, unknown product) answers with `isError: true`, so the model
//! can read the message and fix its call.

mod tools;

use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::Context;
use serde_json::{Value, json};

use crate::tools::Tools;

/// Protocol versions this server speaks, oldest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] = ["2025-06-18", "2025-11-25"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// What the server needs to know about its surroundings.
#[derive(Debug, Clone)]
pub struct ServerContext {
    /// The vulnerability database (`.sqlite` or `.sqlite.zst`).
    pub db_path: PathBuf,
    /// Default `unpatched.yml` for `check_stack`.
    pub config_path: PathBuf,
    /// When true, no network is used (package items are not looked up in OSV).
    pub offline: bool,
}

/// Serve MCP on the process's stdin and stdout until stdin closes.
pub fn serve_stdio(ctx: ServerContext) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(ctx, stdin.lock(), stdout.lock())
}

/// Serve MCP on any reader and writer (one JSON message per line).
pub fn serve<R: BufRead, W: Write>(
    ctx: ServerContext,
    input: R,
    mut output: W,
) -> anyhow::Result<()> {
    let mut tools = Tools::new(ctx);
    for line in input.lines() {
        let line = line.context("reading from the client")?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = handle_line(&mut tools, &line) {
            let text = serde_json::to_string(&reply)?;
            output.write_all(text.as_bytes())?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

fn handle_line(tools: &mut Tools, line: &str) -> Option<Value> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(error(
                &Value::Null,
                PARSE_ERROR,
                &format!("parse error: {e}"),
            ));
        }
    };
    let Some(obj) = msg.as_object() else {
        return Some(error(
            &Value::Null,
            INVALID_REQUEST,
            "expected a JSON-RPC request object (batches are not supported)",
        ));
    };
    let id = obj.get("id").cloned();
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        // A response from the client (we send no requests) or garbage.
        return match id {
            Some(id) if !obj.contains_key("result") && !obj.contains_key("error") => {
                Some(error(&id, INVALID_REQUEST, "the request has no `method`"))
            }
            _ => None,
        };
    };
    // A notification (no id) is never answered, whatever it is.
    let id = id?;
    if !(id.is_string() || id.is_number()) {
        return Some(error(
            &Value::Null,
            INVALID_REQUEST,
            "`id` must be a string or a number",
        ));
    }
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools::definitions() })),
        "tools/call" => call_tool(tools, &params),
        other => Err((METHOD_NOT_FOUND, format!("unknown method: {other}"))),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => error(&id, code, &message),
    })
}

fn initialize(params: &Value) -> Value {
    let latest = SUPPORTED_PROTOCOL_VERSIONS[SUPPORTED_PROTOCOL_VERSIONS.len() - 1];
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(v))
        .unwrap_or(latest);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "unpatched",
            "title": "unpatched",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "Read-only tools about the software stack in unpatched.yml. \
            Never guess versions: ask the user. A verdict of `unknown` is not `not-affected`.",
    })
}

fn call_tool(tools: &mut Tools, params: &Value) -> Result<Value, (i64, String)> {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Err((INVALID_PARAMS, "tools/call needs a string `name`".into()));
    };
    let args = match params.get("arguments") {
        None | Some(Value::Null) => json!({}),
        Some(v) if v.is_object() => v.clone(),
        Some(_) => {
            return Err((INVALID_PARAMS, "`arguments` must be an object".into()));
        }
    };
    if !tools::is_tool(name) {
        return Err((INVALID_PARAMS, format!("unknown tool: {name}")));
    }
    Ok(match tools.call(name, &args) {
        Ok(out) => json!({
            "content": [{ "type": "text", "text": out.text }],
            "structuredContent": out.data,
            "isError": false,
        }),
        Err(message) => json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true,
        }),
    })
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
