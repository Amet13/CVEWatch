//! Drive the server with scripted input against the smoke database.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use unpatched_mcp::{ServerContext, serve};

fn smoke_db() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/smoke/unpatched-db.sqlite")
}

fn ctx(config: &Path) -> ServerContext {
    ServerContext {
        db_path: smoke_db(),
        config_path: config.to_path_buf(),
        offline: true,
    }
}

/// Send each message as one line, return the replies in order.
fn run(ctx: ServerContext, messages: &[Value]) -> Vec<Value> {
    let input: Vec<String> = messages.iter().map(ToString::to_string).collect();
    let input = input.join("\n") + "\n";
    let mut out = Vec::new();
    serve(ctx, Cursor::new(input), &mut out).expect("serve");
    String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("each reply is one JSON line"))
        .collect()
}

fn call(name: &str, args: &Value) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": name, "arguments": args }
    })
}

/// One tool call on a fresh server; returns the `result` object.
fn tool(name: &str, args: &Value) -> Value {
    let replies = run(ctx(Path::new("unpatched.yml")), &[call(name, args)]);
    assert_eq!(replies.len(), 1);
    replies[0]["result"].clone()
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().expect("text content")
}

#[test]
fn handshake_echoes_a_supported_version() {
    let replies = run(
        ctx(Path::new("unpatched.yml")),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"test","version":"0"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
        ],
    );
    // The notification gets no reply.
    assert_eq!(replies.len(), 2);
    let r = &replies[0]["result"];
    assert_eq!(r["protocolVersion"], "2025-06-18");
    assert_eq!(r["serverInfo"]["name"], "unpatched");
    assert_eq!(r["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(r["capabilities"]["tools"].is_object());
    assert_eq!(replies[1]["result"], json!({}));
}

#[test]
fn unsupported_client_version_gets_our_latest() {
    let replies = run(
        ctx(Path::new("unpatched.yml")),
        &[
            json!({"jsonrpc":"2.0","id":"a","method":"initialize","params":{
            "protocolVersion":"2024-11-05"}}),
        ],
    );
    assert_eq!(replies[0]["id"], "a");
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-11-25");
}

#[test]
fn tools_list_snapshot() {
    let replies = run(
        ctx(Path::new("unpatched.yml")),
        &[json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})],
    );
    let tools = &replies[0]["result"]["tools"];
    for t in tools.as_array().unwrap() {
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{}", t["name"]);
        assert_eq!(t["inputSchema"]["type"], "object");
    }
    insta::assert_json_snapshot!(tools);
}

#[test]
fn is_affected_fortios_cve_2024_21762() {
    let r = tool(
        "is_affected",
        &json!({"product":"fortios","version":"7.2.5","cve":"CVE-2024-21762","exposure":"internet"}),
    );
    assert_eq!(r["isError"], false);
    let s = &r["structuredContent"];
    assert_eq!(s["verdict"], "affected");
    assert_eq!(s["vulnerability"], "CVE-2024-21762");
    assert_eq!(s["bucket"], "now");
    assert!(s["fixed_in"].is_string());
    assert!(!s["evidence"].as_array().unwrap().is_empty());
    assert!(text(&r).starts_with("affected."));
}

#[test]
fn is_affected_fixed_version_is_not_affected_with_evidence() {
    let r = tool(
        "is_affected",
        &json!({"product":"fortios","version":"7.6.9","cve":"CVE-2024-21762"}),
    );
    assert_eq!(r["isError"], false);
    let s = &r["structuredContent"];
    assert_eq!(s["verdict"], "not-affected", "{s}");
    assert!(!s["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn is_affected_cve_without_data_is_unknown() {
    // The CVE is in the database, but not for this product.
    let r = tool(
        "is_affected",
        &json!({"product":"nextcloud","version":"28.0.0","cve":"CVE-2024-21762"}),
    );
    assert_eq!(r["structuredContent"]["verdict"], "unknown");
    // The CVE is not in the database at all.
    let r = tool(
        "is_affected",
        &json!({"product":"fortios","version":"7.2.5","cve":"CVE-1999-0001"}),
    );
    assert_eq!(r["structuredContent"]["verdict"], "unknown");
}

#[test]
fn is_affected_without_cve_lists_findings() {
    let r = tool(
        "is_affected",
        &json!({"product":"fortios","version":"7.2.5","exposure":"internet"}),
    );
    let s = &r["structuredContent"];
    assert_eq!(s["product"], "fortios");
    assert!(
        s["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["vuln"] == "CVE-2024-21762")
    );
}

#[test]
fn is_affected_unknown_product_suggests_search() {
    let r = tool("is_affected", &json!({"product":"nope","version":"1"}));
    assert_eq!(r["isError"], true);
    assert!(text(&r).contains("catalog"));
}

#[test]
fn is_affected_missing_argument_is_a_tool_error() {
    let r = tool("is_affected", &json!({"product":"fortios"}));
    assert_eq!(r["isError"], true);
    assert!(text(&r).contains("version"));
}

#[test]
fn explain_cve() {
    let r = tool("explain", &json!({"id":"cve-2024-21762"}));
    assert_eq!(r["isError"], false);
    let s = &r["structuredContent"];
    assert_eq!(s["kind"], "vulnerability");
    assert_eq!(s["vulnerability"]["id"], "CVE-2024-21762");
    assert!(s["ranges_by_source"].is_object());
    assert!(s["signals"]["kev"].is_object(), "{s}");
}

#[test]
fn explain_rule() {
    let r = tool("explain", &json!({"id":"UNP-KEV"}));
    assert_eq!(r["structuredContent"]["kind"], "rule");
    assert_eq!(r["structuredContent"]["rule"]["id"], "UNP-KEV");
    let r = tool("explain", &json!({"id":"UNP-NOPE"}));
    assert_eq!(r["isError"], true);
}

#[test]
fn explain_unknown_cve_is_a_tool_error() {
    let r = tool("explain", &json!({"id":"CVE-1999-0001"}));
    assert_eq!(r["isError"], true);
    assert!(text(&r).contains("not in the database"));
}

#[test]
fn search_catalog_finds_fortios() {
    let r = tool("search_catalog", &json!({"text":"fortios"}));
    let results = r["structuredContent"]["results"].as_array().unwrap();
    assert_eq!(results[0]["id"], "fortios");
    let r = tool("search_catalog", &json!({"text":"zzzz-no-such-product"}));
    assert_eq!(r["structuredContent"]["total"], 0);
    assert_eq!(r["isError"], false);
}

#[test]
fn db_status_reports_age() {
    let r = tool("db_status", &json!({}));
    let s = &r["structuredContent"];
    assert_eq!(s["schema_version"], 1);
    assert!(s["age_hours"].as_f64().unwrap() >= 0.0);
    assert!(s["stale"].is_boolean());
    assert!(!s["sources"].as_array().unwrap().is_empty());
}

#[test]
fn check_stack_reads_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unpatched.yml");
    std::fs::write(
        &path,
        "version: 1\nstack:\n  - product: fortios\n    version: 7.2.5\n    exposure: internet\n    name: Office firewall\n",
    )
    .unwrap();
    let replies = run(ctx(&path), &[call("check_stack", &json!({}))]);
    let r = &replies[0]["result"];
    assert_eq!(r["isError"], false, "{r}");
    let s = &r["structuredContent"];
    assert_eq!(s["format"], 1);
    let findings = s["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| {
        f["vuln"] == "CVE-2024-21762" && f["verdict"] == "affected" && f["bucket"] == "now"
    }));
    assert!(text(r).contains("CVE-2024-21762"));

    // `config_path` overrides the server's file.
    let other = dir.path().join("other.yml");
    std::fs::write(&other, "version: 1\nstack: []\n").unwrap();
    let replies = run(
        ctx(&path),
        &[call(
            "check_stack",
            &json!({"config_path": other.to_str().unwrap()}),
        )],
    );
    let s = &replies[0]["result"]["structuredContent"];
    assert!(
        s["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["vuln"].is_null())
    );
}

#[test]
fn check_stack_errors_say_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.yml");
    let replies = run(ctx(&missing), &[call("check_stack", &json!({}))]);
    assert_eq!(replies[0]["result"]["isError"], true);
    assert!(text(&replies[0]["result"]).contains("Cannot read"));

    let bad = dir.path().join("bad.yml");
    std::fs::write(&bad, "version: 2\nstack: []\n").unwrap();
    let replies = run(ctx(&bad), &[call("check_stack", &json!({}))]);
    assert_eq!(replies[0]["result"]["isError"], true);
    assert!(text(&replies[0]["result"]).contains("not supported"));
}

#[test]
fn missing_database_is_a_tool_error() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ServerContext {
        db_path: dir.path().join("none.sqlite"),
        config_path: dir.path().join("unpatched.yml"),
        offline: true,
    };
    let replies = run(
        ctx,
        &[
            call("db_status", &json!({})),
            // Tools that need no database still work.
            call("search_catalog", &json!({"text":"fortios"})),
        ],
    );
    assert_eq!(replies[0]["result"]["isError"], true);
    assert!(text(&replies[0]["result"]).contains("unpatched db update"));
    assert_eq!(replies[1]["result"]["isError"], false);
}

#[test]
fn json_rpc_errors() {
    let replies = run(
        ctx(Path::new("unpatched.yml")),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"nope/nothing"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                   "params":{"name":"explain","arguments":"x"}}),
            json!([1, 2]),
            json!({"jsonrpc":"2.0","id":{"a":1},"method":"ping"}),
        ],
    );
    assert_eq!(replies[0]["error"]["code"], -32601);
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[1]["error"]["code"], -32602);
    assert_eq!(replies[2]["error"]["code"], -32602);
    assert_eq!(replies[3]["error"]["code"], -32602);
    assert_eq!(replies[4]["error"]["code"], -32600);
    assert_eq!(replies[5]["error"]["code"], -32600);
}

#[test]
fn garbage_line_is_a_parse_error_and_the_server_keeps_going() {
    let mut out = Vec::new();
    let input = "not json\n\n{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n";
    serve(
        ctx(Path::new("unpatched.yml")),
        Cursor::new(input),
        &mut out,
    )
    .unwrap();
    let lines: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["error"]["code"], -32700);
    assert_eq!(lines[0]["id"], Value::Null);
    assert_eq!(lines[1]["id"], 7);
}
