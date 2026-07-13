// taotie-mcp: a read-only MCP (Model Context Protocol) server over a taotie
// case workspace, speaking JSON-RPC 2.0 over stdio (newline-delimited).
//
// It reuses the same query layer as the desktop app and never writes to the
// case: evidence integrity guarantees are unaffected. Each query opens an
// in-memory DuckDB connection over the Parquet lake, so it is safe to run
// while the desktop app has the same case open.
//
//   taotie-mcp --case-root /path/to/case
//   TAOTIE_CASE_ROOT=/path/to/case taotie-mcp

use std::io::{BufRead, Write};

use serde_json::{json, Value};
use taotie_schema::EventPageQuery;

const PROTOCOL_FALLBACK: &str = "2025-03-26";

fn main() {
    let case_root = resolve_case_root();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = handle_line(&case_root, &line) {
            let _ = writeln!(out, "{response}");
            let _ = out.flush();
        }
    }
}

fn resolve_case_root() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--case-root" {
            if let Some(value) = args.next() {
                return value;
            }
        }
    }
    match std::env::var("TAOTIE_CASE_ROOT") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!("taotie-mcp: pass --case-root <dir> or set TAOTIE_CASE_ROOT");
            std::process::exit(2);
        }
    }
}

/// Handle one JSON-RPC message; returns the serialized response, or None for
/// notifications and unparseable input (MCP stdio servers must stay silent).
fn handle_line(case_root: &str, line: &str) -> Option<String> {
    let message: Value = serde_json::from_str(line).ok()?;
    let id = message.get("id").cloned()?;
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let response = match method {
        "initialize" => ok(&id, initialize_result(&message)),
        "ping" => ok(&id, json!({})),
        "tools/list" => ok(&id, json!({ "tools": tool_definitions() })),
        "tools/call" => ok(&id, tools_call(case_root, message.get("params"))),
        other => error(&id, -32601, &format!("method not found: {other}")),
    };
    Some(response)
}

fn ok(id: &Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error(id: &Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

fn initialize_result(message: &Value) -> Value {
    let requested = message
        .get("params")
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_FALLBACK);
    json!({
        "protocolVersion": requested,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "taotie-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "Read-only access to a taotie DFIR case: search the unified \
            timeline, list detections, and walk correlation chains. Nothing is ever \
            written to the case.",
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "case_summary",
            "description": "Overview of the case: id, ingested artifact counts, event counts per artifact type.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "search_events",
            "description": "Search the unified event timeline. `query` uses the taotie search DSL: \
                terms combine with AND; quote values containing spaces. Filters: after:/before: \
                (UTC time), host:, user:, process:, path:, ip:, url:, hash:, eid:, channel:, \
                level:, action:, type: (artifact type), severity:, finding:true (only events \
                with detections); bare words are full-text. Example: \
                \"finding:true severity:high channel:Security after:2023-05-01T00:00\". \
                Returns a page of events plus a cursor for the next page.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "search DSL string (optional; empty = all events)" },
                    "limit": { "type": "integer", "description": "events per page, 1-200 (default 50)" },
                    "cursor": { "type": "string", "description": "cursor from a previous page" },
                    "artifact_type": { "type": "string", "description": "restrict to one artifact type, e.g. evtx, mft, prefetch" },
                    "sort_by": { "type": "string", "description": "time | severity | artifact_type | event_action" },
                    "sort_dir": { "type": "string", "description": "asc | desc" }
                }
            }
        },
        {
            "name": "get_event_detail",
            "description": "Full detail for one event by its event_id (as returned by search_events).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "event_id": { "type": "string" }
                },
                "required": ["event_id"]
            }
        },
        {
            "name": "list_findings",
            "description": "Detections (sigma / heuristics / IOC) grouped by rule, with severity, \
                ATT&CK mapping, affected entities, first/last seen, and a sample message.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "max groups, 1-500 (default 100)" }
                }
            }
        },
        {
            "name": "get_timeline",
            "description": "Event-volume timeline bins (count per time bucket) for the whole case.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "granularity": { "type": "string", "enum": ["minute", "hour", "day"], "description": "bucket size (default hour)" }
                }
            }
        },
        {
            "name": "get_correlation_chains",
            "description": "Cross-artifact correlation chains (download→execute, created→executed, \
                persistence→executed, …) keyed on shared host/user/process/file/hash entities.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "max chains, 1-100 (default 20)" }
                }
            }
        }
    ])
}

fn tools_call(case_root: &str, params: Option<&Value>) -> Value {
    let name = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let empty = json!({});
    let args = params
        .and_then(|p| p.get("arguments"))
        .unwrap_or(&empty)
        .clone();
    match run_tool(case_root, name, &args) {
        Ok(value) => {
            let text = serde_json::to_string(&value).unwrap_or_else(|e| e.to_string());
            json!({ "content": [{ "type": "text", "text": text }] })
        }
        Err(message) => json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true
        }),
    }
}

fn run_tool(case_root: &str, name: &str, args: &Value) -> Result<Value, String> {
    let to_json = |e: taotie_api::ApiError| e.to_string();
    match name {
        "case_summary" => taotie_api::get_case_summary(case_root)
            .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
            .map_err(to_json),
        "search_events" => {
            let page = EventPageQuery {
                limit: Some(clamp_limit(args.get("limit"), 50, 200)),
                cursor: str_arg(args, "cursor"),
                artifact_type: str_arg(args, "artifact_type"),
                user_name: None,
                search: str_arg(args, "query"),
                sort_by: str_arg(args, "sort_by"),
                sort_dir: str_arg(args, "sort_dir"),
            };
            taotie_api::get_event_page(case_root, page)
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
                .map_err(to_json)
        }
        "get_event_detail" => {
            let event_id =
                str_arg(args, "event_id").ok_or_else(|| "event_id is required".to_string())?;
            taotie_api::get_event_detail_light(case_root, &event_id)
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
                .map_err(to_json)
        }
        "list_findings" => {
            let limit = clamp_limit(args.get("limit"), 100, 500);
            taotie_api::get_finding_summary(case_root, Some(limit))
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
                .map_err(to_json)
        }
        "get_timeline" => {
            let granularity = str_arg(args, "granularity").unwrap_or_else(|| "hour".to_string());
            taotie_api::get_timeline_bins(case_root, &granularity)
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
                .map_err(to_json)
        }
        "get_correlation_chains" => {
            let limit = clamp_limit(args.get("limit"), 20, 100);
            taotie_api::get_correlation_chains(case_root, Some(limit))
                .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
                .map_err(to_json)
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

fn str_arg(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn clamp_limit(value: Option<&Value>, default: usize, max: usize) -> usize {
    value
        .and_then(Value::as_u64)
        .map(|n| (n as usize).clamp(1, max))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(response: Option<String>) -> Value {
        serde_json::from_str(&response.expect("expected a response")).expect("valid json")
    }

    #[test]
    fn initialize_echoes_protocol_version_and_advertises_tools() {
        let response = parse(handle_line(
            "/nonexistent",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
        ));
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(response["result"]["serverInfo"]["name"], "taotie-mcp");
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn notifications_and_garbage_get_no_response() {
        assert!(handle_line(
            "/x",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .is_none());
        assert!(handle_line("/x", "not json at all").is_none());
    }

    #[test]
    fn tools_list_names_all_six_tools() {
        let response = parse(handle_line(
            "/nonexistent",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ));
        let tools = response["result"]["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(
            names,
            [
                "case_summary",
                "search_events",
                "get_event_detail",
                "list_findings",
                "get_timeline",
                "get_correlation_chains"
            ]
        );
        for tool in tools {
            assert!(
                tool["inputSchema"]["type"] == "object",
                "schema for {}",
                tool["name"]
            );
        }
    }

    #[test]
    fn unknown_method_is_json_rpc_error_but_unknown_tool_is_tool_error() {
        let response = parse(handle_line(
            "/nonexistent",
            r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#,
        ));
        assert_eq!(response["error"]["code"], -32601);

        let response = parse(handle_line(
            "/nonexistent",
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
        ));
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn tool_error_on_missing_case_is_soft_not_protocol_error() {
        let response = parse(handle_line(
            "/definitely/not/a/case",
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"case_summary","arguments":{}}}"#,
        ));
        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(clamp_limit(Some(&json!(0)), 50, 200), 1);
        assert_eq!(clamp_limit(Some(&json!(9999)), 50, 200), 200);
        assert_eq!(clamp_limit(None, 50, 200), 50);
    }
}
