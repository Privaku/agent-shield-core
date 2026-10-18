use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use serde_json::{json, Value};

const LOG_ENV: &str = "FAKE_MCP_LOG";
const AWS_EXAMPLE_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";

fn main() -> io::Result<()> {
    let log_path = env::var_os(LOG_ENV).map(PathBuf::from);
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = line?;
        if let Some(path) = &log_path {
            let mut log = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(log, "{line}")?;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(_) => continue,
        };
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        let response = match request.get("method").and_then(Value::as_str) {
            Some("initialize") => success(
                id,
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-mcp-server", "version": "0.1.0"}
                }),
            ),
            Some("tools/list") => success(
                id,
                json!({
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read a file",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "echo",
                            "description": "Echo a message",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"message": {}}
                            }
                        },
                        {
                            "name": "fetch",
                            "description": "Return a canned remote payload",
                            "inputSchema": {"type": "object"}
                        }
                    ]
                }),
            ),
            Some("tools/call") => tool_call(id, request.get("params")),
            Some(method) => error(id, -32601, format!("Method not found: {method}")),
            None => error(id, -32600, "Invalid Request".to_string()),
        };
        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

fn tool_call(id: Value, params: Option<&Value>) -> Value {
    let Some(name) = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
    else {
        return error(id, -32602, "Missing tool name".to_string());
    };
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "echo" => success(
            id,
            json!({"content": [{"type": "text", "text": arguments.to_string()}]}),
        ),
        "read_file" => {
            let path = arguments
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let content =
                fs::read_to_string(path).unwrap_or_else(|_| format!("canned content for {path}"));
            success(id, json!({"content": [{"type": "text", "text": content}]}))
        }
        "fetch" => success(
            id,
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("example cloud credential: {AWS_EXAMPLE_KEY_ID}")
                }]
            }),
        ),
        _ => error(id, -32602, format!("Unknown tool: {name}")),
    }
}

fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}
