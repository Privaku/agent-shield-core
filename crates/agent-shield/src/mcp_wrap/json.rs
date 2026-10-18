use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::{
    encode_json, is_http_or_sse, is_wrapped_proxy, proxy_argv, split_proxy_argv,
    wrapped_proxy_is_current, EditResult, McpConfigFormat, McpLocations,
};

/// JSON `mcpServers` object used by Claude Desktop, Claude Code, and Cursor.
pub struct JsonMcpServersFormat {
    label: &'static str,
    locate: fn(&dyn McpLocations) -> Vec<PathBuf>,
}

impl JsonMcpServersFormat {
    pub fn claude_desktop() -> Self {
        Self {
            label: "Claude Desktop",
            locate: |locations| vec![locations.claude_desktop_config()],
        }
    }

    pub fn claude_code() -> Self {
        Self {
            label: "Claude Code",
            locate: |locations| {
                vec![
                    locations.home().join(".claude.json"),
                    locations.project().join(".mcp.json"),
                ]
            },
        }
    }

    pub fn cursor() -> Self {
        Self {
            label: "Cursor",
            locate: |locations| {
                vec![
                    locations.home().join(".cursor/mcp.json"),
                    locations.project().join(".cursor/mcp.json"),
                ]
            },
        }
    }
}

impl McpConfigFormat for JsonMcpServersFormat {
    fn label(&self) -> &'static str {
        self.label
    }

    fn config_paths(&self, locations: &dyn McpLocations) -> Vec<PathBuf> {
        (self.locate)(locations)
    }

    fn wrap(&self, bytes: &[u8], binary: &Path) -> Result<EditResult> {
        edit_json(bytes, binary, EditMode::Wrap)
    }

    fn unwrap(&self, bytes: &[u8], binary: &Path) -> Result<EditResult> {
        edit_json(bytes, binary, EditMode::Unwrap)
    }
}

#[derive(Clone, Copy)]
enum EditMode {
    Wrap,
    Unwrap,
}

fn edit_json(bytes: &[u8], binary: &Path, mode: EditMode) -> Result<EditResult> {
    let mut document: Value = serde_json::from_slice(bytes)
        .map_err(|error| anyhow!("MCP config is not valid JSON: {error}"))?;
    let root = document
        .as_object_mut()
        .ok_or_else(|| anyhow!("MCP config must be a JSON object"))?;
    let Some(servers_value) = root.get_mut("mcpServers") else {
        return Ok(unchanged(bytes));
    };
    let servers = servers_value
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcpServers must be a JSON object"))?;

    let mut changed = false;
    let mut wrapped = Vec::new();
    let mut unwrapped = Vec::new();
    let mut skipped_http = Vec::new();

    for (name, entry) in servers.iter_mut() {
        match edit_entry(name, entry, binary, mode)? {
            EntryEdit::Wrapped => {
                changed = true;
                wrapped.push(name.clone());
            }
            EntryEdit::Unwrapped => {
                changed = true;
                unwrapped.push(name.clone());
            }
            EntryEdit::SkippedHttp => skipped_http.push(name.clone()),
            EntryEdit::Unchanged => {}
        }
    }

    if !changed {
        return Ok(EditResult {
            bytes: bytes.to_vec(),
            changed: false,
            wrapped,
            unwrapped,
            skipped_http,
        });
    }

    Ok(EditResult {
        bytes: encode_json(&document)?,
        changed: true,
        wrapped,
        unwrapped,
        skipped_http,
    })
}

enum EntryEdit {
    Wrapped,
    Unwrapped,
    SkippedHttp,
    Unchanged,
}

fn edit_entry(name: &str, entry: &mut Value, binary: &Path, mode: EditMode) -> Result<EntryEdit> {
    let object = entry
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcpServers.{name} must be a JSON object"))?;
    let type_field = object.get("type").and_then(Value::as_str);
    let has_url = object.get("url").and_then(Value::as_str).is_some();
    let has_command = object.get("command").and_then(Value::as_str).is_some();
    if is_http_or_sse(type_field, has_url, has_command) {
        return Ok(EntryEdit::SkippedHttp);
    }
    let Some(command) = object.get("command").and_then(Value::as_str) else {
        return Ok(EntryEdit::Unchanged);
    };
    let command = command.to_string();
    let args = string_array(object.get("args"), &format!("mcpServers.{name}.args"))?;

    match mode {
        EditMode::Wrap => wrap_stdio(name, object, &command, &args, binary),
        EditMode::Unwrap => unwrap_stdio(name, object, &command, &args),
    }
}

fn wrap_stdio(
    name: &str,
    object: &mut Map<String, Value>,
    command: &str,
    args: &[String],
    binary: &Path,
) -> Result<EntryEdit> {
    if is_wrapped_proxy(command, args) {
        if wrapped_proxy_is_current(command, args, name, binary) {
            return Ok(EntryEdit::Unchanged);
        }
        let (orig_command, orig_args) = split_proxy_argv(args)
            .ok_or_else(|| anyhow!("mcpServers.{name} is not a valid mcp-proxy wrapper"))?;
        object.insert(
            "command".to_string(),
            json!(binary.to_string_lossy().into_owned()),
        );
        object.insert(
            "args".to_string(),
            json!(proxy_argv(name, &orig_command, &orig_args)),
        );
        return Ok(EntryEdit::Wrapped);
    }

    object.insert(
        "command".to_string(),
        json!(binary.to_string_lossy().into_owned()),
    );
    object.insert("args".to_string(), json!(proxy_argv(name, command, args)));
    Ok(EntryEdit::Wrapped)
}

fn unwrap_stdio(
    name: &str,
    object: &mut Map<String, Value>,
    command: &str,
    args: &[String],
) -> Result<EntryEdit> {
    if !is_wrapped_proxy(command, args) {
        return Ok(EntryEdit::Unchanged);
    }
    let (orig_command, orig_args) = split_proxy_argv(args)
        .ok_or_else(|| anyhow!("mcpServers.{name} is not a valid mcp-proxy wrapper"))?;
    object.insert("command".to_string(), json!(orig_command));
    object.insert("args".to_string(), json!(orig_args));
    Ok(EntryEdit::Unwrapped)
}

fn string_array(value: Option<&Value>, name: &str) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let array = value
        .as_array()
        .ok_or_else(|| anyhow!("{name} must be a JSON array"))?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("{name} entries must be strings"))
        })
        .collect()
}

fn unchanged(bytes: &[u8]) -> EditResult {
    EditResult {
        bytes: bytes.to_vec(),
        changed: false,
        wrapped: Vec::new(),
        unwrapped: Vec::new(),
        skipped_http: Vec::new(),
    }
}
