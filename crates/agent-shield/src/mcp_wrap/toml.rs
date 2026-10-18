use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use toml_edit::{Array, DocumentMut, Item, Value};

use super::{
    is_http_or_sse, is_wrapped_proxy, proxy_argv, split_proxy_argv, wrapped_proxy_is_current,
    EditResult, McpConfigFormat, McpLocations,
};

/// Codex `~/.codex/config.toml` `[mcp_servers]` tables.
pub struct TomlMcpServersFormat;

impl TomlMcpServersFormat {
    pub fn codex() -> Self {
        Self
    }
}

impl McpConfigFormat for TomlMcpServersFormat {
    fn label(&self) -> &'static str {
        "Codex"
    }

    fn config_paths(&self, locations: &dyn McpLocations) -> Vec<PathBuf> {
        vec![locations.home().join(".codex/config.toml")]
    }

    fn wrap(&self, bytes: &[u8], binary: &Path) -> Result<EditResult> {
        edit_toml(bytes, binary, EditMode::Wrap)
    }

    fn unwrap(&self, bytes: &[u8], binary: &Path) -> Result<EditResult> {
        edit_toml(bytes, binary, EditMode::Unwrap)
    }
}

#[derive(Clone, Copy)]
enum EditMode {
    Wrap,
    Unwrap,
}

fn edit_toml(bytes: &[u8], binary: &Path, mode: EditMode) -> Result<EditResult> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| anyhow!("Codex config is not valid UTF-8: {error}"))?;
    let mut document: DocumentMut = text
        .parse()
        .map_err(|error| anyhow!("Codex config is not valid TOML: {error}"))?;
    let Some(servers_item) = document.get_mut("mcp_servers") else {
        return Ok(unchanged(bytes));
    };
    let keys: Vec<String> = {
        let Some(servers) = servers_item.as_table_like() else {
            return Err(anyhow!("mcp_servers must be a TOML table"));
        };
        servers.iter().map(|(key, _)| key.to_string()).collect()
    };

    let mut changed = false;
    let mut wrapped = Vec::new();
    let mut unwrapped = Vec::new();
    let mut skipped_http = Vec::new();

    for name in keys {
        let item = document["mcp_servers"]
            .get_mut(&name)
            .ok_or_else(|| anyhow!("mcp_servers.{name} disappeared while editing"))?;
        match edit_entry(&name, item, binary, mode)? {
            EntryEdit::Wrapped => {
                changed = true;
                wrapped.push(name);
            }
            EntryEdit::Unwrapped => {
                changed = true;
                unwrapped.push(name);
            }
            EntryEdit::SkippedHttp => skipped_http.push(name),
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
        bytes: document.to_string().into_bytes(),
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

fn edit_entry(name: &str, item: &mut Item, binary: &Path, mode: EditMode) -> Result<EntryEdit> {
    let type_field = item_str(item, "type").map(str::to_string);
    let has_url = item_str(item, "url").is_some();
    let has_command = item_str(item, "command").is_some();
    if is_http_or_sse(type_field.as_deref(), has_url, has_command) {
        return Ok(EntryEdit::SkippedHttp);
    }
    let Some(command) = item_str(item, "command").map(str::to_string) else {
        return Ok(EntryEdit::Unchanged);
    };
    let args = item_strings(item, "args", name)?;

    match mode {
        EditMode::Wrap => wrap_stdio(name, item, &command, &args, binary),
        EditMode::Unwrap => unwrap_stdio(name, item, &command, &args),
    }
}

fn wrap_stdio(
    name: &str,
    item: &mut Item,
    command: &str,
    args: &[String],
    binary: &Path,
) -> Result<EntryEdit> {
    if is_wrapped_proxy(command, args) {
        if wrapped_proxy_is_current(command, args, name, binary) {
            return Ok(EntryEdit::Unchanged);
        }
        let (orig_command, orig_args) = split_proxy_argv(args)
            .ok_or_else(|| anyhow!("mcp_servers.{name} is not a valid mcp-proxy wrapper"))?;
        set_command_and_args(
            item,
            binary.to_string_lossy().as_ref(),
            &proxy_argv(name, &orig_command, &orig_args),
        )?;
        return Ok(EntryEdit::Wrapped);
    }
    set_command_and_args(
        item,
        binary.to_string_lossy().as_ref(),
        &proxy_argv(name, command, args),
    )?;
    Ok(EntryEdit::Wrapped)
}

fn unwrap_stdio(name: &str, item: &mut Item, command: &str, args: &[String]) -> Result<EntryEdit> {
    if !is_wrapped_proxy(command, args) {
        return Ok(EntryEdit::Unchanged);
    }
    let (orig_command, orig_args) = split_proxy_argv(args)
        .ok_or_else(|| anyhow!("mcp_servers.{name} is not a valid mcp-proxy wrapper"))?;
    set_command_and_args(item, &orig_command, &orig_args)?;
    Ok(EntryEdit::Unwrapped)
}

fn set_command_and_args(item: &mut Item, command: &str, args: &[String]) -> Result<()> {
    let table = item
        .as_table_like_mut()
        .ok_or_else(|| anyhow!("MCP server entry must be a TOML table"))?;
    table.insert("command", toml_edit::value(command));
    let mut array = Array::new();
    for arg in args {
        array.push(arg.as_str());
    }
    table.insert("args", Item::Value(Value::Array(array)));
    Ok(())
}

fn item_str<'a>(item: &'a Item, key: &str) -> Option<&'a str> {
    item.as_table_like()
        .and_then(|table| table.get(key))
        .and_then(Item::as_str)
}

fn item_strings(item: &Item, key: &str, name: &str) -> Result<Vec<String>> {
    let Some(table) = item.as_table_like() else {
        return Ok(Vec::new());
    };
    let Some(value) = table.get(key) else {
        return Ok(Vec::new());
    };
    if value.is_none() {
        return Ok(Vec::new());
    }
    let Some(array) = value.as_array() else {
        return Err(anyhow!("mcp_servers.{name}.{key} must be an array"));
    };
    array
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("mcp_servers.{name}.{key} entries must be strings"))
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
