//! MCP config wrapping for `agent-shield install --mcp`.
//!
//! Each on-disk format implements [`McpConfigFormat`]. Platform path lookup
//! lives behind [`McpLocations`] so tests inject HOME, the project directory,
//! and the Linux XDG Claude Desktop path without `cfg(target_os = "macos")`
//! outside a trait implementation.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::install::{atomic_write, latest_backup, write_backup};

mod json;
mod toml;

pub use json::JsonMcpServersFormat;
pub use toml::TomlMcpServersFormat;

/// Locator for every MCP config this milestone wraps.
///
/// Claude Desktop stores `claude_desktop_config.json` at
/// `~/Library/Application Support/Claude/` on macOS. On Linux (and in
/// tests) the same file is `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json`,
/// falling back to `$HOME/.config/Claude/claude_desktop_config.json` when
/// `XDG_CONFIG_HOME` is unset.
pub trait McpLocations {
    fn home(&self) -> &Path;
    fn project(&self) -> &Path;
    #[allow(dead_code)]
    fn xdg_config_home(&self) -> PathBuf;
    fn claude_desktop_config(&self) -> PathBuf;
}

/// HOME / project / XDG paths, injectable for tests.
#[derive(Debug, Clone)]
pub struct EnvMcpLocations {
    home: PathBuf,
    project: PathBuf,
    #[allow(dead_code)]
    xdg_config_home: Option<PathBuf>,
}

impl EnvMcpLocations {
    pub fn from_env() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set"))?;
        let project = std::env::current_dir().context("cannot locate the current directory")?;
        let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Ok(Self::new(home, project, xdg_config_home))
    }

    pub fn new(home: PathBuf, project: PathBuf, xdg_config_home: Option<PathBuf>) -> Self {
        Self {
            home,
            project,
            xdg_config_home,
        }
    }
}

impl McpLocations for EnvMcpLocations {
    fn home(&self) -> &Path {
        &self.home
    }

    fn project(&self) -> &Path {
        &self.project
    }

    fn xdg_config_home(&self) -> PathBuf {
        self.xdg_config_home
            .clone()
            .unwrap_or_else(|| self.home.join(".config"))
    }

    fn claude_desktop_config(&self) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            self.home
                .join("Library/Application Support/Claude/claude_desktop_config.json")
        }

        #[cfg(not(target_os = "macos"))]
        {
            self.xdg_config_home()
                .join("Claude/claude_desktop_config.json")
        }
    }
}

/// One MCP config format (JSON `mcpServers` or TOML `[mcp_servers]`).
pub trait McpConfigFormat {
    fn label(&self) -> &'static str;
    fn config_paths(&self, locations: &dyn McpLocations) -> Vec<PathBuf>;
    fn wrap(&self, bytes: &[u8], binary: &Path) -> Result<EditResult>;
    fn unwrap(&self, bytes: &[u8], binary: &Path) -> Result<EditResult>;
}

/// Result of wrapping or unwrapping one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditResult {
    pub bytes: Vec<u8>,
    pub changed: bool,
    pub wrapped: Vec<String>,
    pub unwrapped: Vec<String>,
    pub skipped_http: Vec<String>,
}

/// Outcome for one existing config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOutcome {
    pub label: &'static str,
    pub path: PathBuf,
    pub changed: bool,
    pub wrapped: Vec<String>,
    pub unwrapped: Vec<String>,
    pub skipped_http: Vec<String>,
    pub diff: Option<String>,
}

/// Finds stdio MCP servers and rewrites them through `mcp-proxy`.
pub struct McpWrapper {
    locations: EnvMcpLocations,
    binary: PathBuf,
    formats: Vec<Box<dyn McpConfigFormat>>,
}

impl McpWrapper {
    pub fn from_env() -> Result<Self> {
        let locations = EnvMcpLocations::from_env()?;
        let binary = std::env::current_exe()
            .context("cannot locate the current agent-shield binary")?
            .canonicalize()
            .context("cannot resolve the current agent-shield binary")?;
        Ok(Self::new(locations, binary))
    }

    pub fn new(locations: EnvMcpLocations, binary: PathBuf) -> Self {
        Self {
            locations,
            binary,
            formats: formats(),
        }
    }

    pub fn wrap_with(&self, dry_run: bool) -> Result<Vec<FileOutcome>> {
        self.edit_all(EditKind::Wrap, dry_run)
    }

    pub fn unwrap_with(&self, dry_run: bool) -> Result<Vec<FileOutcome>> {
        self.edit_all(EditKind::Unwrap, dry_run)
    }

    fn edit_all(&self, kind: EditKind, dry_run: bool) -> Result<Vec<FileOutcome>> {
        let mut outcomes = Vec::new();
        for format in &self.formats {
            for path in format.config_paths(&self.locations) {
                match kind {
                    EditKind::Wrap => {
                        if let Some(outcome) = self.wrap_file(format.as_ref(), &path, dry_run)? {
                            outcomes.push(outcome);
                        }
                    }
                    EditKind::Unwrap => {
                        if let Some(outcome) = self.unwrap_file(format.as_ref(), &path, dry_run)? {
                            outcomes.push(outcome);
                        }
                    }
                }
            }
        }
        Ok(outcomes)
    }

    fn wrap_file(
        &self,
        format: &dyn McpConfigFormat,
        path: &Path,
        dry_run: bool,
    ) -> Result<Option<FileOutcome>> {
        let original = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let result = format
            .wrap(&original, &self.binary)
            .with_context(|| format!("cannot wrap {}", path.display()))?;
        let mut outcome = outcome_from(format.label(), path, result.clone());
        if result.changed {
            outcome.diff = Some(unified_diff(path, &original, &result.bytes));
            if !dry_run {
                write_backup(path, Some(&original))?;
                atomic_write(path, &result.bytes)?;
            }
        }
        Ok(Some(outcome))
    }

    fn unwrap_file(
        &self,
        format: &dyn McpConfigFormat,
        path: &Path,
        dry_run: bool,
    ) -> Result<Option<FileOutcome>> {
        let current = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let result = format
            .unwrap(&current, &self.binary)
            .with_context(|| format!("cannot unwrap {}", path.display()))?;
        if !result.changed {
            return Ok(Some(outcome_from(format.label(), path, result)));
        }

        let mut restore = result.bytes.clone();
        let mut delete = false;
        if let Some(backup) = latest_backup(path)? {
            let original = fs::read(&backup.path)
                .with_context(|| format!("cannot read backup {}", backup.path.display()))?;
            let reconstructed = if backup.was_absent {
                Vec::new()
            } else {
                original.clone()
            };
            let wrapped = format.wrap(&reconstructed, &self.binary)?;
            if wrapped.bytes == current {
                if backup.was_absent {
                    restore = Vec::new();
                    delete = true;
                } else {
                    restore = original;
                }
            }
        }

        let mut outcome = outcome_from(format.label(), path, result);
        outcome.diff = Some(unified_diff(path, &current, &restore));
        if !dry_run {
            if delete {
                fs::remove_file(path)
                    .with_context(|| format!("cannot remove {}", path.display()))?;
            } else {
                atomic_write(path, &restore)?;
            }
        }
        Ok(Some(outcome))
    }
}

#[derive(Clone, Copy)]
enum EditKind {
    Wrap,
    Unwrap,
}

fn formats() -> Vec<Box<dyn McpConfigFormat>> {
    vec![
        Box::new(JsonMcpServersFormat::claude_desktop()),
        Box::new(JsonMcpServersFormat::claude_code()),
        Box::new(JsonMcpServersFormat::cursor()),
        Box::new(TomlMcpServersFormat::codex()),
    ]
}

fn outcome_from(label: &'static str, path: &Path, result: EditResult) -> FileOutcome {
    FileOutcome {
        label,
        path: path.to_path_buf(),
        changed: result.changed,
        wrapped: result.wrapped,
        unwrapped: result.unwrapped,
        skipped_http: result.skipped_http,
        diff: None,
    }
}

pub fn print_wrap_report(outcomes: &[FileOutcome], dry_run: bool) {
    if outcomes.is_empty() {
        println!("No MCP server configs found.");
        return;
    }
    let mut wrapped = 0usize;
    let mut skipped = 0usize;
    for outcome in outcomes {
        for name in &outcome.wrapped {
            println!(
                "Wrapped stdio MCP server '{name}' in {}",
                outcome.path.display()
            );
            wrapped += 1;
        }
        for name in &outcome.skipped_http {
            println!(
                "Skipping HTTP/SSE MCP server '{name}' in {} (post-MVP)",
                outcome.path.display()
            );
            skipped += 1;
        }
    }
    if wrapped == 0 && skipped == 0 {
        println!("MCP configs already wrapped.");
    } else if wrapped == 0 {
        println!("No stdio MCP servers to wrap.");
    }
    print_diffs(outcomes, dry_run);
}

pub fn print_unwrap_report(outcomes: &[FileOutcome], dry_run: bool) {
    if outcomes.is_empty() {
        println!("No MCP server configs found.");
        return;
    }
    let mut unwrapped = 0usize;
    for outcome in outcomes {
        for name in &outcome.unwrapped {
            println!(
                "Unwrapped stdio MCP server '{name}' in {}",
                outcome.path.display()
            );
            unwrapped += 1;
        }
    }
    if unwrapped == 0 {
        println!("No Agent Shield MCP wrappers were installed.");
    }
    print_diffs(outcomes, dry_run);
}

fn print_diffs(outcomes: &[FileOutcome], dry_run: bool) {
    if !dry_run {
        return;
    }
    for outcome in outcomes {
        if let Some(diff) = &outcome.diff {
            println!("{diff}");
        }
    }
    println!("Dry-run: no files were written.");
}

fn unified_diff(path: &Path, before: &[u8], after: &[u8]) -> String {
    let before = String::from_utf8_lossy(before);
    let after = String::from_utf8_lossy(after);
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();
    let mut output = format!("--- {}\n+++ {}\n", path.display(), path.display());
    output.push_str(&format!(
        "@@ -1,{} +1,{} @@\n",
        before_lines.len(),
        after_lines.len()
    ));
    for (kind, line) in line_edits(&before_lines, &after_lines) {
        output.push(kind);
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn line_edits<'a>(before: &'a [&str], after: &'a [&str]) -> Vec<(char, &'a str)> {
    let mut dp = vec![vec![0usize; after.len() + 1]; before.len() + 1];
    for i in 0..before.len() {
        for j in 0..after.len() {
            dp[i + 1][j + 1] = if before[i] == after[j] {
                dp[i][j] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut edits = Vec::new();
    let mut i = before.len();
    let mut j = after.len();
    while i > 0 && j > 0 {
        if before[i - 1] == after[j - 1] {
            edits.push((' ', before[i - 1]));
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            edits.push(('-', before[i - 1]));
            i -= 1;
        } else {
            edits.push(('+', after[j - 1]));
            j -= 1;
        }
    }
    while i > 0 {
        edits.push(('-', before[i - 1]));
        i -= 1;
    }
    while j > 0 {
        edits.push(('+', after[j - 1]));
        j -= 1;
    }
    edits.reverse();
    edits
}

pub(crate) fn proxy_argv(name: &str, command: &str, args: &[String]) -> Vec<String> {
    let mut argv = vec![
        "mcp-proxy".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--".to_string(),
        command.to_string(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

pub(crate) fn split_proxy_argv(args: &[String]) -> Option<(String, Vec<String>)> {
    if args.len() < 5 {
        return None;
    }
    if args[0] != "mcp-proxy" || args[1] != "--name" || args[3] != "--" {
        return None;
    }
    let command = args[4].clone();
    let rest = args[5..].to_vec();
    Some((command, rest))
}

pub(crate) fn is_agent_shield_binary(command: &str) -> bool {
    Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "agent-shield" || name == "agent-shield.exe")
}

pub(crate) fn is_wrapped_proxy(command: &str, args: &[String]) -> bool {
    is_agent_shield_binary(command) && split_proxy_argv(args).is_some()
}

pub(crate) fn wrapped_proxy_is_current(
    command: &str,
    args: &[String],
    name: &str,
    binary: &Path,
) -> bool {
    split_proxy_argv(args).is_some()
        && command == binary.to_string_lossy()
        && args.len() >= 4
        && args[0] == "mcp-proxy"
        && args[1] == "--name"
        && args[2] == name
        && args[3] == "--"
}

pub(crate) fn is_http_or_sse(type_field: Option<&str>, has_url: bool, has_command: bool) -> bool {
    if let Some(kind) = type_field {
        match kind.to_ascii_lowercase().as_str() {
            "sse" | "http" | "streamablehttp" | "streamable-http" | "streamable_http" => {
                return true;
            }
            "stdio" => return false,
            _ => {}
        }
    }
    has_url && !has_command
}

fn encode_json(document: &serde_json::Value) -> Result<Vec<u8>> {
    let mut output = serde_json::to_vec_pretty(document)?;
    output.push(b'\n');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn wrapper(home: &Path, project: &Path) -> McpWrapper {
        McpWrapper::new(
            EnvMcpLocations::new(home.to_path_buf(), project.to_path_buf(), None),
            PathBuf::from("/opt/agent-shield"),
        )
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn json_wrap_preserves_env_and_skips_http() {
        let format = JsonMcpServersFormat::cursor();
        let original = json!({
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "pkg"],
                    "env": {"TOKEN": "keep"}
                },
                "remote": {
                    "type": "sse",
                    "url": "https://example.com/mcp"
                }
            }
        });
        let bytes = serde_json::to_vec(&original).unwrap();
        let result = format.wrap(&bytes, Path::new("/opt/agent-shield")).unwrap();
        assert!(result.changed);
        assert_eq!(result.wrapped, vec!["fs"]);
        assert_eq!(result.skipped_http, vec!["remote"]);
        let document: Value = serde_json::from_slice(&result.bytes).unwrap();
        assert_eq!(document["mcpServers"]["fs"]["command"], "/opt/agent-shield");
        assert_eq!(
            document["mcpServers"]["fs"]["args"],
            json!(["mcp-proxy", "--name", "fs", "--", "npx", "-y", "pkg"])
        );
        assert_eq!(document["mcpServers"]["fs"]["env"]["TOKEN"], "keep");
        assert_eq!(
            document["mcpServers"]["remote"]["url"],
            "https://example.com/mcp"
        );
    }

    #[test]
    fn json_rewrap_is_a_no_op() {
        let format = JsonMcpServersFormat::claude_code();
        let original = json!({
            "mcpServers": {
                "docs": {"command": "uvx", "args": ["mcp-docs"]}
            }
        });
        let first = format
            .wrap(
                &serde_json::to_vec(&original).unwrap(),
                Path::new("/opt/agent-shield"),
            )
            .unwrap();
        let second = format
            .wrap(&first.bytes, Path::new("/opt/agent-shield"))
            .unwrap();
        assert!(!second.changed);
        assert_eq!(second.bytes, first.bytes);
    }

    #[test]
    fn json_never_double_wraps_an_existing_proxy() {
        let format = JsonMcpServersFormat::claude_desktop();
        let already = json!({
            "mcpServers": {
                "fs": {
                    "command": "/old/agent-shield",
                    "args": ["mcp-proxy", "--name", "fs", "--", "npx", "-y", "pkg"]
                }
            }
        });
        let result = format
            .wrap(
                &serde_json::to_vec(&already).unwrap(),
                Path::new("/opt/agent-shield"),
            )
            .unwrap();
        assert!(result.changed);
        let document: Value = serde_json::from_slice(&result.bytes).unwrap();
        assert_eq!(document["mcpServers"]["fs"]["command"], "/opt/agent-shield");
        assert_eq!(
            document["mcpServers"]["fs"]["args"],
            json!(["mcp-proxy", "--name", "fs", "--", "npx", "-y", "pkg"])
        );
    }

    #[test]
    fn wrap_then_unwrap_restores_json_configs_byte_for_byte() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        let originals = [
            (
                home.join(".cursor/mcp.json"),
                "{\n  \"mcpServers\": {\n    \"fs\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"pkg\"],\n      \"env\": {\"TOKEN\": \"keep\"}\n    }\n  }\n}\n",
            ),
            (
                home.join(".claude.json"),
                "{\"theme\":\"dark\",\"mcpServers\":{\"docs\":{\"command\":\"uvx\",\"args\":[\"mcp-docs\"]}}}\n",
            ),
            (
                project.join(".mcp.json"),
                "{\n  \"mcpServers\": { \"local\": { \"command\": \"node\", \"args\": [\"server.js\"] } }\n}\n",
            ),
            (
                project.join(".cursor/mcp.json"),
                "{\"mcpServers\":{\"http\":{\"url\":\"https://example.com\"},\"stdio\":{\"command\":\"python\",\"args\":[\"-m\",\"mcp\"]}}}\n",
            ),
            (
                home.join(".config/Claude/claude_desktop_config.json"),
                "{\n \"mcpServers\": { \"desktop\": { \"command\": \"npx\", \"args\": [\"-y\", \"desktop\"] } }\n}\n",
            ),
        ];
        for (path, contents) in &originals {
            write(path, contents);
        }
        let wrapper = wrapper(&home, &project);
        wrapper.wrap_with(false).unwrap();
        let wrapped: Vec<Vec<u8>> = originals
            .iter()
            .map(|(path, _)| fs::read(path).unwrap())
            .collect();
        wrapper.wrap_with(false).unwrap();
        for (index, (path, _)) in originals.iter().enumerate() {
            assert_eq!(
                fs::read(path).unwrap(),
                wrapped[index],
                "{}",
                path.display()
            );
        }
        wrapper.unwrap_with(false).unwrap();
        for (path, contents) in originals {
            assert_eq!(
                fs::read(&path).unwrap(),
                contents.as_bytes(),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn toml_wrap_preserves_env_comments_and_skips_http() {
        let original = r#"# keep this comment
[mcp_servers.fs]
command = "npx"
args = ["-y", "pkg"]

[mcp_servers.fs.env]
TOKEN = "keep"

[mcp_servers.remote]
url = "https://example.com/mcp"
"#;
        let format = TomlMcpServersFormat::codex();
        let result = format
            .wrap(original.as_bytes(), Path::new("/opt/agent-shield"))
            .unwrap();
        assert!(result.changed);
        assert_eq!(result.wrapped, vec!["fs"]);
        assert_eq!(result.skipped_http, vec!["remote"]);
        let text = String::from_utf8(result.bytes.clone()).unwrap();
        assert!(text.contains("# keep this comment"));
        assert!(text.contains("TOKEN = \"keep\""));
        assert!(text.contains("url = \"https://example.com/mcp\""));
        assert!(text.contains("mcp-proxy"));
        assert!(text.contains("/opt/agent-shield"));
        let second = format
            .wrap(&result.bytes, Path::new("/opt/agent-shield"))
            .unwrap();
        assert!(!second.changed);
        assert_eq!(second.bytes, result.bytes);
    }

    #[test]
    fn wrap_then_unwrap_restores_codex_toml_byte_for_byte() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        let original = "# header\n[mcp_servers.docs]\ncommand = \"uvx\"\nargs = [\"mcp-docs\"]\n\n[mcp_servers.docs.env]\nTOKEN = \"keep\"\n";
        let path = home.join(".codex/config.toml");
        write(&path, original);
        let wrapper = wrapper(&home, &project);
        wrapper.wrap_with(false).unwrap();
        let wrapped = fs::read(&path).unwrap();
        wrapper.wrap_with(false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), wrapped);
        wrapper.unwrap_with(false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
    }

    fn backup_count(path: &Path) -> usize {
        let filename = path.file_name().unwrap().to_string_lossy();
        let prefix = format!("{filename}.agent-shield.");
        fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .count()
    }

    #[test]
    fn dry_run_wrap_produces_a_diff_and_writes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        let path = home.join(".cursor/mcp.json");
        let original =
            "{\n  \"mcpServers\": { \"fs\": { \"command\": \"npx\", \"args\": [\"-y\", \"pkg\"] } }\n}\n";
        write(&path, original);
        let wrapper = wrapper(&home, &project);
        let outcomes = wrapper.wrap_with(true).unwrap();
        let outcome = outcomes.iter().find(|item| item.path == path).unwrap();
        let diff = outcome
            .diff
            .as_ref()
            .expect("dry-run should produce a diff");
        assert!(diff.contains("--- "));
        assert!(diff.contains("+++ "));
        assert!(diff.contains("mcp-proxy"));
        assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
        assert_eq!(backup_count(&path), 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn linux_claude_desktop_uses_xdg_then_home_config() {
        let xdg = EnvMcpLocations::new(
            PathBuf::from("/home/me"),
            PathBuf::from("/repo"),
            Some(PathBuf::from("/xdg-config")),
        );
        assert_eq!(
            xdg.claude_desktop_config(),
            PathBuf::from("/xdg-config/Claude/claude_desktop_config.json")
        );
        let fallback =
            EnvMcpLocations::new(PathBuf::from("/home/me"), PathBuf::from("/repo"), None);
        assert_eq!(
            fallback.claude_desktop_config(),
            PathBuf::from("/home/me/.config/Claude/claude_desktop_config.json")
        );
    }
}
