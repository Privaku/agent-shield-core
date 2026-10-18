use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Map, Value};

use crate::mcp_wrap::{print_unwrap_report, print_wrap_report, McpWrapper};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Cursor,
    Codex,
}

impl Agent {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Cursor => "cursor",
            Agent::Codex => "codex",
        }
    }

    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code",
            Agent::Cursor => "Cursor",
            Agent::Codex => "Codex",
        }
    }
}

/// Portable seam for one agent configuration format.
///
/// Implementations only know how to locate and mutate their own JSON shape.
/// Filesystem and process discovery stay in [`Installer`], so another
/// platform can supply format implementations without changing install flow.
pub trait HookInstaller {
    fn agent(&self) -> Agent;
    fn relative_config_path(&self) -> &'static Path;
    fn merge_hook(&self, document: &mut Value, command: &str) -> Result<bool>;
    fn remove_hook(&self, document: &mut Value) -> Result<bool>;
    fn diagnose_hook(&self, document: &Value, command: &str) -> Result<Vec<String>>;

    fn is_detected(&self, home: &Path) -> bool {
        let path = home.join(self.relative_config_path());
        path.exists() || path.parent().is_some_and(Path::exists)
    }
}

#[derive(Debug, Default)]
pub struct ClaudeHookInstaller;

impl HookInstaller for ClaudeHookInstaller {
    fn agent(&self) -> Agent {
        Agent::Claude
    }

    fn relative_config_path(&self) -> &'static Path {
        Path::new(".claude/settings.json")
    }

    fn merge_hook(&self, document: &mut Value, command: &str) -> Result<bool> {
        merge_pre_tool_use(document, command, Agent::Claude, "Claude settings")
    }

    fn remove_hook(&self, document: &mut Value) -> Result<bool> {
        remove_pre_tool_use(document, Agent::Claude, "Claude settings")
    }

    fn diagnose_hook(&self, document: &Value, command: &str) -> Result<Vec<String>> {
        diagnose_pre_tool_use(document, command, Agent::Claude, "Claude settings")
    }
}

#[derive(Debug, Default)]
pub struct CodexHookInstaller;

impl HookInstaller for CodexHookInstaller {
    fn agent(&self) -> Agent {
        Agent::Codex
    }

    fn relative_config_path(&self) -> &'static Path {
        Path::new(".codex/hooks.json")
    }

    fn merge_hook(&self, document: &mut Value, command: &str) -> Result<bool> {
        merge_pre_tool_use(document, command, Agent::Codex, "Codex hooks")
    }

    fn remove_hook(&self, document: &mut Value) -> Result<bool> {
        remove_pre_tool_use(document, Agent::Codex, "Codex hooks")
    }

    fn diagnose_hook(&self, document: &Value, command: &str) -> Result<Vec<String>> {
        diagnose_pre_tool_use(document, command, Agent::Codex, "Codex hooks")
    }
}

fn merge_pre_tool_use(
    document: &mut Value,
    command: &str,
    agent: Agent,
    name: &str,
) -> Result<bool> {
    let root = object_mut(document, name)?;
    let hooks = object_field(root, "hooks", &format!("{name}.hooks"))?;
    let pre_tool_use = array_field(hooks, "PreToolUse", &format!("{name}.hooks.PreToolUse"))?;

    let owned = pre_tool_use
        .iter()
        .flat_map(|entry| {
            entry
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|hook| {
            hook.get("command")
                .and_then(Value::as_str)
                .is_some_and(|value| is_agent_shield_command(value, agent))
        })
        .collect::<Vec<_>>();
    if owned.len() == 1
        && owned[0].get("type").and_then(Value::as_str) == Some("command")
        && owned[0].get("command").and_then(Value::as_str) == Some(command)
    {
        return Ok(false);
    }
    remove_owned_pre_tool_entries(pre_tool_use, agent, name)?;

    let expected = json!({
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": command,
        }],
    });
    pre_tool_use.push(expected);
    Ok(true)
}

fn remove_pre_tool_use(document: &mut Value, agent: Agent, name: &str) -> Result<bool> {
    let root = object_mut(document, name)?;
    let Some(hooks_value) = root.get_mut("hooks") else {
        return Ok(false);
    };
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| anyhow!("{name}.hooks must be a JSON object"))?;
    let Some(pre_tool_value) = hooks.get_mut("PreToolUse") else {
        return Ok(false);
    };
    let pre_tool_use = pre_tool_value
        .as_array_mut()
        .ok_or_else(|| anyhow!("{name}.hooks.PreToolUse must be a JSON array"))?;
    let changed = remove_owned_pre_tool_entries(pre_tool_use, agent, name)?;
    if pre_tool_use.is_empty() {
        hooks.remove("PreToolUse");
    }
    if hooks.is_empty() {
        root.remove("hooks");
    }
    Ok(changed)
}

fn diagnose_pre_tool_use(
    document: &Value,
    command: &str,
    agent: Agent,
    name: &str,
) -> Result<Vec<String>> {
    let root = document
        .as_object()
        .ok_or_else(|| anyhow!("{name} must be a JSON object"))?;
    let Some(pre_tool_use) = root
        .get("hooks")
        .and_then(Value::as_object)
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
    else {
        return Ok(vec!["PreToolUse hook is missing".to_string()]);
    };
    let commands = pre_tool_use
        .iter()
        .flat_map(|entry| {
            entry
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|hook| hook.get("command").and_then(Value::as_str))
        .filter(|value| is_agent_shield_command(value, agent))
        .collect::<Vec<_>>();
    let exact = commands.iter().filter(|value| **value == command).count();
    let mut issues = Vec::new();
    if commands.is_empty() {
        issues.push("Agent Shield PreToolUse hook is missing".to_string());
    } else {
        if exact == 0 {
            issues.push("hook does not point at the current binary".to_string());
        }
        if commands.len() > 1 {
            issues.push("duplicate Agent Shield PreToolUse hooks are installed".to_string());
        }
    }
    Ok(issues)
}

fn remove_owned_pre_tool_entries(
    entries: &mut Vec<Value>,
    agent: Agent,
    name: &str,
) -> Result<bool> {
    let mut changed = false;
    let mut index = 0;
    while index < entries.len() {
        let Some(entry) = entries[index].as_object_mut() else {
            index += 1;
            continue;
        };
        let Some(hooks_value) = entry.get_mut("hooks") else {
            index += 1;
            continue;
        };
        let nested = hooks_value
            .as_array_mut()
            .ok_or_else(|| anyhow!("{name}.hooks.PreToolUse[].hooks must be a JSON array"))?;
        let before = nested.len();
        nested.retain(|hook| {
            !hook
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|value| is_agent_shield_command(value, agent))
        });
        changed |= nested.len() != before;
        if nested.is_empty() {
            entries.remove(index);
        } else {
            index += 1;
        }
    }
    Ok(changed)
}

#[derive(Debug, Default)]
pub struct CursorHookInstaller;

impl HookInstaller for CursorHookInstaller {
    fn agent(&self) -> Agent {
        Agent::Cursor
    }

    fn relative_config_path(&self) -> &'static Path {
        Path::new(".cursor/hooks.json")
    }

    fn merge_hook(&self, document: &mut Value, command: &str) -> Result<bool> {
        let root = object_mut(document, "Cursor hooks")?;
        if !root.contains_key("version") {
            root.insert("version".to_string(), json!(1));
        }
        let hooks = object_field(root, "hooks", "Cursor hooks.hooks")?;
        let mut changed = false;
        for event in [
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeReadFile",
        ] {
            let entries = array_field(hooks, event, &format!("Cursor hooks.hooks.{event}"))?;
            let expected_command = format!("{command} --event {event}");
            let owned = entries
                .iter()
                .filter(|entry| {
                    entry
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|value| is_agent_shield_command(value, Agent::Cursor))
                })
                .collect::<Vec<_>>();
            if owned.len() == 1
                && owned[0].get("command").and_then(Value::as_str) == Some(&expected_command)
                && owned[0].get("failClosed").and_then(Value::as_bool) == Some(true)
            {
                continue;
            }
            entries.retain(|entry| {
                !entry
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|value| is_agent_shield_command(value, Agent::Cursor))
            });
            entries.push(json!({
                "command": expected_command,
                "failClosed": true,
            }));
            changed = true;
        }
        Ok(changed)
    }

    fn remove_hook(&self, document: &mut Value) -> Result<bool> {
        let root = object_mut(document, "Cursor hooks")?;
        let Some(hooks_value) = root.get_mut("hooks") else {
            return Ok(false);
        };
        let hooks = hooks_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("Cursor hooks.hooks must be a JSON object"))?;
        let mut changed = false;
        for event in [
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeReadFile",
        ] {
            let mut remove_event = false;
            if let Some(value) = hooks.get_mut(event) {
                let entries = value
                    .as_array_mut()
                    .ok_or_else(|| anyhow!("Cursor hooks.hooks.{event} must be a JSON array"))?;
                let before = entries.len();
                entries.retain(|entry| {
                    !entry
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|value| is_agent_shield_command(value, Agent::Cursor))
                });
                changed |= entries.len() != before;
                remove_event = entries.is_empty();
            }
            if remove_event {
                hooks.remove(event);
            }
        }
        if hooks.is_empty() {
            root.remove("hooks");
        }
        Ok(changed)
    }

    fn diagnose_hook(&self, document: &Value, command: &str) -> Result<Vec<String>> {
        let root = document
            .as_object()
            .ok_or_else(|| anyhow!("Cursor hooks must be a JSON object"))?;
        let hooks = root.get("hooks").and_then(Value::as_object);
        let mut issues = Vec::new();
        for event in [
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeReadFile",
        ] {
            let expected = format!("{command} --event {event}");
            let entries = hooks
                .and_then(|hooks| hooks.get(event))
                .and_then(Value::as_array);
            let owned = entries
                .into_iter()
                .flatten()
                .filter(|entry| {
                    entry
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|value| is_agent_shield_command(value, Agent::Cursor))
                })
                .collect::<Vec<_>>();
            if owned.is_empty() {
                issues.push(format!("{event} hook is missing"));
                continue;
            }
            if !owned
                .iter()
                .any(|entry| entry.get("command").and_then(Value::as_str) == Some(&expected))
            {
                issues.push(format!("{event} hook does not point at the current binary"));
            }
            if owned
                .iter()
                .any(|entry| entry.get("failClosed").and_then(Value::as_bool) != Some(true))
            {
                issues.push(format!("{event} hook must set failClosed to true"));
            }
            if owned.len() > 1 {
                issues.push(format!("{event} has duplicate Agent Shield hooks"));
            }
        }
        Ok(issues)
    }
}

pub struct Installer {
    home: PathBuf,
    binary: PathBuf,
    formats: Vec<Box<dyn HookInstaller>>,
}

pub struct HookInspection {
    pub agent: Agent,
    pub path: PathBuf,
    pub detected: bool,
    pub issues: Vec<String>,
}

impl Installer {
    pub fn from_env() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set"))?;
        let binary = std::env::current_exe()
            .context("cannot locate the current agent-shield binary")?
            .canonicalize()
            .context("cannot resolve the current agent-shield binary")?;
        Ok(Self::new(home, binary))
    }

    pub fn new(home: PathBuf, binary: PathBuf) -> Self {
        Self {
            home,
            binary,
            formats: vec![
                Box::new(ClaudeHookInstaller),
                Box::new(CursorHookInstaller),
                Box::new(CodexHookInstaller),
            ],
        }
    }

    pub fn install(
        &self,
        claude: bool,
        cursor: bool,
        codex: bool,
        all: bool,
    ) -> Result<Vec<Agent>> {
        let any_explicit = claude || cursor || codex;
        let mut installed = Vec::new();
        for format in &self.formats {
            let selected = match format.agent() {
                Agent::Claude => claude,
                Agent::Cursor => cursor,
                Agent::Codex => codex,
            };
            if !(selected || ((!any_explicit || all) && format.is_detected(&self.home))) {
                continue;
            }
            self.install_one(format.as_ref())?;
            installed.push(format.agent());
        }
        Ok(installed)
    }

    pub fn uninstall(&self) -> Result<Vec<Agent>> {
        self.uninstall_selected(false, false, false)
    }

    pub fn uninstall_selected(
        &self,
        claude: bool,
        cursor: bool,
        codex: bool,
    ) -> Result<Vec<Agent>> {
        let any_explicit = claude || cursor || codex;
        let mut removed = Vec::new();
        for format in &self.formats {
            let selected = match format.agent() {
                Agent::Claude => claude,
                Agent::Cursor => cursor,
                Agent::Codex => codex,
            };
            if any_explicit && !selected {
                continue;
            }
            if self.uninstall_one(format.as_ref())? {
                removed.push(format.agent());
            }
        }
        Ok(removed)
    }

    pub fn inspect_hooks(&self) -> Vec<HookInspection> {
        self.formats
            .iter()
            .map(|format| {
                let path = self.home.join(format.relative_config_path());
                let detected = format.is_detected(&self.home);
                let issues = if !detected {
                    vec!["agent installation was not detected".to_string()]
                } else {
                    match fs::read(&path) {
                        Ok(bytes) => match serde_json::from_slice(&bytes) {
                            Ok(document) => format
                                .diagnose_hook(
                                    &document,
                                    &hook_command(&self.binary, format.agent()),
                                )
                                .unwrap_or_else(|error| vec![error.to_string()]),
                            Err(error) => vec![format!("config is not valid JSON: {error}")],
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            vec!["hook config is missing".to_string()]
                        }
                        Err(error) => vec![format!("cannot read config: {error}")],
                    }
                };
                HookInspection {
                    agent: format.agent(),
                    path,
                    detected,
                    issues,
                }
            })
            .collect()
    }

    fn install_one(&self, format: &dyn HookInstaller) -> Result<()> {
        let path = self.home.join(format.relative_config_path());
        let original = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let mut document = match &original {
            Some(bytes) => serde_json::from_slice(bytes)
                .with_context(|| format!("{} is not valid JSON", path.display()))?,
            None => Value::Object(Map::new()),
        };
        let command = hook_command(&self.binary, format.agent());
        if !format.merge_hook(&mut document, &command)? {
            return Ok(());
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        write_backup(&path, original.as_deref())?;
        atomic_write(&path, &encoded(&document)?)?;
        Ok(())
    }

    fn uninstall_one(&self, format: &dyn HookInstaller) -> Result<bool> {
        let path = self.home.join(format.relative_config_path());
        let current = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let mut document: Value = serde_json::from_slice(&current)
            .with_context(|| format!("{} is not valid JSON", path.display()))?;
        if !format.remove_hook(&mut document)? {
            return Ok(false);
        }

        if let Some(backup) = latest_backup(&path)? {
            let original = fs::read(&backup.path)
                .with_context(|| format!("cannot read backup {}", backup.path.display()))?;
            let mut reconstructed = if backup.was_absent {
                Value::Object(Map::new())
            } else {
                serde_json::from_slice(&original).with_context(|| {
                    format!("backup {} is not valid JSON", backup.path.display())
                })?
            };
            format.merge_hook(
                &mut reconstructed,
                &hook_command(&self.binary, format.agent()),
            )?;
            if encoded(&reconstructed)? == current {
                if backup.was_absent {
                    fs::remove_file(&path)
                        .with_context(|| format!("cannot remove {}", path.display()))?;
                } else {
                    atomic_write(&path, &original)?;
                }
                return Ok(true);
            }
        }

        atomic_write(&path, &encoded(&document)?)?;
        Ok(true)
    }
}

pub fn run_install(
    claude: bool,
    cursor: bool,
    codex: bool,
    all: bool,
    mcp: bool,
    dry_run: bool,
) -> ExitCode {
    if dry_run && !mcp {
        eprintln!("error: --dry-run currently applies to MCP wrapping; pass --mcp");
        return ExitCode::from(2);
    }
    let result = (|| -> Result<()> {
        let mcp_only = mcp && !claude && !cursor && !codex && !all;
        if !mcp_only && !dry_run {
            let installer = Installer::from_env()?;
            let installed = installer.install(claude, cursor, codex, all)?;
            if installed.is_empty() {
                println!("No supported agent installations detected.");
            } else {
                for agent in installed {
                    println!("Installed Agent Shield hook for {}.", agent.display_name());
                }
            }
        }
        if mcp {
            let wrapper = McpWrapper::from_env()?;
            let outcomes = wrapper.wrap_with(dry_run)?;
            print_wrap_report(&outcomes, dry_run);
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

pub fn run_uninstall(
    claude: bool,
    cursor: bool,
    codex: bool,
    mcp: bool,
    dry_run: bool,
) -> ExitCode {
    if dry_run && !mcp {
        eprintln!("error: --dry-run currently applies to MCP wrapping; pass --mcp");
        return ExitCode::from(2);
    }
    let result = (|| -> Result<()> {
        let mcp_only = mcp && !claude && !cursor && !codex;
        if !mcp_only && !dry_run {
            let installer = Installer::from_env()?;
            let removed = if claude || cursor || codex {
                installer.uninstall_selected(claude, cursor, codex)?
            } else {
                installer.uninstall()?
            };
            if removed.is_empty() {
                println!("No Agent Shield hooks were installed.");
            } else {
                for agent in removed {
                    println!("Removed Agent Shield hook for {}.", agent.display_name());
                }
            }
        }
        if mcp {
            let wrapper = McpWrapper::from_env()?;
            let outcomes = wrapper.unwrap_with(dry_run)?;
            print_unwrap_report(&outcomes, dry_run);
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn hook_command(binary: &Path, agent: Agent) -> String {
    let binary = shell_quote(&binary.to_string_lossy());
    match agent {
        Agent::Claude => format!("{binary} hook claude"),
        Agent::Cursor => format!("{binary} hook cursor"),
        Agent::Codex => format!("{binary} hook codex"),
    }
}

fn is_agent_shield_command(command: &str, agent: Agent) -> bool {
    let marker = match agent {
        Agent::Claude => " hook claude",
        Agent::Cursor => " hook cursor",
        Agent::Codex => " hook codex",
    };
    let Some((executable, arguments)) = command.split_once(marker) else {
        return false;
    };
    if match agent {
        Agent::Cursor => !(arguments.is_empty() || arguments.starts_with(" --event ")),
        Agent::Claude | Agent::Codex => !arguments.is_empty(),
    } {
        return false;
    }
    let executable = executable.trim();
    let executable = executable
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .unwrap_or(executable);
    Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "agent-shield" || name == "agent-shield.exe")
}

fn shell_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn object_mut<'a>(value: &'a mut Value, name: &str) -> Result<&'a mut Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("{name} must be a JSON object"))
}

fn object_field<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
    name: &str,
) -> Result<&'a mut Map<String, Value>> {
    object
        .entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("{name} must be a JSON object"))
}

fn array_field<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
    name: &str,
) -> Result<&'a mut Vec<Value>> {
    object
        .entry(key)
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow!("{name} must be a JSON array"))
}

fn backup_suffix() -> Result<String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(format!(
        "{:020}-{:09}",
        elapsed.as_secs(),
        elapsed.subsec_nanos()
    ))
}

pub(crate) fn write_backup(path: &Path, original: Option<&[u8]>) -> Result<PathBuf> {
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("config path has no file name: {}", path.display()))?
        .to_string_lossy();
    let kind = if original.is_some() {
        "backup"
    } else {
        "absent"
    };
    let backup = path.with_file_name(format!(
        "{filename}.agent-shield.{kind}.{}",
        backup_suffix()?
    ));
    fs::write(&backup, original.unwrap_or_default())
        .with_context(|| format!("cannot write backup {}", backup.display()))?;
    Ok(backup)
}

pub(crate) struct Backup {
    pub path: PathBuf,
    pub was_absent: bool,
}

pub(crate) fn latest_backup(path: &Path) -> Result<Option<Backup>> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent: {}", path.display()))?;
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("config path has no file name: {}", path.display()))?
        .to_string_lossy();
    let backup_prefix = format!("{filename}.agent-shield.backup.");
    let absent_prefix = format!("{filename}.agent-shield.absent.");
    let mut candidates = Vec::new();
    for entry in fs::read_dir(parent)
        .with_context(|| format!("cannot inspect backups in {}", parent.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&backup_prefix) {
            candidates.push((name.into_owned(), entry.path(), false));
        } else if name.starts_with(&absent_prefix) {
            candidates.push((name.into_owned(), entry.path(), true));
        }
    }
    Ok(candidates
        .into_iter()
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, path, was_absent)| Backup { path, was_absent }))
}

fn encoded(document: &Value) -> Result<Vec<u8>> {
    let mut output = serde_json::to_vec_pretty(document)?;
    output.push(b'\n');
    Ok(output)
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("config path has no file name: {}", path.display()))?
        .to_string_lossy();
    let temporary = path.with_file_name(format!(
        ".{filename}.agent-shield.tmp-{}-{}",
        std::process::id(),
        backup_suffix()?
    ));
    let result = (|| -> Result<()> {
        let mut file = File::create(&temporary)
            .with_context(|| format!("cannot create {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("cannot write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("cannot sync {}", temporary.display()))?;
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "cannot atomically replace {} with {}",
                path.display(),
                temporary.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_format_is_idempotent_and_preserves_user_hooks() {
        let format = ClaudeHookInstaller;
        let command = "/opt/agent-shield hook claude";
        let mut document = json!({
            "theme": "dark",
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "user-hook"}]
                }]
            }
        });
        assert!(format.merge_hook(&mut document, command).unwrap());
        let once = document.clone();
        assert!(!format.merge_hook(&mut document, command).unwrap());
        assert_eq!(document, once);
        assert_eq!(document["theme"], "dark");
        assert_eq!(document["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn injected_home_and_binary_install_on_linux() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join(".claude")).unwrap();
        let installer = Installer::new(
            temp.path().to_path_buf(),
            PathBuf::from("/opt/agent-shield"),
        );
        assert_eq!(
            installer.install(false, false, false, false).unwrap(),
            vec![Agent::Claude]
        );
        let installed: Value =
            serde_json::from_slice(&fs::read(temp.path().join(".claude/settings.json")).unwrap())
                .unwrap();
        assert_eq!(
            installed["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "/opt/agent-shield hook claude"
        );
    }

    #[test]
    fn install_then_uninstall_restores_all_existing_configs_byte_for_byte() {
        let temp = tempfile::tempdir().unwrap();
        let fixtures = [
            (
                ".claude/settings.json",
                "{\n  \"theme\": \"dark\",\n  \"hooks\": {\"PreToolUse\": []}\n}\n",
            ),
            (
                ".cursor/hooks.json",
                "{\"version\":1,\"hooks\":{\"beforeShellExecution\":[{\"command\":\"user-hook\"}]}}\n",
            ),
            (
                ".codex/hooks.json",
                "{\n \"custom\": true,\n \"hooks\": {\"PreToolUse\": []}\n}\n",
            ),
        ];
        for (relative, original) in fixtures {
            let path = temp.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, original).unwrap();
        }
        let installer = Installer::new(
            temp.path().to_path_buf(),
            PathBuf::from("/opt/agent-shield"),
        );
        installer.install(true, true, true, false).unwrap();
        assert_eq!(installer.uninstall().unwrap().len(), 3);
        for (relative, original) in fixtures {
            assert_eq!(
                fs::read(temp.path().join(relative)).unwrap(),
                original.as_bytes()
            );
        }
    }

    #[test]
    fn uninstall_removes_a_config_that_install_created() {
        let temp = tempfile::tempdir().unwrap();
        let installer = Installer::new(
            temp.path().to_path_buf(),
            PathBuf::from("/opt/agent-shield"),
        );
        installer.install(true, false, false, false).unwrap();
        let path = temp.path().join(".claude/settings.json");
        assert!(path.exists());
        assert_eq!(installer.uninstall().unwrap(), vec![Agent::Claude]);
        assert!(!path.exists());
    }

    #[test]
    fn uninstall_preserves_user_changes_made_after_install() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".cursor/hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\"version\":1}\n").unwrap();
        let installer = Installer::new(
            temp.path().to_path_buf(),
            PathBuf::from("/opt/agent-shield"),
        );
        installer.install(false, true, false, false).unwrap();
        let mut document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        document["userSetting"] = json!("keep-me");
        fs::write(&path, encoded(&document).unwrap()).unwrap();

        installer.uninstall().unwrap();
        let result: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(result["userSetting"], "keep-me");
        assert!(result.get("hooks").is_none());
    }
}
