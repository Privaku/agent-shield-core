use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use shield_audit::{AuditWriter, PlatformPaths};
use shield_core::engine::Engine;
use shield_core::model::{
    Action, ActionKind, AgentContext, AgentKind, ArgvTree, Decision, Outcome, RiskScore, Severity,
};
use shield_core::paths::PathContext;
use shield_core::policy;
use shield_core::shell;

const HOOK_EVENT: &str = "PreToolUse";

#[derive(Debug, Deserialize, Serialize)]
struct HookInput {
    tool_name: String,
    tool_input: Value,
    cwd: PathBuf,
    session_id: String,
    hook_event_name: String,
}

struct MappedInput {
    action: Action,
    forced_decision: Option<Decision>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookResponse<'a> {
    hook_specific_output: HookSpecificOutput<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput<'a> {
    hook_event_name: &'static str,
    permission_decision: &'static str,
    permission_decision_reason: &'a str,
}

pub fn run(agent: AgentKind, autonomous_flag: bool) -> ExitCode {
    let input = match read_input(std::io::stdin().lock()) {
        Ok(input) => input,
        Err(error) => return fail(error),
    };
    let autonomous = autonomous_flag || autonomous_from_env();
    let mapped = match map_input(input, agent, autonomous) {
        Ok(mapped) => mapped,
        Err(error) => return fail(error),
    };

    let decision = match mapped.forced_decision {
        Some(decision) => decision,
        None => match evaluate(&mapped.action) {
            Ok(decision) => decision,
            Err(error) => return fail(error),
        },
    };
    let resolved = shield_ipc::resolve_ask_env(&mapped.action, decision);
    if let Err(error) = audit(
        &mapped.action,
        &resolved.decision,
        resolved.approver.as_deref(),
    ) {
        return fail(error);
    }
    print_response(&resolved.decision);
    ExitCode::SUCCESS
}

pub(crate) fn evaluate(action: &Action) -> Result<Decision, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let paths = policy::Paths::new(home.as_deref(), Some(&action.context.cwd));
    let policy = policy::load(&paths).map_err(|error| format!("cannot load policy: {error}"))?;
    let engine = Engine::new(policy, PathContext::from_env(&action.context.cwd))
        .map_err(|error| format!("cannot compile policy: {error}"))?;
    Ok(engine.evaluate(action, &action.context))
}

pub(crate) fn audit(
    action: &Action,
    decision: &Decision,
    approver: Option<&str>,
) -> Result<(), String> {
    let writer = AuditWriter::new(&PlatformPaths::from_env())
        .map_err(|error| format!("cannot initialize audit log: {error}"))?;
    let approver = match (approver, decision.outcome) {
        (Some(name), _) => Some(name),
        (None, Outcome::Ask) => None,
        (None, _) => Some("policy"),
    };
    writer
        .append(action, decision, approver)
        .map_err(|error| format!("cannot write audit log: {error}"))?;
    Ok(())
}

fn print_response(decision: &Decision) {
    let response = HookResponse {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: HOOK_EVENT,
            permission_decision: decision.outcome.as_str(),
            permission_decision_reason: &decision.reason_agent,
        },
    };
    println!(
        "{}",
        serde_json::to_string(&response).expect("hook response is serializable")
    );
}

fn read_input(reader: impl Read) -> Result<HookInput, String> {
    let input: HookInput =
        serde_json::from_reader(reader).map_err(|error| format!("invalid hook input: {error}"))?;
    if input.tool_name.trim().is_empty() {
        return Err("invalid hook input: tool_name must not be empty".into());
    }
    if input.session_id.trim().is_empty() {
        return Err("invalid hook input: session_id must not be empty".into());
    }
    if input.cwd.as_os_str().is_empty() {
        return Err("invalid hook input: cwd must not be empty".into());
    }
    if input.hook_event_name != HOOK_EVENT {
        return Err(format!(
            "invalid hook input: expected hook_event_name {HOOK_EVENT}, got {}",
            input.hook_event_name
        ));
    }
    if !input.tool_input.is_object() {
        return Err("invalid hook input: tool_input must be an object".into());
    }
    Ok(input)
}

fn map_input(input: HookInput, agent: AgentKind, autonomous: bool) -> Result<MappedInput, String> {
    let cwd = absolute_cwd(input.cwd);
    let context = AgentContext {
        agent,
        session_id: input.session_id,
        cwd: cwd.clone(),
        autonomous,
    };
    let object = input
        .tool_input
        .as_object()
        .expect("read_input validates tool_input");

    let (kind, forced_decision) = match input.tool_name.as_str() {
        "Bash" => {
            let raw = command_string(object)?;
            let (argv_tree, obfuscation) = match shell::parse(&raw) {
                Ok(tree) => (tree.to_argv_tree(), tree.obfuscation.to_vec()),
                Err(_) => (ArgvTree::Unparsed { raw: raw.clone() }, Vec::new()),
            };
            (
                ActionKind::Shell {
                    argv_tree,
                    raw,
                    cwd,
                    obfuscation,
                },
                None,
            )
        }
        "Read" => (
            ActionKind::FileRead {
                path: required_path(object, &["file_path"])?,
            },
            None,
        ),
        "Grep" => (
            ActionKind::FileRead {
                path: required_path(object, &["path"])?,
            },
            None,
        ),
        "Glob" => {
            let pattern = required_string(object, &["pattern"])?;
            (
                ActionKind::FileRead {
                    path: glob_directory(pattern, &cwd),
                },
                None,
            )
        }
        "Write" | "Edit" | "MultiEdit" => (
            ActionKind::FileWrite {
                path: required_path(object, &["file_path", "path"])?,
            },
            None,
        ),
        "apply_patch" => (
            ActionKind::FileWrite {
                path: patch_path(object)?,
            },
            None,
        ),
        "WebFetch" => (
            ActionKind::Network {
                url: Some(required_string(object, &["url"])?.to_string()),
                host: None,
                method: Some("GET".into()),
                body_source: None,
            },
            None,
        ),
        name if name.starts_with("mcp__") => {
            let (server, tool) = parse_mcp_name(name)?;
            (
                ActionKind::McpToolCall {
                    server,
                    tool,
                    args_json: input.tool_input,
                },
                None,
            )
        }
        name => (
            ActionKind::McpToolCall {
                server: "unknown".into(),
                tool: name.to_string(),
                args_json: input.tool_input,
            },
            Some(unknown_tool_decision(name)),
        ),
    };

    Ok(MappedInput {
        action: Action::new(context, kind),
        forced_decision,
    })
}

fn command_string(object: &serde_json::Map<String, Value>) -> Result<String, String> {
    for key in ["command", "cmd"] {
        if let Some(value) = object.get(key) {
            return match value {
                Value::String(command) if !command.trim().is_empty() => Ok(command.clone()),
                Value::Array(arguments) if !arguments.is_empty() => arguments
                    .iter()
                    .map(|argument| {
                        argument.as_str().map(shell_quote).ok_or_else(|| {
                            format!("invalid hook input: tool_input.{key} must contain strings")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(|arguments| arguments.join(" ")),
                _ => Err(format!(
                    "invalid hook input: tool_input.{key} must be a non-empty string or string array"
                )),
            };
        }
    }
    Err("invalid hook input: Bash requires tool_input.command or tool_input.cmd".into())
}

fn shell_quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./~-".contains(&byte))
    {
        argument.to_string()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<&'a str, String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "invalid hook input: tool_input requires non-empty {}",
                keys.join(" or ")
            )
        })
}

fn required_path(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<PathBuf, String> {
    required_string(object, keys).map(PathBuf::from)
}

fn patch_path(object: &serde_json::Map<String, Value>) -> Result<PathBuf, String> {
    if let Ok(path) = required_path(object, &["file_path", "path"]) {
        return Ok(path);
    }
    let patch = required_string(object, &["patch", "input"])?;
    patch
        .lines()
        .find_map(|line| {
            ["*** Add File: ", "*** Update File: ", "*** Delete File: "]
                .iter()
                .find_map(|prefix| line.strip_prefix(prefix))
        })
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "invalid hook input: apply_patch contains no file path".into())
}

fn glob_directory(pattern: &str, cwd: &Path) -> PathBuf {
    let wildcard = pattern
        .char_indices()
        .find_map(|(index, character)| "*?[{".contains(character).then_some(index))
        .unwrap_or(pattern.len());
    let prefix = &pattern[..wildcard];
    let candidate = if prefix.ends_with('/') {
        prefix.trim_end_matches('/')
    } else {
        Path::new(prefix)
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("")
    };
    if candidate.is_empty() || candidate == "." {
        cwd.to_path_buf()
    } else {
        PathBuf::from(candidate)
    }
}

fn parse_mcp_name(name: &str) -> Result<(String, String), String> {
    let remainder = name
        .strip_prefix("mcp__")
        .expect("caller checked MCP prefix");
    let (server, tool) = remainder.split_once("__").ok_or_else(|| {
        "invalid hook input: MCP tool name must be mcp__<server>__<tool>".to_string()
    })?;
    if server.is_empty() || tool.is_empty() {
        return Err("invalid hook input: MCP server and tool must not be empty".into());
    }
    Ok((server.to_string(), tool.to_string()))
}

fn absolute_cwd(cwd: PathBuf) -> PathBuf {
    if cwd.is_absolute() {
        cwd
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(cwd)
    }
}

pub(crate) fn autonomous_from_env() -> bool {
    std::env::var("AGENT_SHIELD_AUTONOMOUS")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn unknown_tool_decision(name: &str) -> Decision {
    Decision {
        outcome: Outcome::Ask,
        rule_id: Some("hook.unknown_tool".into()),
        matched_rule_ids: vec!["hook.unknown_tool".into()],
        severity: Severity::High,
        reason_user: format!("Unknown hook tool `{name}` requires approval"),
        reason_agent: format!(
            "Privaku Agent Shield does not recognize tool `{name}`; ask the user for permission and do not retry."
        ),
        risk_score: RiskScore::MAX,
    }
}

fn fail(message: String) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn input(tool_name: &str, tool_input: Value) -> HookInput {
        HookInput {
            tool_name: tool_name.into(),
            tool_input,
            cwd: PathBuf::from("/workspace"),
            session_id: "session-1".into(),
            hook_event_name: HOOK_EVENT.into(),
        }
    }

    fn mapped(tool_name: &str, tool_input: Value) -> MappedInput {
        map_input(input(tool_name, tool_input), AgentKind::Claude, false).unwrap()
    }

    #[test]
    fn maps_shell_string_and_codex_argv_variant() {
        let bash = mapped("Bash", json!({"command": "git status"}));
        assert!(matches!(
            bash.action.kind,
            ActionKind::Shell { ref raw, .. } if raw == "git status"
        ));

        let codex = mapped("Bash", json!({"cmd": ["git", "status", "--short"]}));
        assert!(matches!(
            codex.action.kind,
            ActionKind::Shell { ref raw, .. } if raw == "git status --short"
        ));
    }

    #[test]
    fn maps_file_tools_and_derives_glob_directory() {
        assert!(matches!(
            mapped("Read", json!({"file_path": "src/main.rs"})).action.kind,
            ActionKind::FileRead { ref path } if path == Path::new("src/main.rs")
        ));
        assert!(matches!(
            mapped("Grep", json!({"path": "src", "pattern": "unsafe"})).action.kind,
            ActionKind::FileRead { ref path } if path == Path::new("src")
        ));
        assert!(matches!(
            mapped("Glob", json!({"pattern": "src/**/*.rs"})).action.kind,
            ActionKind::FileRead { ref path } if path == Path::new("src")
        ));
        assert!(matches!(
            mapped("Write", json!({"file_path": "src/main.rs", "content": ""})).action.kind,
            ActionKind::FileWrite { ref path } if path == Path::new("src/main.rs")
        ));
    }

    #[test]
    fn derives_apply_patch_path() {
        let patch = "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\n";
        assert!(matches!(
            mapped("apply_patch", json!({"patch": patch})).action.kind,
            ActionKind::FileWrite { ref path } if path == Path::new("src/lib.rs")
        ));
    }

    #[test]
    fn maps_web_fetch_and_mcp() {
        assert!(matches!(
            mapped("WebFetch", json!({"url": "https://example.test"})).action.kind,
            ActionKind::Network { ref url, .. }
                if url.as_deref() == Some("https://example.test")
        ));
        assert!(matches!(
            mapped(
                "mcp__filesystem__read_file",
                json!({"path": "~/.aws/credentials"})
            )
            .action
            .kind,
            ActionKind::McpToolCall { ref server, ref tool, .. }
                if server == "filesystem" && tool == "read_file"
        ));
    }

    #[test]
    fn unknown_tool_is_forced_to_ask() {
        let mapped = mapped("Teleport", json!({"target": "moon"}));
        assert_eq!(mapped.forced_decision.unwrap().outcome, Outcome::Ask);
    }

    #[test]
    fn serializes_native_pre_tool_use_response() {
        let decision = unknown_tool_decision("Teleport");
        let response = HookResponse {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: HOOK_EVENT,
                permission_decision: decision.outcome.as_str(),
                permission_decision_reason: &decision.reason_agent,
            },
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["hookSpecificOutput"]["hookEventName"], HOOK_EVENT);
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("do not retry"));
    }

    #[test]
    fn rejects_wrong_event_and_missing_tool_fields() {
        let mut wrong = input("Read", json!({"file_path": "src/main.rs"}));
        wrong.hook_event_name = "PostToolUse".into();
        let encoded = serde_json::to_vec(&wrong).unwrap();
        assert!(read_input(encoded.as_slice()).is_err());
        assert!(map_input(input("Read", json!({})), AgentKind::Claude, false).is_err());
    }
}
