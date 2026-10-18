use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::ValueEnum;
use serde::Serialize;
use serde_json::{Map, Value};
use shield_core::model::{
    Action, ActionKind, AgentContext, AgentKind, ArgvTree, Decision, Outcome, RiskScore, Severity,
};
use shield_core::{secrets, shell};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum CursorEvent {
    #[value(name = "beforeShellExecution")]
    ShellExecution,
    #[value(name = "beforeMCPExecution")]
    McpExecution,
    #[value(name = "beforeReadFile")]
    ReadFile,
}

impl CursorEvent {
    fn from_wire(value: &str) -> Result<Self, String> {
        match value {
            "beforeShellExecution" => Ok(Self::ShellExecution),
            "beforeMCPExecution" => Ok(Self::McpExecution),
            "beforeReadFile" => Ok(Self::ReadFile),
            _ => Err(format!("unsupported Cursor hook event `{value}`")),
        }
    }
}

#[derive(Debug)]
struct CursorPayload {
    fields: Map<String, Value>,
    hook_event: Option<CursorEvent>,
}

#[derive(Debug, PartialEq, Eq)]
struct EventSelection {
    event: CursorEvent,
    conflict: bool,
}

struct MappedPayload {
    action: Action,
    forced_decision: Option<Decision>,
}

#[derive(Serialize)]
struct CursorResponse<'a> {
    permission: &'static str,
    user_message: &'a str,
    agent_message: &'a str,
}

pub(crate) fn run(event_override: Option<CursorEvent>, autonomous_flag: bool) -> ExitCode {
    let payload = match read_payload(std::io::stdin().lock()) {
        Ok(payload) => payload,
        Err(error) => return fail(error),
    };
    let selection = match select_event(&payload, event_override) {
        Ok(selection) => selection,
        Err(error) => return fail(error),
    };
    let autonomous = autonomous_flag || crate::hook::autonomous_from_env();
    let mut mapped = match map_payload(payload, selection.event, autonomous) {
        Ok(mapped) => mapped,
        Err(error) => return fail(error),
    };
    if selection.conflict {
        mapped.forced_decision = Some(forced_decision(
            "hook.cursor_event_conflict",
            "Cursor hook event metadata conflicts with its payload shape",
            "Privaku Agent Shield detected conflicting Cursor hook event metadata. Do not retry; ask the user to check the hook configuration.",
            autonomous,
        ));
    }
    let decision = match mapped.forced_decision {
        Some(decision) => decision,
        None => match crate::hook::evaluate(&mapped.action) {
            Ok(decision) => decision,
            Err(error) => return fail(error),
        },
    };
    let resolved = shield_ipc::resolve_ask_env(&mapped.action, decision);
    if let Err(error) = crate::hook::audit(
        &mapped.action,
        &resolved.decision,
        resolved.approver.as_deref(),
    ) {
        return fail(error);
    }
    print_response(&resolved.decision);
    ExitCode::SUCCESS
}

fn read_payload(reader: impl Read) -> Result<CursorPayload, String> {
    let value: Value = serde_json::from_reader(reader)
        .map_err(|error| format!("invalid Cursor hook input: {error}"))?;
    let fields = value
        .as_object()
        .cloned()
        .ok_or_else(|| "invalid Cursor hook input: expected a JSON object".to_string())?;
    let hook_event = match fields.get("hook_event_name") {
        None => None,
        Some(Value::String(value)) => Some(
            CursorEvent::from_wire(value)
                .map_err(|error| format!("invalid Cursor hook input: {error}"))?,
        ),
        Some(_) => {
            return Err("invalid Cursor hook input: hook_event_name must be a string".to_string())
        }
    };
    Ok(CursorPayload { fields, hook_event })
}

fn select_event(
    payload: &CursorPayload,
    event_override: Option<CursorEvent>,
) -> Result<EventSelection, String> {
    let shapes = detect_shapes(&payload.fields);
    let declared = event_override.or(payload.hook_event);
    let event = match (declared, shapes.as_slice()) {
        (Some(event), _) => event,
        (None, [event]) => *event,
        (None, []) => {
            return Err(
                "invalid Cursor hook input: cannot detect event from payload shape".to_string(),
            )
        }
        (None, _) => {
            return Err(
                "invalid Cursor hook input: payload matches multiple event shapes".to_string(),
            )
        }
    };
    let conflict = event_override
        .zip(payload.hook_event)
        .is_some_and(|(explicit, declared)| explicit != declared)
        || !matches!(shapes.as_slice(), [detected] if *detected == event);
    Ok(EventSelection { event, conflict })
}

fn detect_shapes(fields: &Map<String, Value>) -> Vec<CursorEvent> {
    [
        (fields.contains_key("command"), CursorEvent::ShellExecution),
        (
            ["tool_name", "tool_input", "mcp_server_name"]
                .iter()
                .any(|field| fields.contains_key(*field)),
            CursorEvent::McpExecution,
        ),
        (fields.contains_key("file_path"), CursorEvent::ReadFile),
    ]
    .into_iter()
    .filter_map(|(matches, event)| matches.then_some(event))
    .collect()
}

fn map_payload(
    payload: CursorPayload,
    event: CursorEvent,
    autonomous: bool,
) -> Result<MappedPayload, String> {
    let session_id = optional_string(&payload.fields, "conversation_id")?
        .or(optional_string(&payload.fields, "generation_id")?)
        .unwrap_or("cursor-hook")
        .to_string();
    let cwd = payload_cwd(&payload.fields, event)?;
    let context = AgentContext {
        agent: AgentKind::Cursor,
        session_id,
        cwd: cwd.clone(),
        autonomous,
    };

    let (kind, forced_decision) = match event {
        CursorEvent::ShellExecution => {
            let raw = required_string(&payload.fields, "command")?.to_string();
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
        CursorEvent::McpExecution => {
            let tool = required_string(&payload.fields, "tool_name")?.to_string();
            let encoded = required_string(&payload.fields, "tool_input")?;
            let args_json = serde_json::from_str(encoded).map_err(|error| {
                format!("invalid Cursor hook input: tool_input is not valid JSON: {error}")
            })?;
            let (server, forced) = match payload.fields.get("mcp_server_name") {
                Some(Value::String(server)) if !server.trim().is_empty() => {
                    (server.to_string(), None)
                }
                _ => (
                    "unknown".to_string(),
                    Some(forced_decision(
                        "hook.cursor_missing_mcp_server",
                        "Cursor MCP call has no valid server name",
                        "Privaku Agent Shield cannot identify the Cursor MCP server. Do not retry; ask the user to review the MCP configuration.",
                        autonomous,
                    )),
                ),
            };
            (
                ActionKind::McpToolCall {
                    server,
                    tool,
                    args_json,
                },
                forced,
            )
        }
        CursorEvent::ReadFile => {
            let path = PathBuf::from(required_string(&payload.fields, "file_path")?);
            let content = optional_string(&payload.fields, "content")?;
            let forced = content
                .filter(|content| !secrets::detect(content).is_empty())
                .map(|_| {
                    forced_decision(
                        "hook.cursor_secret_content",
                        "The requested file contains secret-looking content",
                        "Privaku Agent Shield detected secret-looking file content. Do not retry or expose the content; ask the user how to proceed.",
                        autonomous,
                    )
                });
            (ActionKind::FileRead { path }, forced)
        }
    };
    Ok(MappedPayload {
        action: Action::new(context, kind),
        forced_decision,
    })
}

fn required_string<'a>(fields: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    optional_string(fields, field)?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("invalid Cursor hook input: {field} must be a non-empty string"))
}

fn optional_string<'a>(
    fields: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    match fields.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(format!(
            "invalid Cursor hook input: {field} must be a string"
        )),
    }
}

fn payload_cwd(fields: &Map<String, Value>, event: CursorEvent) -> Result<PathBuf, String> {
    if let Some(cwd) = optional_string(fields, "cwd")?.filter(|cwd| !cwd.trim().is_empty()) {
        return Ok(absolute_path(Path::new(cwd)));
    }
    if event == CursorEvent::ShellExecution {
        return Err("invalid Cursor hook input: cwd must be a non-empty string".into());
    }
    if let Some(roots) = fields.get("workspace_roots") {
        let roots = roots.as_array().ok_or_else(|| {
            "invalid Cursor hook input: workspace_roots must be an array".to_string()
        })?;
        if let Some(root) = roots.first().and_then(workspace_root) {
            return Ok(absolute_path(Path::new(root)));
        }
    }
    std::env::current_dir()
        .map_err(|error| format!("cannot determine Cursor hook working directory: {error}"))
}

fn workspace_root(value: &Value) -> Option<&str> {
    value.as_str().or_else(|| {
        value
            .as_object()
            .and_then(|root| root.get("path").or_else(|| root.get("uri")))
            .and_then(Value::as_str)
    })
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn forced_decision(
    rule_id: &str,
    reason_user: &str,
    reason_agent: &str,
    autonomous: bool,
) -> Decision {
    let outcome = if autonomous {
        Outcome::Deny
    } else {
        Outcome::Ask
    };
    let reason_agent = if autonomous {
        format!("{reason_agent} No human is available in autonomous mode, so the action is denied.")
    } else {
        reason_agent.to_string()
    };
    Decision {
        outcome,
        rule_id: Some(rule_id.into()),
        matched_rule_ids: vec![rule_id.into()],
        severity: Severity::High,
        reason_user: reason_user.into(),
        reason_agent,
        risk_score: RiskScore::MAX,
    }
}

fn print_response(decision: &Decision) {
    let response = CursorResponse {
        permission: decision.outcome.as_str(),
        user_message: &decision.reason_user,
        agent_message: &decision.reason_agent,
    };
    println!(
        "{}",
        serde_json::to_string(&response).expect("Cursor response is serializable")
    );
}

fn fail(message: String) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn payload(value: Value) -> CursorPayload {
        read_payload(serde_json::to_vec(&value).unwrap().as_slice()).unwrap()
    }

    #[test]
    fn detects_all_native_payload_shapes() {
        let cases = [
            (
                json!({"command": "npm test", "cwd": "/workspace"}),
                CursorEvent::ShellExecution,
            ),
            (
                json!({"tool_name": "echo", "tool_input": "{}"}),
                CursorEvent::McpExecution,
            ),
            (json!({"file_path": "src/lib.rs"}), CursorEvent::ReadFile),
        ];
        for (value, expected) in cases {
            assert_eq!(
                select_event(&payload(value), None).unwrap(),
                EventSelection {
                    event: expected,
                    conflict: false
                }
            );
        }
    }

    #[test]
    fn declared_event_is_used_and_explicit_event_wins() {
        let declared = payload(json!({
            "hook_event_name": "beforeReadFile",
            "file_path": "src/lib.rs"
        }));
        assert_eq!(
            select_event(&declared, None).unwrap().event,
            CursorEvent::ReadFile
        );
        assert_eq!(
            select_event(&declared, Some(CursorEvent::ShellExecution)).unwrap(),
            EventSelection {
                event: CursorEvent::ShellExecution,
                conflict: true
            }
        );
    }

    #[test]
    fn shape_disagreement_is_marked_as_conflict() {
        let payload = payload(json!({
            "hook_event_name": "beforeReadFile",
            "command": "npm test",
            "cwd": "/workspace"
        }));
        assert_eq!(
            select_event(&payload, None).unwrap(),
            EventSelection {
                event: CursorEvent::ReadFile,
                conflict: true
            }
        );
    }

    #[test]
    fn rejects_invalid_json_unknown_events_and_ambiguous_shapes() {
        assert!(read_payload(b"{".as_slice()).is_err());
        assert!(read_payload(b"[]".as_slice()).is_err());
        assert!(read_payload(
            serde_json::to_vec(&json!({"hook_event_name": "afterReadFile"}))
                .unwrap()
                .as_slice()
        )
        .is_err());
        assert!(select_event(
            &payload(json!({"command": "pwd", "file_path": "src/lib.rs"})),
            None
        )
        .is_err());
        assert!(select_event(&payload(json!({"conversation_id": "c1"})), None).is_err());
    }

    #[test]
    fn maps_shell_mcp_and_read_payloads() {
        let shell = map_payload(
            payload(json!({
                "command": "npm test",
                "cwd": "/workspace",
                "conversation_id": "conversation-1"
            })),
            CursorEvent::ShellExecution,
            false,
        )
        .unwrap();
        assert_eq!(shell.action.context.agent, AgentKind::Cursor);
        assert_eq!(shell.action.context.session_id, "conversation-1");
        assert!(matches!(
            shell.action.kind,
            ActionKind::Shell { ref raw, .. } if raw == "npm test"
        ));

        let mcp = map_payload(
            payload(json!({
                "tool_name": "echo",
                "tool_input": "{\"message\":\"hello\"}",
                "mcp_server_name": "utilities",
                "generation_id": "generation-1",
                "workspace_roots": ["/workspace"]
            })),
            CursorEvent::McpExecution,
            false,
        )
        .unwrap();
        assert!(matches!(
            mcp.action.kind,
            ActionKind::McpToolCall { ref server, ref tool, ref args_json }
                if server == "utilities" && tool == "echo" && args_json["message"] == "hello"
        ));

        let read = map_payload(
            payload(json!({
                "file_path": "src/lib.rs",
                "workspace_roots": [{"path": "/workspace"}]
            })),
            CursorEvent::ReadFile,
            false,
        )
        .unwrap();
        assert!(matches!(
            read.action.kind,
            ActionKind::FileRead { ref path } if path == Path::new("src/lib.rs")
        ));
    }

    #[test]
    fn missing_mcp_server_and_secret_content_fail_closed_without_logging_content() {
        let missing_server = map_payload(
            payload(json!({
                "tool_name": "echo",
                "tool_input": "{}",
                "mcp_server_name": 42
            })),
            CursorEvent::McpExecution,
            true,
        )
        .unwrap();
        assert_eq!(
            missing_server.forced_decision.unwrap().outcome,
            Outcome::Deny
        );

        let secret = "AKIAIOSFODNN7EXAMPLE";
        let read = map_payload(
            payload(json!({
                "file_path": ".env",
                "content": secret,
                "workspace_roots": ["/workspace"]
            })),
            CursorEvent::ReadFile,
            false,
        )
        .unwrap();
        assert_eq!(read.forced_decision.unwrap().outcome, Outcome::Ask);
        assert!(!serde_json::to_string(&read.action)
            .unwrap()
            .contains(secret));
    }

    #[test]
    fn rejects_invalid_tool_input_and_missing_required_fields() {
        assert!(map_payload(
            payload(json!({
                "tool_name": "echo",
                "tool_input": "{",
                "mcp_server_name": "utilities"
            })),
            CursorEvent::McpExecution,
            false
        )
        .is_err());
        assert!(map_payload(
            payload(json!({"command": "npm test"})),
            CursorEvent::ShellExecution,
            false
        )
        .is_err());
        assert!(map_payload(
            payload(json!({"content": "hello"})),
            CursorEvent::ReadFile,
            false
        )
        .is_err());
    }

    #[test]
    fn serializes_cursor_response_with_both_reason_fields() {
        let decision = forced_decision(
            "hook.test",
            "User reason",
            "Agent reason. Do not retry.",
            false,
        );
        let response = CursorResponse {
            permission: decision.outcome.as_str(),
            user_message: &decision.reason_user,
            agent_message: &decision.reason_agent,
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({
                "permission": "ask",
                "user_message": "User reason",
                "agent_message": "Agent reason. Do not retry."
            })
        );
    }
}
