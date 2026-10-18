//! Newline-delimited JSON-RPC proxy for stdio MCP servers.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use serde_json::{json, Value};
use shield_audit::{AuditWriter, PlatformPaths};
use shield_core::engine::Engine;
use shield_core::model::{
    Action, ActionKind, AgentContext, AgentKind, Decision, Outcome, RiskScore, Severity,
};
use shield_core::paths::PathContext;
use shield_core::{policy, secrets};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// Configuration supplied by `agent-shield mcp-proxy`.
#[derive(Debug, Clone)]
pub struct Config {
    pub name: String,
    pub command: Vec<String>,
    pub redact_results: bool,
}

/// A proxy startup, relay, or child-process failure.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("the MCP server command is missing")]
    MissingCommand,
    #[error("cannot determine the proxy working directory: {0}")]
    WorkingDirectory(#[source] io::Error),
    #[error("cannot load Agent Shield policy: {0}")]
    Policy(String),
    #[error("cannot compile Agent Shield policy: {0}")]
    Engine(String),
    #[error("cannot initialize the audit log: {0}")]
    Audit(String),
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("cannot spawn MCP server `{program}`: {source}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("MCP server stdin was unavailable")]
    MissingStdin,
    #[error("MCP server stdout was unavailable")]
    MissingStdout,
    #[error("MCP relay failed: {0}")]
    Relay(#[source] io::Error),
    #[error("cannot wait for MCP server: {0}")]
    Wait(#[source] io::Error),
    #[error("MCP relay task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
}

/// Run the proxy until the child server exits and return its process code.
pub fn run(config: Config) -> Result<i32, ProxyError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ProxyError::Runtime)?;
    runtime.block_on(run_async(config))
}

async fn run_async(config: Config) -> Result<i32, ProxyError> {
    restore_default_signals();
    let guard = Guard::new(&config.name)?;
    let pending = Arc::new(Mutex::new(HashMap::new()));
    let scanner = ResultScanner {
        enabled: config.redact_results,
        pending: Arc::clone(&pending),
        audit: guard.audit.clone(),
        context: guard.context.clone(),
        server: guard.server.clone(),
    };
    let (program, args) = config
        .command
        .split_first()
        .ok_or(ProxyError::MissingCommand)?;
    let mut child = spawn_server(program, args)?;
    let child_id = child.id().ok_or_else(|| ProxyError::Spawn {
        program: program.clone(),
        source: io::Error::other("spawned child has no process id"),
    })?;
    let child_stdin = child.stdin.take().ok_or(ProxyError::MissingStdin)?;
    let child_stdout = child.stdout.take().ok_or(ProxyError::MissingStdout)?;
    let client_output = Arc::new(Mutex::new(BufWriter::new(tokio::io::stdout())));
    let error_output = Arc::clone(&client_output);
    let server_output = Arc::clone(&client_output);

    let mut client_task = tokio::spawn(async move {
        relay_client_to_server(
            BufReader::new(tokio::io::stdin()),
            BufWriter::new(child_stdin),
            error_output,
            guard,
            pending,
            config.redact_results,
        )
        .await?;
        Ok::<(), io::Error>(())
    });
    let mut server_task = tokio::spawn(async move {
        relay_server_to_client(BufReader::new(child_stdout), server_output, scanner).await?;
        Ok::<(), io::Error>(())
    });

    let mut wait = Box::pin(wait_with_signals(&mut child, child_id));
    let (status, client_done, server_done) = tokio::select! {
        status = &mut wait => (status.map_err(ProxyError::Wait)?, false, false),
        result = &mut client_task => {
            task_result(result)?;
            (wait.await.map_err(ProxyError::Wait)?, true, false)
        }
        result = &mut server_task => {
            task_result(result)?;
            (wait.await.map_err(ProxyError::Wait)?, false, true)
        }
    };

    if !server_done {
        server_task
            .await
            .map_err(ProxyError::Task)?
            .map_err(ProxyError::Relay)?;
    }
    if !client_done {
        client_task.abort();
        let _ = client_task.await;
    }

    Ok(exit_code(status))
}

fn spawn_server(program: &str, args: &[String]) -> Result<Child, ProxyError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        command.process_group(0);
        // SAFETY: runs in the child after fork and before exec. Restoring
        // SIG_DFL is required because a parent that ignored SIGINT/SIGTERM
        // (a shell background job) would otherwise leave the server and its
        // descendants unable to die on forwarded signals.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                Ok(())
            });
        }
    }
    command.spawn().map_err(|source| ProxyError::Spawn {
        program: program.to_string(),
        source,
    })
}

#[cfg(unix)]
fn restore_default_signals() {
    // SAFETY: the proxy must be able to observe SIGINT/SIGTERM even when it
    // was started with those signals ignored. Tokio then replaces these
    // default handlers with its own listener.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_signals() {}

struct Guard {
    engine: Engine,
    audit: AuditWriter,
    context: AgentContext,
    server: String,
}

impl Guard {
    fn new(server: &str) -> Result<Self, ProxyError> {
        let cwd = std::env::current_dir().map_err(ProxyError::WorkingDirectory)?;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let policy_paths = policy::Paths::new(home.as_deref(), Some(&cwd));
        let policy =
            policy::load(&policy_paths).map_err(|error| ProxyError::Policy(error.to_string()))?;
        let engine = Engine::new(policy, PathContext::from_env(&cwd))
            .map_err(|error| ProxyError::Engine(error.to_string()))?;
        let audit = AuditWriter::new(&PlatformPaths::from_env())
            .map_err(|error| ProxyError::Audit(error.to_string()))?;
        let context = AgentContext {
            agent: AgentKind::Mcp,
            session_id: format!("{server}-{}", std::process::id()),
            cwd,
            autonomous: false,
        };
        Ok(Self {
            engine,
            audit,
            context,
            server: server.to_string(),
        })
    }
}

struct ResultScanner {
    enabled: bool,
    pending: Arc<Mutex<HashMap<String, String>>>,
    audit: AuditWriter,
    context: AgentContext,
    server: String,
}

async fn relay_client_to_server<R, W, O>(
    mut input: R,
    mut server_output: W,
    client_output: Arc<Mutex<O>>,
    guard: Guard,
    pending: Arc<Mutex<HashMap<String, String>>>,
    scan_results: bool,
) -> io::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut line = Vec::new();
    loop {
        line.clear();
        if input.read_until(b'\n', &mut line).await? == 0 {
            shutdown_or_closed(&mut server_output).await?;
            return Ok(());
        }
        let request: Value = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(_) => {
                reply_error(
                    &client_output,
                    Value::Null,
                    -32700,
                    "Parse error".to_string(),
                )
                .await?;
                continue;
            }
        };
        let Some(tool_call) = parse_tool_call(&request) else {
            write_all_or_closed(&mut server_output, &line).await?;
            continue;
        };
        let (id, tool, args) = match tool_call {
            Ok(call) => call,
            Err(message) => {
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                reply_error(&client_output, id, -32602, message.to_string()).await?;
                continue;
            }
        };
        let action = Action::new(
            guard.context.clone(),
            ActionKind::McpToolCall {
                server: guard.server.clone(),
                tool,
                args_json: args,
            },
        );
        let decision = guard.engine.evaluate(&action, &guard.context);
        let resolved = resolve_ask_blocking(action.clone(), decision).await;
        if let Err(error) =
            guard
                .audit
                .append(&action, &resolved.decision, resolved.approver.as_deref())
        {
            reply_error(
                &client_output,
                id,
                -32001,
                format!("Blocked by Privaku Agent Shield: cannot write audit log: {error}"),
            )
            .await?;
            continue;
        }
        if resolved.decision.outcome == Outcome::Allow {
            if scan_results {
                if let Some(key) = request_id_key(&id) {
                    pending.lock().await.insert(key, tool_name(&action));
                }
            }
            write_all_or_closed(&mut server_output, &line).await?;
        } else {
            reply_error(
                &client_output,
                id,
                -32001,
                blocked_message(&resolved.decision),
            )
            .await?;
        }
    }
}

fn tool_name(action: &Action) -> String {
    match &action.kind {
        ActionKind::McpToolCall { tool, .. } => tool.clone(),
        _ => unreachable!("the proxy only tracks MCP tool calls"),
    }
}

fn request_id_key(id: &Value) -> Option<String> {
    if id.is_null() {
        None
    } else {
        serde_json::to_string(id).ok()
    }
}

fn parse_tool_call(request: &Value) -> Option<Result<(Value, String, Value), &'static str>> {
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return Some(Err("tools/call params must be an object"));
    };
    let Some(tool) = params.get("name").and_then(Value::as_str) else {
        return Some(Err("tools/call params.name must be a string"));
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some(Ok((id, tool.to_string(), args)))
}

async fn resolve_ask_blocking(action: Action, decision: Decision) -> shield_ipc::ResolvedAsk {
    tokio::task::spawn_blocking(move || shield_ipc::resolve_ask_env(&action, decision))
        .await
        .unwrap_or_else(|_| shield_ipc::ResolvedAsk {
            decision: Decision {
                outcome: Outcome::Deny,
                rule_id: Some("mcp.approval_failed".into()),
                matched_rule_ids: vec!["mcp.approval_failed".into()],
                severity: Severity::High,
                reason_user: "Approval resolution failed".into(),
                reason_agent: shield_ipc::DAEMON_DOWN_AGENT_MESSAGE.into(),
                risk_score: RiskScore::MAX,
            },
            approver: Some("autonomous".into()),
            source: shield_ipc::AskSource::DaemonDown,
            dialog_invoked: false,
        })
}

fn blocked_message(decision: &Decision) -> String {
    format!("Blocked by Privaku Agent Shield: {}", decision.reason_agent)
}

async fn relay_server_to_client<R, O>(
    mut input: R,
    output: Arc<Mutex<O>>,
    scanner: ResultScanner,
) -> io::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut line = Vec::new();
    loop {
        line.clear();
        if input.read_until(b'\n', &mut line).await? == 0 {
            return Ok(());
        }
        if !scanner.enabled {
            write_client_bytes(&output, &line).await?;
            continue;
        }
        let mut response: Value = match serde_json::from_slice(&line) {
            Ok(response) => response,
            Err(_) => {
                write_client_bytes(&output, &line).await?;
                continue;
            }
        };
        let Some(id) = response.get("id").cloned() else {
            write_client_bytes(&output, &line).await?;
            continue;
        };
        let Some(key) = request_id_key(&id) else {
            write_client_bytes(&output, &line).await?;
            continue;
        };
        let Some(tool) = scanner.pending.lock().await.remove(&key) else {
            write_client_bytes(&output, &line).await?;
            continue;
        };
        let Some(result) = response.get_mut("result") else {
            write_client_bytes(&output, &line).await?;
            continue;
        };
        if !redact_value(result) {
            write_client_bytes(&output, &line).await?;
            continue;
        }

        let action = Action::new(
            scanner.context.clone(),
            ActionKind::McpToolCall {
                server: scanner.server.clone(),
                tool: "mcp.result_redacted".to_string(),
                args_json: json!({"tool": tool, "request_id": id}),
            },
        );
        let decision = result_redacted_decision();
        if let Err(error) = scanner.audit.append(&action, &decision, Some("policy")) {
            reply_error(
                &output,
                id,
                -32001,
                format!("Blocked by Privaku Agent Shield: cannot write audit log: {error}"),
            )
            .await?;
            continue;
        }
        let mut encoded = serde_json::to_vec(&response).map_err(io::Error::other)?;
        encoded.push(b'\n');
        write_client_bytes(&output, &encoded).await?;
    }
}

fn redact_value(value: &mut Value) -> bool {
    match value {
        Value::String(text) => {
            let redacted = secrets::redact(text);
            if redacted == *text {
                false
            } else {
                *text = redacted;
                true
            }
        }
        Value::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= redact_value(value);
            }
            changed
        }
        Value::Object(values) => {
            let mut changed = false;
            for value in values.values_mut() {
                changed |= redact_value(value);
            }
            changed
        }
        _ => false,
    }
}

fn result_redacted_decision() -> Decision {
    Decision {
        outcome: Outcome::Allow,
        rule_id: Some("mcp.result_redacted".to_string()),
        matched_rule_ids: vec!["mcp.result_redacted".to_string()],
        severity: Severity::High,
        reason_user: "Secret content was redacted from an MCP tool result".to_string(),
        reason_agent: "MCP tool result secret content was redacted before delivery.".to_string(),
        risk_score: RiskScore::MIN,
    }
}

async fn write_client_bytes<W>(output: &Arc<Mutex<W>>, bytes: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut output = output.lock().await;
    write_all_or_closed(&mut *output, bytes).await
}

async fn write_all_or_closed<W>(output: &mut W, bytes: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match output.write_all(bytes).await {
        Ok(()) => match output.flush().await {
            Ok(()) => Ok(()),
            Err(error) if child_gone(&error) => Ok(()),
            Err(error) => Err(error),
        },
        Err(error) if child_gone(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn shutdown_or_closed<W>(output: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match output.shutdown().await {
        Ok(()) => Ok(()),
        Err(error) if child_gone(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

fn child_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    )
}

async fn reply_error<W>(
    output: &Arc<Mutex<W>>,
    id: Value,
    code: i64,
    message: String,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut encoded = serde_json::to_vec(
        &json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    )
    .map_err(io::Error::other)?;
    encoded.push(b'\n');
    let mut output = output.lock().await;
    write_all_or_closed(&mut *output, &encoded).await
}

fn task_result(
    result: Result<Result<(), io::Error>, tokio::task::JoinError>,
) -> Result<(), ProxyError> {
    result.map_err(ProxyError::Task)?.map_err(ProxyError::Relay)
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map_or(1, |signal| 128 + signal)
    }
    #[cfg(not(unix))]
    {
        1
    }
}

#[cfg(unix)]
async fn wait_with_signals(child: &mut Child, child_id: u32) -> io::Result<ExitStatus> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    loop {
        tokio::select! {
            status = child.wait() => return status,
            received = interrupt.recv() => {
                if received.is_some() {
                    let _ = forward_signal(child_id, libc::SIGINT);
                }
            }
            received = terminate.recv() => {
                if received.is_some() {
                    let _ = forward_signal(child_id, libc::SIGTERM);
                }
            }
        }
    }
}

#[cfg(unix)]
fn forward_signal(child_id: u32, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: `child_id` is the process group id of the MCP server, created
    // with `process_group(0)` at spawn. A negative pid targets that group so
    // a shell wrapper and its descendants both receive SIGINT/SIGTERM.
    let result = unsafe { libc::kill(-(child_id as libc::pid_t), signal) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
async fn wait_with_signals(child: &mut Child, _child_id: u32) -> io::Result<ExitStatus> {
    child.wait().await
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(version().starts_with("0.1"));
    }

    #[test]
    fn exit_code_propagates_clean_child_status() {
        let success = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .status()
            .unwrap();
        assert_eq!(exit_code(success), 0);

        let failure = std::process::Command::new("sh")
            .args(["-c", "exit 42"])
            .status()
            .unwrap();
        assert_eq!(exit_code(failure), 42);
    }

    #[cfg(unix)]
    #[test]
    fn exit_code_maps_signal_termination() {
        use std::os::unix::process::ExitStatusExt;

        let interrupted = ExitStatus::from_raw(libc::SIGINT);
        assert_eq!(exit_code(interrupted), 128 + libc::SIGINT);
        let terminated = ExitStatus::from_raw(libc::SIGTERM);
        assert_eq!(exit_code(terminated), 128 + libc::SIGTERM);
    }

    #[test]
    fn parse_tool_call_forwards_non_calls_and_rejects_bad_params() {
        assert!(parse_tool_call(&json!({"method": "initialize"})).is_none());
        let call = parse_tool_call(&json!({
            "id": 7,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "hi"}}
        }))
        .unwrap()
        .unwrap();
        assert_eq!(call.0, json!(7));
        assert_eq!(call.1, "echo");
        assert_eq!(call.2, json!({"message": "hi"}));
        assert_eq!(
            parse_tool_call(&json!({"method": "tools/call", "params": {}}))
                .unwrap()
                .unwrap_err(),
            "tools/call params.name must be a string"
        );
    }

    #[test]
    fn blocked_message_prefixes_reason() {
        let decision = Decision {
            outcome: Outcome::Deny,
            rule_id: Some("test.ask".into()),
            matched_rule_ids: vec!["test.ask".into()],
            severity: Severity::Medium,
            reason_user: "needs a human".into(),
            reason_agent: "needs a human.".into(),
            risk_score: RiskScore::MIN,
        };
        let message = blocked_message(&decision);
        assert_eq!(message, "Blocked by Privaku Agent Shield: needs a human.");
        assert!(!blocked_message(&Decision {
            outcome: Outcome::Deny,
            rule_id: Some("test.deny".into()),
            matched_rule_ids: vec!["test.deny".into()],
            severity: Severity::Critical,
            reason_user: "blocked".into(),
            reason_agent: "blocked.".into(),
            risk_score: RiskScore::MIN,
        })
        .contains("M16"));
    }

    #[test]
    fn redact_value_removes_canary_aws_key() {
        let mut value = json!({
            "content": [{"type": "text", "text": "example cloud credential: AKIAIOSFODNN7EXAMPLE"}]
        });
        assert!(redact_value(&mut value));
        let encoded = value.to_string();
        assert!(!encoded.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(encoded.contains("[REDACTED:aws_access_key_id]"));
    }
}
