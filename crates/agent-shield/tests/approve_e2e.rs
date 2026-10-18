//! Linux E2E: scripted approve UI, autonomous no-UI, daemon-down, T12 rate limit.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use shield_audit::ACTIVE_LOG_NAME;

struct Harness {
    _temp: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    cwd: PathBuf,
    socket: PathBuf,
    rate_dir: PathBuf,
    daemon: Child,
    approve: Option<Child>,
}

impl Harness {
    fn start(with_ui_script: Option<&str>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let state = temp.path().join("state");
        let cwd = temp.path().join("cwd");
        let socket = temp.path().join("run/agent-shield.sock");
        let rate_dir = temp.path().join("rate");
        for dir in [&home, &state, &cwd, socket.parent().unwrap(), &rate_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let daemon = bin()
            .args(["daemon", "--foreground"])
            .env("HOME", &home)
            .env("AGENT_SHIELD_SOCK", &socket)
            .env("AGENT_SHIELD_ASK_TIMEOUT", "5")
            .env("AGENT_SHIELD_STATE_DIR", &state)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("daemon");
        wait_path(&socket);
        let approve = with_ui_script.map(|script| {
            let mut child = bin()
                .args(["approve", "--script", script])
                .env("HOME", &home)
                .env("AGENT_SHIELD_SOCK", &socket)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("approve");
            wait_subscribed(&mut child);
            child
        });
        Self {
            _temp: temp,
            home,
            state,
            cwd,
            socket,
            rate_dir,
            daemon,
            approve,
        }
    }

    fn command(&self) -> Command {
        let mut command = bin();
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("AGENT_SHIELD_STATE_DIR", &self.state)
            .env("AGENT_SHIELD_SOCK", &self.socket)
            .env("AGENT_SHIELD_RATE_DIR", &self.rate_dir)
            .env("AGENT_SHIELD_ASK_TIMEOUT", "5")
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(&self.cwd);
        command
    }

    fn hook(&self, agent: &str, stdin: &[u8]) -> Value {
        let mut command = self.command();
        command.args(["hook", agent]);
        let output = run_with_stdin(command, stdin);
        assert!(
            output.status.success(),
            "hook {agent} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("hook json")
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.state.join(ACTIVE_LOG_NAME))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut ui) = self.approve.take() {
            let _ = ui.kill();
            let _ = ui.wait();
        }
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agent-shield"))
}

fn run_with_stdin(mut command: Command, stdin: &[u8]) -> Output {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn");
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn wait_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{} did not appear", path.display());
}

fn wait_subscribed(child: &mut Child) {
    let stdout = child.stdout.as_mut().expect("approve stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            panic!("approve exited before subscribe");
        }
        if line.contains("subscribed") {
            return;
        }
    }
    panic!("approve did not subscribe");
}

fn fixtures(rel: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(rel),
    )
    .unwrap()
}

fn claude_read(session: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "tool_name": "Read",
        "tool_input": {"file_path": ".env"},
        "cwd": "/workspace",
        "session_id": session,
        "hook_event_name": "PreToolUse"
    }))
    .unwrap()
}

fn permission(response: &Value) -> &str {
    response["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .or_else(|| response["permission"].as_str())
        .unwrap()
}

#[test]
fn scripted_ui_allows_and_denies_claude_cursor_and_mcp_asks() {
    let harness = Harness::start(Some("a,d,a,d,a,d"));

    let claude_allow = harness.hook("claude", &fixtures("claude/read_dotenv.json"));
    assert_eq!(permission(&claude_allow), "allow");

    let claude_deny = harness.hook("claude", &fixtures("claude/write_zshrc.json"));
    assert_eq!(permission(&claude_deny), "deny");
    assert!(
        claude_deny["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("do not retry")
    );

    let cursor_allow = harness.hook("cursor", &fixtures("cursor/read_dotenv.json"));
    assert_eq!(permission(&cursor_allow), "allow");

    let cursor_deny = harness.hook("cursor", &fixtures("cursor/read_dotenv.json"));
    assert_eq!(permission(&cursor_deny), "deny");

    let mut proxy = spawn_ask_proxy(&harness);
    let allowed = proxy.rpc(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "from-ui"}}
    }));
    assert!(allowed.get("error").is_none(), "mcp allow: {allowed}");
    assert!(allowed["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("from-ui"));

    let denied = proxy.rpc(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "blocked"}}
    }));
    assert_eq!(denied["error"]["code"], -32001);
    let log = std::fs::read_to_string(&proxy.log_path).unwrap_or_default();
    assert!(
        log.contains("from-ui"),
        "allowed call was not forwarded: {log}"
    );
    assert!(!log.contains("blocked"), "denied call was forwarded: {log}");
    proxy.finish();

    let entries = harness.audit();
    assert!(
        entries.len() >= 6,
        "expected hook+mcp audits, got {}",
        entries.len()
    );
}

#[test]
fn no_ui_denies_and_audits_autonomous() {
    let harness = Harness::start(None);
    let response = harness.hook("claude", &fixtures("claude/read_dotenv.json"));
    assert_eq!(permission(&response), "deny");
    let reason = response["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("no human was available"), "{reason}");
    assert!(reason.contains("Continue with other work"), "{reason}");
    let entries = harness.audit();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["decision"], "deny");
    assert_eq!(entries[0]["approver"], "autonomous");
    assert_eq!(entries[0]["rule_id"], "secrets.dotenv");
}

#[test]
fn daemon_down_denies_ask_fixtures() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let state = temp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    let output = run_with_stdin(
        {
            let mut command = bin();
            command
                .args(["hook", "claude"])
                .env_clear()
                .env("HOME", &home)
                .env("AGENT_SHIELD_STATE_DIR", &state)
                .env("AGENT_SHIELD_SOCK", home.join("missing.sock"))
                .env("PATH", std::env::var_os("PATH").unwrap_or_default());
            command
        },
        &fixtures("claude/read_dotenv.json"),
    );
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(permission(&response), "deny");
    let reason = response["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("do not retry"), "{reason}");
    let entries: Vec<Value> = std::fs::read_to_string(state.join(ACTIVE_LOG_NAME))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries[0]["approver"], "autonomous");
}

#[test]
fn sixth_ask_from_one_session_is_denied() {
    let harness = Harness::start(Some("a,a,a,a,a"));
    for i in 0..5 {
        let response = harness.hook("claude", &claude_read("rate-sess"));
        assert_eq!(permission(&response), "allow", "ask {i} should be allowed");
    }
    let sixth = harness.hook("claude", &claude_read("rate-sess"));
    assert_eq!(permission(&sixth), "deny");
    let reason = sixth["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(
        reason.contains("paused") || reason.contains("too many"),
        "{reason}"
    );
    let last = harness.audit().pop().unwrap();
    assert_eq!(last["approver"], "rate_limit");
    assert_eq!(last["decision"], "deny");
}

struct AskProxy {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    log_path: PathBuf,
}

impl AskProxy {
    fn rpc(&mut self, request: &Value) -> Value {
        let mut bytes = serde_json::to_vec(request).unwrap();
        bytes.push(b'\n');
        self.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
        self.stdin.as_mut().unwrap().flush().unwrap();
        let mut line = Vec::new();
        self.stdout.read_until(b'\n', &mut line).unwrap();
        serde_json::from_slice(&line).unwrap()
    }

    fn finish(mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_ask_proxy(harness: &Harness) -> AskProxy {
    std::fs::write(
        harness.cwd.join(".agent-shield.yaml"),
        r#"
version: 1
rules:
  - id: test.mcp_echo_ask
    description: Echo requires approval
    severity: medium
    decision: ask
    match:
      mcp: { tool: echo }
"#,
    )
    .unwrap();
    let log_path = harness.cwd.join("fake-mcp.log");
    let fake = fake_mcp_server();
    let mut child = harness
        .command()
        .args(["mcp-proxy", "--name", "fake", "--", fake.to_str().unwrap()])
        .env("FAKE_MCP_LOG", &log_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("mcp-proxy");
    AskProxy {
        stdin: child.stdin.take(),
        stdout: BufReader::new(child.stdout.take().unwrap()),
        child,
        log_path,
    }
}

fn fake_mcp_server() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_agent-shield"));
    path.set_file_name(format!("fake-mcp-server{}", std::env::consts::EXE_SUFFIX));
    if !path.exists() {
        let status = Command::new("cargo")
            .args(["build", "-p", "fake-mcp-server"])
            .status()
            .unwrap();
        assert!(status.success());
    }
    path
}
