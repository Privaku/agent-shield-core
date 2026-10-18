use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use shield_audit::ACTIVE_LOG_NAME;

const AWS_EXAMPLE_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const WARMUPS: usize = 10;
const SAMPLES: usize = 50;
const MEDIAN_BUDGET: Duration = Duration::from_millis(5);

struct Sandbox {
    _temp: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    cwd: PathBuf,
    log_path: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let state = temp.path().join("state");
        let cwd = temp.path().join("cwd");
        fs_create(&home);
        fs_create(&cwd);
        Self {
            log_path: temp.path().join("fake-mcp.log"),
            _temp: temp,
            home,
            state,
            cwd,
        }
    }

    fn write_project_policy(&self, contents: &str) {
        std::fs::write(self.cwd.join(".agent-shield.yaml"), contents).unwrap();
    }
}

struct Proxy {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    sandbox: Option<Sandbox>,
}

impl Proxy {
    fn spawn(sandbox: Sandbox, extra: &[&str], server: &[&str]) -> Self {
        let mut args = vec!["mcp-proxy", "--name", "fake"];
        args.extend_from_slice(extra);
        args.push("--");
        args.extend_from_slice(server);
        let mut child = base_command(&sandbox)
            .args(&args)
            .env("FAKE_MCP_LOG", &sandbox.log_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mcp-proxy");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().expect("proxy stdout"));
        Self {
            child,
            stdin,
            stdout,
            sandbox: Some(sandbox),
        }
    }

    fn spawn_fake(sandbox: Sandbox, extra: &[&str]) -> Self {
        let fake = fake_mcp_server();
        Self::spawn(sandbox, extra, &[fake.to_str().unwrap()])
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        self.stdin
            .as_mut()
            .expect("proxy stdin")
            .write_all(bytes)
            .unwrap();
        self.stdin.as_mut().unwrap().flush().unwrap();
    }

    fn read_raw(&mut self) -> Vec<u8> {
        let mut line = Vec::new();
        let n = self.stdout.read_until(b'\n', &mut line).unwrap();
        assert!(
            n > 0,
            "proxy closed stdout unexpectedly: {}",
            String::from_utf8_lossy(&line)
        );
        line
    }

    fn rpc(&mut self, request: &Value) -> Value {
        let bytes = json_line(request);
        self.write_raw(&bytes);
        let response = self.read_raw();
        serde_json::from_slice(&response).unwrap_or_else(|_| {
            panic!(
                "proxy returned non-JSON {:?}",
                String::from_utf8_lossy(&response)
            )
        })
    }

    fn finish(mut self) -> (ExitStatus, Sandbox, String) {
        drop(self.stdin.take());
        let status = wait_with_timeout(&mut self.child, Duration::from_secs(8));
        let stderr = read_remaining(self.child.stderr.take());
        assert!(
            status.success(),
            "proxy exited {:?}: {stderr}",
            status.code()
        );
        (status, self.sandbox.take().expect("sandbox"), stderr)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn initialize_list_echo_deny_and_redact_through_the_real_proxy() {
    let mut proxy = Proxy::spawn_fake(Sandbox::new(), &[]);
    let initialize = json_line(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "agent-shield-test", "version": "0.1.0"}
        }
    }));
    let tools_list = json_line(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    let direct = talk_to_fake(&[&initialize, &tools_list]);

    proxy.write_raw(&initialize);
    let initialize_response = proxy.read_raw();
    proxy.write_raw(&tools_list);
    let tools_list_response = proxy.read_raw();
    assert_eq!(
        initialize_response, direct[0],
        "initialize must be byte-identical"
    );
    assert_eq!(
        tools_list_response, direct[1],
        "tools/list must be byte-identical"
    );

    let echo = proxy.rpc(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "hello"}}
    }));
    assert!(echo.get("error").is_none(), "echo was blocked: {echo}");
    assert!(echo["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("hello"));

    proxy.write_raw(b"this is not json\n");
    let parse_error = proxy.read_raw();
    let parse_error: Value = serde_json::from_slice(&parse_error).unwrap();
    assert_eq!(parse_error["error"]["code"], -32700);
    assert_eq!(parse_error["id"], Value::Null);

    let denied = proxy.rpc(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}}
    }));
    assert_eq!(denied["id"], 4);
    assert_eq!(denied["error"]["code"], -32001);
    let message = denied["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("Blocked by Privaku Agent Shield:"),
        "{message}"
    );

    let fetch = proxy.rpc(&json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "fetch", "arguments": {}}
    }));
    let fetch_text = fetch.to_string();
    assert!(!fetch_text.contains(AWS_EXAMPLE_KEY_ID), "{fetch_text}");
    assert!(
        fetch_text.contains("[REDACTED:aws_access_key_id]"),
        "{fetch_text}"
    );

    let (_status, sandbox, _stderr) = proxy.finish();
    let server_log = std::fs::read_to_string(&sandbox.log_path).unwrap();
    assert!(
        server_log.contains("\"method\":\"initialize\""),
        "{server_log}"
    );
    assert!(
        server_log.contains("\"method\":\"tools/list\""),
        "{server_log}"
    );
    assert!(server_log.contains("\"name\":\"echo\""), "{server_log}");
    assert!(server_log.contains("\"name\":\"fetch\""), "{server_log}");
    assert!(
        !server_log.contains("this is not json"),
        "malformed JSON was forwarded: {server_log}"
    );
    assert!(
        server_log
            .lines()
            .all(|line| !line.contains("\"name\":\"read_file\"")),
        "denied read_file reached the server: {server_log}"
    );
    assert!(!server_log.contains("id_rsa"), "{server_log}");

    verify_audit(&sandbox, 4);
    let entries = audit_entries(&sandbox);
    assert_eq!(entries[0]["decision"], "allow");
    assert_eq!(entries[0]["approver"], "policy");
    assert_eq!(entries[1]["decision"], "deny");
    assert_eq!(entries[1]["rule_id"], "mcp.fs_secret_paths");
    assert_eq!(entries[1]["approver"], "policy");
    assert_eq!(entries[2]["decision"], "allow");
    assert_eq!(entries[3]["decision"], "allow");
    assert_eq!(entries[3]["rule_id"], "mcp.result_redacted");
}

#[test]
fn fetch_result_keeps_canary_when_redaction_is_disabled() {
    let mut proxy = Proxy::spawn_fake(Sandbox::new(), &["--no-redact-results"]);
    let fetch = proxy.rpc(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "fetch", "arguments": {}}
    }));
    let encoded = fetch.to_string();
    assert!(encoded.contains(AWS_EXAMPLE_KEY_ID), "{encoded}");
    assert!(!encoded.contains("[REDACTED:"));
    let (_status, sandbox, _) = proxy.finish();
    let entries = audit_entries(&sandbox);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["decision"], "allow");
    assert_ne!(entries[0]["rule_id"], "mcp.result_redacted");
}

#[test]
fn ask_without_ui_is_denied_and_audited_autonomous() {
    let sandbox = Sandbox::new();
    sandbox.write_project_policy(
        r#"
version: 1
rules:
  - id: test.mcp_echo_ask
    description: Echo requires approval
    severity: medium
    decision: ask
    match:
      mcp: { tool: echo }
    agent_message: Echo needs a human.
"#,
    );
    let mut proxy = Proxy::spawn_fake(sandbox, &[]);
    let response = proxy.rpc(&json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "secret?"}}
    }));
    assert_eq!(response["error"]["code"], -32001);
    let message = response["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("Blocked by Privaku Agent Shield:"),
        "{message}"
    );
    assert!(
        message.contains("no human") || message.contains("do not retry"),
        "{message}"
    );
    let (_status, sandbox, _) = proxy.finish();
    let server_log = std::fs::read_to_string(&sandbox.log_path).unwrap_or_default();
    assert!(
        !server_log.contains("\"name\":\"echo\""),
        "Ask was forwarded: {server_log}"
    );
    verify_audit(&sandbox, 1);
    let entries = audit_entries(&sandbox);
    assert_eq!(entries[0]["decision"], "deny");
    assert_eq!(entries[0]["rule_id"], "test.mcp_echo_ask");
    assert_eq!(entries[0]["approver"], "autonomous");
}

#[test]
fn stderr_is_passed_through_byte_identical() {
    let sandbox = Sandbox::new();
    let mut proxy = Proxy::spawn(
        sandbox,
        &[],
        &[
            "sh",
            "-c",
            "printf 'err-bytes'; printf 'err-bytes' >&2; exit 0",
        ],
    );
    drop(proxy.stdin.take());
    let status = wait_with_timeout(&mut proxy.child, Duration::from_secs(5));
    let stderr = read_remaining(proxy.child.stderr.take());
    let mut stdout = Vec::new();
    proxy.stdout.read_to_end(&mut stdout).unwrap();
    assert!(status.success(), "proxy failed: {stderr}");
    assert_eq!(stderr, "err-bytes");
    assert_eq!(stdout, b"err-bytes");
}

#[test]
fn immediate_child_exit_codes_propagate() {
    assert_eq!(proxy_exit(&["true"]), 0);
    assert_eq!(proxy_exit(&["false"]), 1);
    assert_eq!(proxy_exit(&["sh", "-c", "exit 42"]), 42);
}

#[cfg(unix)]
#[test]
fn forwarded_signals_terminate_a_shell_server() {
    assert_signal_terminates("INT", 130);
    assert_signal_terminates("TERM", 143);
}

#[test]
fn median_added_relay_latency_is_under_five_milliseconds_in_release() {
    if cfg!(debug_assertions) {
        eprintln!("mcp relay latency gate runs only with cargo test --release");
        return;
    }

    let mut proxy = Proxy::spawn_fake(Sandbox::new(), &[]);
    let direct_sandbox = Sandbox::new();
    let mut direct = spawn_fake_direct(&direct_sandbox);
    let mut proxy_samples = Vec::with_capacity(SAMPLES);
    let mut direct_samples = Vec::with_capacity(SAMPLES);

    for index in 0..(WARMUPS + SAMPLES) {
        let request = json_line(&json!({
            "jsonrpc": "2.0",
            "id": index,
            "method": "tools/list",
            "params": {}
        }));

        let started = Instant::now();
        proxy.write_raw(&request);
        let proxied = proxy.read_raw();
        let proxy_elapsed = started.elapsed();
        assert!(
            proxied.starts_with(b"{"),
            "proxy returned {:?}",
            String::from_utf8_lossy(&proxied)
        );

        let started = Instant::now();
        direct.stdin.as_mut().unwrap().write_all(&request).unwrap();
        direct.stdin.as_mut().unwrap().flush().unwrap();
        let mut direct_line = Vec::new();
        let n = direct.stdout.read_until(b'\n', &mut direct_line).unwrap();
        let direct_elapsed = started.elapsed();
        assert!(
            n > 0,
            "direct fake server closed stdout: {:?}",
            String::from_utf8_lossy(&direct_line)
        );
        assert_eq!(proxied, direct_line);

        if index >= WARMUPS {
            proxy_samples.push(proxy_elapsed);
            direct_samples.push(direct_elapsed);
        }
    }

    drop(direct.stdin.take());
    let _ = direct.child.wait();
    let _ = proxy.finish();

    proxy_samples.sort_unstable();
    direct_samples.sort_unstable();
    let proxy_median = proxy_samples[SAMPLES / 2];
    let direct_median = direct_samples[SAMPLES / 2];
    let added = proxy_median.saturating_sub(direct_median);
    println!(
        "median MCP relay latency: proxy {:.3} ms, direct {:.3} ms, added {:.3} ms over {SAMPLES} messages",
        proxy_median.as_secs_f64() * 1_000.0,
        direct_median.as_secs_f64() * 1_000.0,
        added.as_secs_f64() * 1_000.0
    );
    assert!(
        added < MEDIAN_BUDGET,
        "median added relay latency {:.3} ms exceeds 5 ms",
        added.as_secs_f64() * 1_000.0
    );
}

struct DirectServer {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Drop for DirectServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn spawn_fake_direct(sandbox: &Sandbox) -> DirectServer {
    let mut child = Command::new(fake_mcp_server())
        .env(
            "FAKE_MCP_LOG",
            sandbox.log_path.with_extension("direct.log"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    DirectServer {
        child,
        stdin,
        stdout,
    }
}

fn talk_to_fake(requests: &[&[u8]]) -> Vec<Vec<u8>> {
    let sandbox = Sandbox::new();
    let mut child = Command::new(fake_mcp_server())
        .env(
            "FAKE_MCP_LOG",
            sandbox.log_path.with_extension("direct.log"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for request in requests {
            stdin.write_all(request).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    split_lines(&output.stdout)
}

fn proxy_exit(server: &[&str]) -> i32 {
    let sandbox = Sandbox::new();
    let status = base_command(&sandbox)
        .args(["mcp-proxy", "--name", "t", "--"])
        .args(server)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .unwrap();
    status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(1, |signal| 128 + signal)
        }
        #[cfg(not(unix))]
        {
            1
        }
    })
}

#[cfg(unix)]
fn assert_signal_terminates(signal: &str, expected: i32) {
    let sandbox = Sandbox::new();
    let mut child = base_command(&sandbox)
        .args(["mcp-proxy", "--name", "t", "--", "sh", "-c", "sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(250));
    let pid = child.id();
    let sent = Command::new("kill")
        .args([format!("-{signal}"), pid.to_string()])
        .status()
        .unwrap();
    assert!(sent.success(), "kill -{signal} {pid} failed");
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map_or(1, |value| 128 + value)
    });
    assert_eq!(
        code,
        expected,
        "signal {signal} produced {code}, stderr {}",
        read_remaining(child.stderr.take())
    );
}

fn verify_audit(sandbox: &Sandbox, entries: usize) {
    let output = base_command(sandbox)
        .args(["log", "verify"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "log verify failed: {stdout}{stderr}"
    );
    assert!(
        stdout.contains(&format!("OK: {entries} entries")),
        "{stdout}"
    );
}

fn audit_entries(sandbox: &Sandbox) -> Vec<Value> {
    let contents = std::fs::read_to_string(sandbox.state.join(ACTIVE_LOG_NAME)).unwrap();
    contents
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn base_command(sandbox: &Sandbox) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin("agent-shield"));
    command
        .env_clear()
        .env("HOME", &sandbox.home)
        .env("AGENT_SHIELD_STATE_DIR", &sandbox.state)
        .env("AGENT_SHIELD_SOCK", sandbox.home.join("no-daemon.sock"))
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .current_dir(&sandbox.cwd);
    command
}

fn fake_mcp_server_path() -> PathBuf {
    let mut path = assert_cmd::cargo::cargo_bin("agent-shield");
    path.set_file_name(format!("fake-mcp-server{}", std::env::consts::EXE_SUFFIX));
    path
}

fn fake_mcp_server() -> PathBuf {
    static BUILD: std::sync::Once = std::sync::Once::new();
    BUILD.call_once(|| {
        let path = fake_mcp_server_path();
        if path.exists() {
            return;
        }
        let mut build = Command::new(env!("CARGO"));
        build.args(["build", "-p", "fake-mcp-server"]);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(
            build.status().unwrap().success(),
            "failed to build fake-mcp-server"
        );
    });
    let path = fake_mcp_server_path();
    assert!(path.exists(), "missing {}", path.display());
    path
}

fn json_line(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn split_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(bytes[start..=index].to_vec());
            start = index + 1;
        }
    }
    if start < bytes.len() {
        lines.push(bytes[start..].to_vec());
    }
    lines
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timed out waiting for mcp-proxy after {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_remaining(stream: Option<impl Read>) -> String {
    let Some(mut stream) = stream else {
        return String::new();
    };
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf
}

fn fs_create(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
}
