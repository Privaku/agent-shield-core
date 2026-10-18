//! Scripted `agent-shield approve` over the same IPC protocol as the TUI.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use shield_core::model::{
    AgentContext, AgentKind, ApprovalRequest, ApprovalVerdict, RiskScore, Severity,
};
use shield_ipc::request_approval_at;

struct Sandbox {
    _temp: tempfile::TempDir,
    home: PathBuf,
    socket: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let socket = temp.path().join("run/agent-shield.sock");
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        Self {
            _temp: temp,
            home,
            socket,
        }
    }

    fn bin() -> Command {
        Command::new(env!("CARGO_BIN_EXE_agent-shield"))
    }
}

fn spawn_daemon(sandbox: &Sandbox) -> Child {
    Sandbox::bin()
        .args(["daemon", "--foreground"])
        .env("HOME", &sandbox.home)
        .env("AGENT_SHIELD_SOCK", &sandbox.socket)
        .env("AGENT_SHIELD_ASK_TIMEOUT", "5")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon")
}

fn spawn_approve(sandbox: &Sandbox, script: &str) -> Child {
    Sandbox::bin()
        .args(["approve", "--script", script])
        .env("HOME", &sandbox.home)
        .env("AGENT_SHIELD_SOCK", &sandbox.socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn approve")
}

fn wait_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("daemon socket {} did not appear", path.display());
}

fn wait_subscribed(child: &mut Child) {
    let stdout = child.stdout.as_mut().expect("approve stdout");
    let mut reader = BufReader::new(stdout);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            panic!("approve exited before subscribe");
        }
        if line.contains("subscribed") {
            return;
        }
    }
    panic!("approve did not subscribe in time");
}

fn sample(id: &str) -> ApprovalRequest {
    ApprovalRequest {
        id: id.into(),
        action_summary: "read ~/.env".into(),
        rule: Some("secrets.dotenv".into()),
        severity: Severity::High,
        risk: RiskScore::MIN,
        reason_user: "Reading a dotenv file".into(),
        agent: AgentContext {
            agent: AgentKind::Claude,
            session_id: "approve-cli".into(),
            cwd: PathBuf::from("/work"),
            autonomous: false,
        },
    }
}

#[test]
fn scripted_approve_allows_then_denies() {
    let sandbox = Sandbox::new();
    let mut daemon = spawn_daemon(&sandbox);
    wait_socket(&sandbox.socket);
    let mut ui = spawn_approve(&sandbox, "a,d");
    wait_subscribed(&mut ui);

    let allow =
        request_approval_at(&sandbox.socket, sample("one"), Duration::from_secs(5)).unwrap();
    assert_eq!(allow.verdict, ApprovalVerdict::AllowOnce);
    assert_eq!(allow.by, "cli");

    let deny = request_approval_at(&sandbox.socket, sample("two"), Duration::from_secs(5)).unwrap();
    assert_eq!(deny.verdict, ApprovalVerdict::Deny);
    assert_eq!(deny.by, "cli");

    let _ = ui.kill();
    let _ = ui.wait();
    let _ = daemon.kill();
    let _ = daemon.wait();
}

#[test]
fn approve_without_daemon_fails_closed() {
    let sandbox = Sandbox::new();
    let output = Sandbox::bin()
        .args(["approve", "--script", "a", "--once"])
        .env("HOME", &sandbox.home)
        .env("AGENT_SHIELD_SOCK", sandbox.socket.join("missing.sock"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot connect") || stderr.contains("error"),
        "{stderr}"
    );
}

#[test]
fn help_mentions_script_flag() {
    let output = Sandbox::bin().args(["approve", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--script"), "{stdout}");
}
