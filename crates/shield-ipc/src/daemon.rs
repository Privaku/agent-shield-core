//! Approval daemon: UNIX socket broker for Ask decisions.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use shield_core::model::{ApprovalRequest, ApprovalResponse, ApprovalVerdict};
use shield_core::policy::{self, Paths as PolicyPaths};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::always_allow::{append_user_rule, normalised_action};
use crate::error::IpcError;
use crate::protocol::{
    decode_line, encode_line, DecisionEvent, IpcMessage, IpcRole, PROTOCOL_VERSION,
};
use crate::transport::{current_uid, socket_path_from_env, IpcTransport, UnixIpcTransport};

/// Maximum JSON-lines message size. Larger frames fail closed.
const MAX_LINE_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How the daemon is configured. Tests inject a temp socket and a 1 s timeout.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub timeout: Duration,
    pub home: PathBuf,
    pub user_policy: PathBuf,
    pub uid: u32,
}

impl DaemonConfig {
    /// Production configuration from the environment and the merged policy.
    pub fn from_env() -> Result<Self, IpcError> {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or(IpcError::MissingHome)?;
        let socket_path = socket_path_from_env()?;
        let user_policy = PolicyPaths::new(Some(&home), None)
            .user_policy
            .expect("HOME is set");
        let timeout = timeout_from_env(&home);
        Ok(Self {
            socket_path,
            timeout,
            home,
            user_policy,
            uid: current_uid(),
        })
    }
}

fn timeout_from_env(home: &std::path::Path) -> Duration {
    if let Ok(raw) = std::env::var("AGENT_SHIELD_ASK_TIMEOUT") {
        if let Ok(seconds) = raw.parse::<u64>() {
            return Duration::from_secs(seconds.max(1));
        }
    }
    match policy::load(&PolicyPaths::new(Some(home), None)) {
        Ok(policy) => Duration::from_secs(policy.defaults.ask_timeout_seconds),
        Err(_) => DEFAULT_TIMEOUT,
    }
}

struct Pending {
    reply: oneshot::Sender<ApprovalResponse>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    session: String,
    rule: String,
    action: String,
}

impl CacheKey {
    fn from_request(request: &ApprovalRequest) -> Self {
        Self {
            session: request.agent.session_id.clone(),
            rule: request.rule.clone().unwrap_or_default(),
            action: normalised_action(&request.action_summary),
        }
    }
}

struct UiSink {
    tx: mpsc::UnboundedSender<IpcMessage>,
}

struct Inner {
    config: DaemonConfig,
    uis: HashMap<u64, UiSink>,
    pending: HashMap<String, Pending>,
    cache: HashMap<CacheKey, ()>,
    next_id: u64,
}

impl Inner {
    fn subscribed_ui_count(&self) -> usize {
        self.uis.len()
    }

    fn broadcast(&self, message: &IpcMessage) {
        for ui in self.uis.values() {
            let _ = ui.tx.send(message.clone());
        }
    }
}

/// Run until `shutdown` completes. Used by the CLI and by integration tests.
pub async fn run_until(
    config: DaemonConfig,
    transport: UnixIpcTransport,
    ready: Option<oneshot::Sender<()>>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), IpcError> {
    let listener = transport.bind(&config.socket_path)?;
    if let Some(ready) = ready {
        let _ = ready.send(());
    }
    let state = Arc::new(Mutex::new(Inner {
        config,
        uis: HashMap::new(),
        pending: HashMap::new(),
        cache: HashMap::new(),
        next_id: 1,
    }));
    let uid = state.lock().await.config.uid;

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        if error.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        break;
                    }
                };
                match transport.peer_credentials(&stream) {
                    Ok(creds) if creds.uid == uid => {}
                    Ok(creds) => {
                        let _ = creds;
                        continue;
                    }
                    Err(_) => continue,
                }
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _ = handle_connection(state, stream).await;
                });
            }
        }
    }
    Ok(())
}

/// Blocking entry used by `agent-shield daemon`.
pub fn run(config: DaemonConfig, foreground: bool) -> Result<(), IpcError> {
    if !foreground {
        daemonize()?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|source| IpcError::io("runtime", "<tokio>", source))?;
    runtime.block_on(async {
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let stop = async move {
            let _ = stop_rx.await;
        };
        let path = config.socket_path.clone();
        eprintln!("agent-shield daemon listening on {}", path.display());
        let run = run_until(config, UnixIpcTransport, None, stop);
        tokio::select! {
            result = run => result,
            _ = tokio::signal::ctrl_c() => {
                let _ = stop_tx.send(());
                Ok(())
            }
        }
    })
}

fn daemonize() -> Result<(), IpcError> {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(IpcError::io(
                "fork",
                "<process>",
                std::io::Error::last_os_error(),
            ));
        }
        if pid > 0 {
            libc::_exit(0);
        }
        libc::setsid();
        let pid = libc::fork();
        if pid < 0 {
            return Err(IpcError::io(
                "fork",
                "<process>",
                std::io::Error::last_os_error(),
            ));
        }
        if pid > 0 {
            libc::_exit(0);
        }
        libc::chdir(c"/".as_ptr());
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
    Ok(())
}

async fn handle_connection(state: Arc<Mutex<Inner>>, stream: UnixStream) -> Result<(), IpcError> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let first = read_line(&mut lines).await?;
    let hello = decode_line(&first)?;
    let role = match hello {
        IpcMessage::Hello { version, .. } if version != PROTOCOL_VERSION => {
            return Err(IpcError::UnsupportedVersion(version));
        }
        IpcMessage::Hello { role, .. } => role,
        other => {
            return Err(IpcError::protocol(format!(
                "first message must be hello, got {other:?}"
            )));
        }
    };

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<IpcMessage>();
    let mut ui_id = None;

    let writer_task = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            let line = match encode_line(&message) {
                Ok(line) => line,
                Err(_) => break,
            };
            if writer.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let result = drive_connection(state.clone(), role, &mut ui_id, &mut lines, &out_tx).await;

    if let Some(id) = ui_id {
        state.lock().await.uis.remove(&id);
    }
    drop(out_tx);
    let _ = writer_task.await;
    result
}

async fn drive_connection(
    state: Arc<Mutex<Inner>>,
    role: IpcRole,
    ui_id: &mut Option<u64>,
    lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    out_tx: &mpsc::UnboundedSender<IpcMessage>,
) -> Result<(), IpcError> {
    loop {
        let line = match read_line(lines).await {
            Ok(line) => line,
            Err(IpcError::Protocol(message)) if message == "eof" => break,
            Err(error) => return Err(error),
        };
        let message = decode_line(&line)?;
        match (role, message) {
            (_, IpcMessage::Ping) => {
                let _ = out_tx.send(IpcMessage::Ping);
            }
            (IpcRole::Ui, IpcMessage::Subscribe) => {
                let mut inner = state.lock().await;
                if ui_id.is_none() {
                    let id = inner.next_id;
                    inner.next_id += 1;
                    inner.uis.insert(id, UiSink { tx: out_tx.clone() });
                    *ui_id = Some(id);
                }
            }
            (IpcRole::Ui, IpcMessage::ApprovalResponse { id, verdict, by }) => {
                complete_request(
                    &state,
                    ApprovalResponse {
                        id: id.clone(),
                        verdict,
                        by,
                    },
                )
                .await;
            }
            (IpcRole::Client, IpcMessage::ApprovalRequest { .. }) => {
                let request = decode_line(&line)?
                    .as_request()
                    .expect("just matched ApprovalRequest");
                let response = process_request(state.clone(), request).await;
                let _ = out_tx.send(IpcMessage::from_response(response));
            }
            (_, IpcMessage::Event { decision }) => {
                state
                    .lock()
                    .await
                    .broadcast(&IpcMessage::Event { decision });
            }
            (_, IpcMessage::Hello { .. }) => {
                return Err(IpcError::protocol("duplicate hello"));
            }
            (role, other) => {
                return Err(IpcError::protocol(format!(
                    "{role:?} sent unexpected message {other:?}"
                )));
            }
        }
    }
    Ok(())
}

async fn process_request(state: Arc<Mutex<Inner>>, request: ApprovalRequest) -> ApprovalResponse {
    let key = CacheKey::from_request(&request);
    {
        let inner = state.lock().await;
        if inner.cache.contains_key(&key) {
            let response = ApprovalResponse {
                id: request.id.clone(),
                verdict: ApprovalVerdict::AllowSession,
                by: "session_cache".into(),
            };
            inner.broadcast(&IpcMessage::Event {
                decision: DecisionEvent::from_approval(&request, response.verdict),
            });
            return response;
        }
        if inner.subscribed_ui_count() == 0 {
            let response = ApprovalResponse {
                id: request.id.clone(),
                verdict: ApprovalVerdict::Deny,
                by: "no_ui".into(),
            };
            inner.broadcast(&IpcMessage::Event {
                decision: DecisionEvent::from_approval(&request, response.verdict),
            });
            return response;
        }
    }

    let timeout = state.lock().await.config.timeout;
    let (tx, rx) = oneshot::channel();
    {
        let mut inner = state.lock().await;
        inner.broadcast(&IpcMessage::from_request(request.clone()));
        inner
            .pending
            .insert(request.id.clone(), Pending { reply: tx });
    }

    let response = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => ApprovalResponse {
            id: request.id.clone(),
            verdict: ApprovalVerdict::Deny,
            by: "timeout".into(),
        },
        Err(_) => {
            let mut inner = state.lock().await;
            inner.pending.remove(&request.id);
            ApprovalResponse {
                id: request.id.clone(),
                verdict: ApprovalVerdict::Deny,
                by: "timeout".into(),
            }
        }
    };

    apply_verdict(state, &request, response).await
}

async fn complete_request(state: &Arc<Mutex<Inner>>, response: ApprovalResponse) {
    let mut inner = state.lock().await;
    if let Some(pending) = inner.pending.remove(&response.id) {
        let _ = pending.reply.send(response);
    }
}

async fn apply_verdict(
    state: Arc<Mutex<Inner>>,
    request: &ApprovalRequest,
    mut response: ApprovalResponse,
) -> ApprovalResponse {
    match response.verdict {
        ApprovalVerdict::AllowSession => {
            let mut inner = state.lock().await;
            inner.cache.insert(CacheKey::from_request(request), ());
        }
        ApprovalVerdict::AlwaysAllow => {
            let (home, user_policy) = {
                let inner = state.lock().await;
                (inner.config.home.clone(), inner.config.user_policy.clone())
            };
            if let Err(error) = append_user_rule(&home, &user_policy, request) {
                response.verdict = ApprovalVerdict::Deny;
                response.by = format!("always_allow_failed: {error}");
            }
        }
        ApprovalVerdict::AllowOnce | ApprovalVerdict::Deny => {}
    }
    state.lock().await.broadcast(&IpcMessage::Event {
        decision: DecisionEvent::from_approval(request, response.verdict),
    });
    response
}

async fn read_line(
    lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
) -> Result<String, IpcError> {
    match lines.next_line().await {
        Ok(Some(line)) if line.len() > MAX_LINE_BYTES => {
            Err(IpcError::protocol("IPC line too long"))
        }
        Ok(Some(line)) if line.is_empty() => Err(IpcError::protocol("empty IPC line")),
        Ok(Some(line)) => Ok(line),
        Ok(None) => Err(IpcError::protocol("eof")),
        Err(error) => Err(IpcError::from(error)),
    }
}
