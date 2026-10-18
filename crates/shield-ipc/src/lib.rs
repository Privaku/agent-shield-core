//! JSON-lines IPC protocol, approval daemon, and client for Agent Shield.
//!
//! Protocol v1 messages: `hello`, `approval_request`, `approval_response`,
//! `subscribe`, `event{decision}`, and `ping`. The daemon listens on a
//! UNIX socket (mode 0600, peer-uid checked) and fails closed.

mod always_allow;
mod client;
mod daemon;
mod dialog;
mod error;
mod protocol;
mod rate_limit;
mod resolve;
mod transport;
mod ui;

pub use client::{ping, request_approval, request_approval_at};
pub use daemon::{run, run_until, DaemonConfig};
pub use dialog::{
    format_dialog_text, osascript_source, verdict_from_osascript_stdout, Dialog, DialogError,
    FailingDialog, MockDialog, OsascriptDialog, PlatformDialog,
};
pub use error::IpcError;
pub use protocol::{
    decode_line, encode_line, DecisionEvent, IpcMessage, IpcRole, PROTOCOL_VERSION,
};
pub use rate_limit::{AskRateLimiter, RateLimited, MAX_ASKS_PER_WINDOW, WINDOW as ASK_RATE_WINDOW};
pub use resolve::{
    action_summary, build_request, resolve_ask, resolve_ask_env, timeout_from_env, AskOptions,
    AskSource, ResolvedAsk, AUTONOMOUS_AGENT_MESSAGE, DAEMON_DOWN_AGENT_MESSAGE,
    RATE_LIMIT_AGENT_MESSAGE,
};
pub use transport::{
    current_uid, platform_socket_path, socket_path_from_env, IpcTransport, PeerCredentials,
    UnixIpcTransport, SOCKET_MODE,
};
pub use ui::{
    format_request, parse_script, parse_script_token, verdict_from_key, ApprovalUiSession,
};

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
}
