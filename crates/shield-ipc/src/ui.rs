//! Synchronous approval-UI session used by `agent-shield approve`.
//!
//! The interactive TUI and the scripted mock share this protocol loop so
//! CI never needs a TTY.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use shield_core::model::{ApprovalRequest, ApprovalResponse, ApprovalVerdict};

use crate::error::IpcError;
use crate::protocol::{decode_line, encode_line, IpcMessage, IpcRole};
use crate::transport::{socket_path_from_env, IpcTransport, UnixIpcTransport};

/// A subscribed UI connection to the approval daemon.
pub struct ApprovalUiSession {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl ApprovalUiSession {
    /// Connect to the platform socket (or `AGENT_SHIELD_SOCK`).
    pub fn connect() -> Result<Self, IpcError> {
        Self::connect_at(&socket_path_from_env()?)
    }

    /// Connect, send `hello{role: ui}` and `subscribe`.
    pub fn connect_at(path: &Path) -> Result<Self, IpcError> {
        let stream = UnixIpcTransport.connect_std(path)?;
        let writer = stream
            .try_clone()
            .map_err(|source| IpcError::io("clone", path, source))?;
        let mut session = Self {
            reader: BufReader::new(stream),
            writer,
        };
        session.write(&IpcMessage::hello(IpcRole::Ui))?;
        session.write(&IpcMessage::Subscribe)?;
        Ok(session)
    }

    /// Block until the next `approval_request`. Live events and pings are skipped.
    pub fn next_request(&mut self) -> Result<ApprovalRequest, IpcError> {
        loop {
            let message = self.read()?;
            if let Some(request) = message.as_request() {
                return Ok(request);
            }
            if matches!(message, IpcMessage::Ping) {
                let _ = self.write(&IpcMessage::Ping);
            }
        }
    }

    pub fn respond(
        &mut self,
        id: &str,
        verdict: ApprovalVerdict,
        by: &str,
    ) -> Result<(), IpcError> {
        self.write(&IpcMessage::from_response(ApprovalResponse {
            id: id.to_string(),
            verdict,
            by: by.to_string(),
        }))
    }

    fn write(&mut self, message: &IpcMessage) -> Result<(), IpcError> {
        let line = encode_line(message)?;
        self.writer
            .write_all(line.as_bytes())
            .map_err(|source| IpcError::io("write", "<socket>", source))?;
        self.writer
            .flush()
            .map_err(|source| IpcError::io("flush", "<socket>", source))
    }

    fn read(&mut self) -> Result<IpcMessage, IpcError> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|source| IpcError::io("read", "<socket>", source))?;
        if n == 0 {
            return Err(IpcError::protocol("daemon closed the UI connection"));
        }
        Ok(decode_line(&line)?)
    }
}

/// Map a key or script token to a verdict.
///
/// Keys: `a` allow once, `s` allow for session, `A` always allow, `d` deny.
pub fn verdict_from_key(key: char) -> Option<ApprovalVerdict> {
    match key {
        'a' => Some(ApprovalVerdict::AllowOnce),
        's' => Some(ApprovalVerdict::AllowSession),
        'A' => Some(ApprovalVerdict::AlwaysAllow),
        'd' => Some(ApprovalVerdict::Deny),
        _ => None,
    }
}

/// Parse one `--script` token (`a`, `s`, `A`, `d`, or a snake_case name).
pub fn parse_script_token(token: &str) -> Result<ApprovalVerdict, IpcError> {
    let token = token.trim();
    if token.len() == 1 {
        if let Some(verdict) = token.chars().next().and_then(verdict_from_key) {
            return Ok(verdict);
        }
    }
    match token {
        "allow_once" | "allow-once" => Ok(ApprovalVerdict::AllowOnce),
        "allow_session" | "allow-session" => Ok(ApprovalVerdict::AllowSession),
        "always_allow" | "always-allow" => Ok(ApprovalVerdict::AlwaysAllow),
        "deny" => Ok(ApprovalVerdict::Deny),
        other => Err(IpcError::protocol(format!(
            "unknown approval script token `{other}` (use a, s, A, d)"
        ))),
    }
}

pub fn parse_script(script: &str) -> Result<Vec<ApprovalVerdict>, IpcError> {
    if script.trim().is_empty() {
        return Ok(Vec::new());
    }
    script
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(parse_script_token)
        .collect()
}

/// Human-readable request block shown by the TUI and the scripted client.
pub fn format_request(request: &ApprovalRequest) -> String {
    let rule = request.rule.as_deref().unwrap_or("(none)");
    format!(
        "Agent: {}\nAction: {}\nRule: {}\nRisk: {}\nSeverity: {}\n\n{}",
        request.agent.agent.as_str(),
        request.action_summary,
        rule,
        request.risk,
        request.severity.as_str(),
        request.reason_user
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use shield_core::model::{AgentContext, AgentKind, RiskScore, Severity};

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: "ui-1".into(),
            action_summary: "read ~/.env".into(),
            rule: Some("secrets.dotenv".into()),
            severity: Severity::High,
            risk: RiskScore::new(0.2).unwrap(),
            reason_user: "Reading a dotenv file".into(),
            agent: AgentContext {
                agent: AgentKind::Cursor,
                session_id: "c1".into(),
                cwd: PathBuf::from("/work"),
                autonomous: false,
            },
        }
    }

    #[test]
    fn keys_map_to_verdicts() {
        assert_eq!(verdict_from_key('a'), Some(ApprovalVerdict::AllowOnce));
        assert_eq!(verdict_from_key('s'), Some(ApprovalVerdict::AllowSession));
        assert_eq!(verdict_from_key('A'), Some(ApprovalVerdict::AlwaysAllow));
        assert_eq!(verdict_from_key('d'), Some(ApprovalVerdict::Deny));
        assert_eq!(verdict_from_key('x'), None);
    }

    #[test]
    fn script_parses_keys_and_names() {
        let verdicts = parse_script("a, deny, s, always_allow").unwrap();
        assert_eq!(
            verdicts,
            vec![
                ApprovalVerdict::AllowOnce,
                ApprovalVerdict::Deny,
                ApprovalVerdict::AllowSession,
                ApprovalVerdict::AlwaysAllow,
            ]
        );
        assert!(parse_script("nope").is_err());
    }

    #[test]
    fn format_request_shows_redacted_summary_and_rule() {
        let text = format_request(&request());
        assert!(text.contains("Agent: cursor"), "{text}");
        assert!(text.contains("Action: read ~/.env"), "{text}");
        assert!(text.contains("Rule: secrets.dotenv"), "{text}");
        assert!(text.contains("Severity: high"), "{text}");
        assert!(!text.contains("AKIA"), "{text}");
    }
}
