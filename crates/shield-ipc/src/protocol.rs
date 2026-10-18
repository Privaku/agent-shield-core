//! Version 1 JSON-lines messages for the approval daemon.
//!
//! One object per line. Unknown fields and unknown `type` values are
//! rejected so a malformed peer fails closed.

use serde::{Deserialize, Serialize};
use shield_core::model::{
    AgentContext, AgentKind, ApprovalRequest, ApprovalResponse, ApprovalVerdict, Outcome,
    RiskScore, Severity,
};

/// Protocol version spoken by this build. A hello with any other version
/// closes the connection.
pub const PROTOCOL_VERSION: u32 = 1;

/// Who is at the other end of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcRole {
    /// Hook, proxy or shim asking for a verdict.
    Client,
    /// Approval UI that receives requests and live events.
    Ui,
}

impl IpcRole {
    pub fn as_str(self) -> &'static str {
        match self {
            IpcRole::Client => "client",
            IpcRole::Ui => "ui",
        }
    }
}

/// One JSON-lines message on the daemon socket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcMessage {
    Hello {
        role: IpcRole,
        version: u32,
    },
    ApprovalRequest {
        id: String,
        action_summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
        severity: Severity,
        risk: RiskScore,
        reason_user: String,
        agent: AgentContext,
    },
    ApprovalResponse {
        id: String,
        verdict: ApprovalVerdict,
        by: String,
    },
    Subscribe,
    Event {
        decision: DecisionEvent,
    },
    Ping,
}

impl IpcMessage {
    pub fn hello(role: IpcRole) -> Self {
        IpcMessage::Hello {
            role,
            version: PROTOCOL_VERSION,
        }
    }

    pub fn from_request(request: ApprovalRequest) -> Self {
        IpcMessage::ApprovalRequest {
            id: request.id,
            action_summary: request.action_summary,
            rule: request.rule,
            severity: request.severity,
            risk: request.risk,
            reason_user: request.reason_user,
            agent: request.agent,
        }
    }

    pub fn from_response(response: ApprovalResponse) -> Self {
        IpcMessage::ApprovalResponse {
            id: response.id,
            verdict: response.verdict,
            by: response.by,
        }
    }

    pub fn as_request(&self) -> Option<ApprovalRequest> {
        match self {
            IpcMessage::ApprovalRequest {
                id,
                action_summary,
                rule,
                severity,
                risk,
                reason_user,
                agent,
            } => Some(ApprovalRequest {
                id: id.clone(),
                action_summary: action_summary.clone(),
                rule: rule.clone(),
                severity: *severity,
                risk: *risk,
                reason_user: reason_user.clone(),
                agent: agent.clone(),
            }),
            _ => None,
        }
    }

    pub fn as_response(&self) -> Option<ApprovalResponse> {
        match self {
            IpcMessage::ApprovalResponse { id, verdict, by } => Some(ApprovalResponse {
                id: id.clone(),
                verdict: *verdict,
                by: by.clone(),
            }),
            _ => None,
        }
    }
}

/// Live-feed payload for `event{decision}`.
///
/// Carries `agent`, `session`, `rule_id`, `decision`, and the remaining
/// decision details a subscriber needs to render a row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionEvent {
    pub agent: AgentKind,
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub decision: Outcome,
    pub severity: Severity,
    pub risk_score: RiskScore,
    pub reason_user: String,
    pub reason_agent: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_summary: Option<String>,
}

impl DecisionEvent {
    /// Build a live-feed event from an Ask that has just been answered.
    pub fn from_approval(request: &ApprovalRequest, verdict: ApprovalVerdict) -> Self {
        let decision = if verdict.is_allowed() {
            Outcome::Allow
        } else {
            Outcome::Deny
        };
        let reason_agent = match verdict {
            ApprovalVerdict::AllowOnce => {
                "Allowed once by the user via Privaku Agent Shield.".to_string()
            }
            ApprovalVerdict::AllowSession => {
                "Allowed for this session by the user via Privaku Agent Shield.".to_string()
            }
            ApprovalVerdict::AlwaysAllow => {
                "Always allowed by the user via Privaku Agent Shield.".to_string()
            }
            ApprovalVerdict::Deny => {
                "Denied by the user via Privaku Agent Shield; do not retry.".to_string()
            }
        };
        DecisionEvent {
            agent: request.agent.agent,
            session: request.agent.session_id.clone(),
            rule_id: request.rule.clone(),
            decision,
            severity: request.severity,
            risk_score: request.risk,
            reason_user: request.reason_user.clone(),
            reason_agent,
            matched_rule_ids: request.rule.iter().cloned().collect(),
            action_summary: Some(request.action_summary.clone()),
        }
    }
}

/// Encode one message as a single JSON line including the trailing newline.
pub fn encode_line(message: &IpcMessage) -> Result<String, serde_json::Error> {
    let mut line = serde_json::to_string(message)?;
    line.push('\n');
    Ok(line)
}

/// Decode one JSON line. Empty lines are rejected.
pub fn decode_line(line: &str) -> Result<IpcMessage, serde_json::Error> {
    serde_json::from_str(line.trim_end_matches(['\n', '\r']))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_request() -> ApprovalRequest {
        ApprovalRequest {
            id: "req-1".into(),
            action_summary: "echo hi".into(),
            rule: Some("demo.echo".into()),
            severity: Severity::Low,
            risk: RiskScore::MIN,
            reason_user: "ask".into(),
            agent: AgentContext {
                agent: AgentKind::Claude,
                session_id: "s1".into(),
                cwd: PathBuf::from("/tmp"),
                autonomous: false,
            },
        }
    }

    #[test]
    fn hello_round_trips() {
        let message = IpcMessage::hello(IpcRole::Client);
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["type"], "hello");
        assert_eq!(json["role"], "client");
        assert_eq!(json["version"], PROTOCOL_VERSION);
        let back: IpcMessage = serde_json::from_value(json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn request_converts_to_and_from_the_model() {
        let request = sample_request();
        let message = IpcMessage::from_request(request.clone());
        assert_eq!(message.as_request().unwrap(), request);
    }

    #[test]
    fn event_carries_attribution_fields() {
        let request = sample_request();
        let event = DecisionEvent::from_approval(&request, ApprovalVerdict::AllowOnce);
        assert_eq!(event.agent, AgentKind::Claude);
        assert_eq!(event.session, "s1");
        assert_eq!(event.rule_id.as_deref(), Some("demo.echo"));
        assert_eq!(event.decision, Outcome::Allow);
    }

    #[test]
    fn unknown_type_is_rejected() {
        let err = serde_json::from_str::<IpcMessage>(r#"{"type":"nope"}"#).unwrap_err();
        assert!(err.to_string().contains("unknown variant"), "{err}");
    }
}
