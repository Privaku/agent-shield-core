use serde::{Deserialize, Serialize};

use super::{AgentContext, RiskScore, Severity};

/// What the hook, proxy or shim sends to the approval daemon when a decision
/// is `Ask`. The daemon forwards it unchanged to every connected UI.
///
/// Everything in here is shown to the user, so `action_summary` and
/// `reason_user` must already be redacted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    /// Unique request id, echoed back in the response.
    pub id: String,
    /// One-line, redacted description of the action (`cat ~/.ssh/id_rsa`).
    pub action_summary: String,
    /// Id of the rule that asked. Absent when the risk scorer escalated an
    /// otherwise allowed action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub severity: Severity,
    pub risk: RiskScore,
    /// Why the user is being asked, in plain words.
    pub reason_user: String,
    pub agent: AgentContext,
}

/// The human's answer. The first response for an `id` wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdict {
    /// Allow this one action.
    AllowOnce,
    /// Allow this action, rule and normalised command for the rest of the
    /// session.
    AllowSession,
    /// Allow and write a scoped user rule. Never offered for a `critical`
    /// deny.
    AlwaysAllow,
    /// Deny the action. Also the answer on timeout and when no UI is
    /// connected.
    Deny,
}

impl ApprovalVerdict {
    /// `true` when the verdict lets the action run.
    pub fn is_allowed(self) -> bool {
        !matches!(self, ApprovalVerdict::Deny)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResponse {
    /// The `id` of the request being answered.
    pub id: String,
    pub verdict: ApprovalVerdict,
    /// Who answered: a UI name (`cli`, `menubar`, `dialog`) or one of the
    /// fail-closed sources (`timeout`, `no_ui`).
    pub by: String,
}
