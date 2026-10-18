use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// What happens to an action. Ordered from most to least permissive so that
/// `max` picks the stricter outcome: `Allow < Ask < Deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Let the action through.
    Allow,
    /// Route the action to a human; no answer means deny.
    Ask,
    /// Block the action.
    Deny,
}

impl Outcome {
    /// Precedence helper: `Deny > Ask > Allow`.
    pub fn combine(self, other: Outcome) -> Outcome {
        self.max(other)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Ask => "ask",
            Outcome::Deny => "deny",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How bad it is when the matched rule is right. Ordered from least to most
/// severe. A `critical` deny can only be relaxed by editing the policy file
/// by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a risk score is outside `0.0..=1.0` or not a number.
#[derive(Debug, Clone, Copy, PartialEq, Error)]
#[error("risk score must be a finite number in 0.0..=1.0, got {0}")]
pub struct RiskScoreError(pub f64);

/// Layer 2 risk estimate in `0.0..=1.0`. Scores at or above the policy's
/// `ask_threshold` escalate an Allow to an Ask; they never downgrade.
///
/// The range is checked on construction and on deserialisation, so a
/// malformed score is rejected rather than silently clamped.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RiskScore(f64);

impl RiskScore {
    pub const MIN: RiskScore = RiskScore(0.0);
    pub const MAX: RiskScore = RiskScore(1.0);

    pub fn new(value: f64) -> Result<Self, RiskScoreError> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(RiskScore(value))
        } else {
            Err(RiskScoreError(value))
        }
    }

    /// Build a score from an unchecked estimate, pulling it into range. `NaN`
    /// becomes the maximum score, because an unknown risk must fail closed.
    pub fn clamped(value: f64) -> Self {
        if value.is_nan() {
            RiskScore::MAX
        } else {
            RiskScore(value.clamp(0.0, 1.0))
        }
    }

    pub fn value(self) -> f64 {
        self.0
    }
}

impl Default for RiskScore {
    fn default() -> Self {
        RiskScore::MIN
    }
}

impl<'de> Deserialize<'de> for RiskScore {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = f64::deserialize(deserializer)?;
        RiskScore::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for RiskScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

/// The policy engine's answer for one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub outcome: Outcome,
    /// Id of the rule that produced this decision. Absent for unmatched
    /// actions and for escalations by the risk scorer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Every matching rule id in policy order, including rules that lost
    /// precedence resolution. Empty for unmatched and parser-error decisions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rule_ids: Vec<String>,
    pub severity: Severity,
    /// One line for the human approving or reviewing the action.
    pub reason_user: String,
    /// Message returned to the agent. Written so the agent re-plans instead
    /// of retrying the same action.
    pub reason_agent: String,
    pub risk_score: RiskScore,
}

impl Decision {
    /// Decision for an action no rule matched: allowed, lowest severity,
    /// zero risk until the scorer says otherwise.
    pub fn allow_unmatched() -> Self {
        Decision {
            outcome: Outcome::Allow,
            rule_id: None,
            matched_rule_ids: Vec::new(),
            severity: Severity::Info,
            reason_user: "No rule matched".to_string(),
            reason_agent: "Allowed by Privaku Agent Shield.".to_string(),
            risk_score: RiskScore::MIN,
        }
    }

    /// Strictness ordering used by [`combine`]: outcome first, then severity,
    /// then risk score.
    fn strictness(&self) -> (Outcome, Severity, RiskScore) {
        (self.outcome, self.severity, self.risk_score)
    }
}

/// Pick the decision that wins under `Deny > Ask > Allow`.
///
/// When both decisions have the same outcome, the higher severity wins, then
/// the higher risk score. When they are still tied, `a` is kept, so callers
/// that fold rules in policy order get the first matching rule.
pub fn combine(a: Decision, b: Decision) -> Decision {
    match a.strictness().partial_cmp(&b.strictness()) {
        Some(Ordering::Less) => b,
        _ => a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(outcome: Outcome, severity: Severity, risk: f64, rule_id: &str) -> Decision {
        Decision {
            outcome,
            rule_id: Some(rule_id.to_string()),
            matched_rule_ids: vec![rule_id.to_string()],
            severity,
            reason_user: format!("{rule_id} for user"),
            reason_agent: format!("{rule_id} for agent"),
            risk_score: RiskScore::new(risk).unwrap(),
        }
    }

    #[test]
    fn outcome_precedence_is_deny_ask_allow() {
        use Outcome::*;
        assert_eq!(Allow.combine(Allow), Allow);
        assert_eq!(Allow.combine(Ask), Ask);
        assert_eq!(Ask.combine(Allow), Ask);
        assert_eq!(Allow.combine(Deny), Deny);
        assert_eq!(Deny.combine(Allow), Deny);
        assert_eq!(Ask.combine(Deny), Deny);
        assert_eq!(Deny.combine(Ask), Deny);
        assert_eq!(Ask.combine(Ask), Ask);
        assert_eq!(Deny.combine(Deny), Deny);
        assert!(Allow < Ask && Ask < Deny);
    }

    #[test]
    fn outcome_combine_is_commutative_and_associative() {
        use Outcome::*;
        let all = [Allow, Ask, Deny];
        for &a in &all {
            for &b in &all {
                assert_eq!(a.combine(b), b.combine(a));
                for &c in &all {
                    assert_eq!(a.combine(b).combine(c), a.combine(b.combine(c)));
                }
            }
        }
    }

    #[test]
    fn combine_prefers_deny_over_ask_over_allow() {
        let allow = decision(Outcome::Allow, Severity::Critical, 1.0, "allow");
        let ask = decision(Outcome::Ask, Severity::Low, 0.1, "ask");
        let deny = decision(Outcome::Deny, Severity::Info, 0.0, "deny");

        assert_eq!(
            combine(allow.clone(), ask.clone()).rule_id.as_deref(),
            Some("ask")
        );
        assert_eq!(
            combine(ask.clone(), allow.clone()).rule_id.as_deref(),
            Some("ask")
        );
        assert_eq!(
            combine(allow.clone(), deny.clone()).rule_id.as_deref(),
            Some("deny")
        );
        assert_eq!(
            combine(deny.clone(), allow).rule_id.as_deref(),
            Some("deny")
        );
        assert_eq!(
            combine(ask.clone(), deny.clone()).rule_id.as_deref(),
            Some("deny")
        );
        assert_eq!(combine(deny, ask).rule_id.as_deref(), Some("deny"));
    }

    #[test]
    fn combine_breaks_ties_on_severity_then_risk() {
        let high = decision(Outcome::Deny, Severity::High, 0.2, "high");
        let critical = decision(Outcome::Deny, Severity::Critical, 0.1, "critical");
        assert_eq!(
            combine(high.clone(), critical.clone()).rule_id.as_deref(),
            Some("critical")
        );
        assert_eq!(combine(critical, high).rule_id.as_deref(), Some("critical"));

        let risky = decision(Outcome::Ask, Severity::High, 0.9, "risky");
        let calm = decision(Outcome::Ask, Severity::High, 0.3, "calm");
        assert_eq!(
            combine(calm.clone(), risky.clone()).rule_id.as_deref(),
            Some("risky")
        );
        assert_eq!(combine(risky, calm).rule_id.as_deref(), Some("risky"));
    }

    #[test]
    fn combine_keeps_first_on_full_tie() {
        let first = decision(Outcome::Ask, Severity::Medium, 0.5, "first");
        let second = decision(Outcome::Ask, Severity::Medium, 0.5, "second");
        assert_eq!(combine(first, second).rule_id.as_deref(), Some("first"));
    }

    #[test]
    fn combine_never_downgrades_a_deny() {
        let deny = decision(Outcome::Deny, Severity::Critical, 0.0, "deny");
        let unmatched = Decision::allow_unmatched();
        assert_eq!(
            combine(deny.clone(), unmatched.clone()).outcome,
            Outcome::Deny
        );
        assert_eq!(combine(unmatched, deny).outcome, Outcome::Deny);
    }

    #[test]
    fn risk_score_rejects_out_of_range_and_nan() {
        assert!(RiskScore::new(0.0).is_ok());
        assert!(RiskScore::new(1.0).is_ok());
        assert!(RiskScore::new(0.7).is_ok());
        assert_eq!(RiskScore::new(-0.1), Err(RiskScoreError(-0.1)));
        assert_eq!(RiskScore::new(1.1), Err(RiskScoreError(1.1)));
        assert!(RiskScore::new(f64::NAN).is_err());
        assert!(RiskScore::new(f64::INFINITY).is_err());
    }

    #[test]
    fn risk_score_clamped_fails_closed_on_nan() {
        assert_eq!(RiskScore::clamped(f64::NAN), RiskScore::MAX);
        assert_eq!(RiskScore::clamped(7.0), RiskScore::MAX);
        assert_eq!(RiskScore::clamped(-7.0), RiskScore::MIN);
        assert_eq!(RiskScore::clamped(0.25).value(), 0.25);
    }

    #[test]
    fn risk_score_deserialisation_rejects_out_of_range() {
        assert_eq!(
            serde_json::from_str::<RiskScore>("0.5").unwrap().value(),
            0.5
        );
        assert_eq!(
            serde_json::from_str::<RiskScore>("1").unwrap(),
            RiskScore::MAX
        );
        assert!(serde_json::from_str::<RiskScore>("1.5").is_err());
        assert!(serde_json::from_str::<RiskScore>("-1").is_err());
        assert!(serde_json::from_str::<RiskScore>("\"0.5\"").is_err());
    }

    #[test]
    fn wire_names_are_snake_case() {
        assert_eq!(serde_json::to_string(&Outcome::Allow).unwrap(), "\"allow\"");
        assert_eq!(serde_json::to_string(&Outcome::Ask).unwrap(), "\"ask\"");
        assert_eq!(serde_json::to_string(&Outcome::Deny).unwrap(), "\"deny\"");
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert!(serde_json::from_str::<Outcome>("\"Allow\"").is_err());
        assert!(serde_json::from_str::<Severity>("\"CRITICAL\"").is_err());
    }

    #[test]
    fn decision_omits_absent_rule_id_and_rejects_unknown_fields() {
        let json = serde_json::to_value(Decision::allow_unmatched()).unwrap();
        assert!(json.get("rule_id").is_none());
        assert_eq!(json["outcome"], "allow");
        assert_eq!(json["severity"], "info");
        assert_eq!(json["risk_score"], 0.0);

        let mut with_extra = json.clone();
        with_extra["surprise"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<Decision>(with_extra).is_err());
    }
}
