//! Layer 2 risk scoring and the Layer 3 explainer stub.
//!
//! [`FeatureScorer`] is the default, deterministic backend. Scores at or
//! above the policy `ask_threshold` escalate an Allow to an Ask and never
//! downgrade a Deny (or an Ask). [`Explainer`] is a post-MVP stub.

use crate::model::{Action, AgentContext, Decision, Outcome, RiskScore, Severity};

mod features;

pub use features::{FeatureHits, FeatureScorer, FeatureWeights, ScoreError, EMBEDDED_WEIGHTS};

/// Layer 2 backend. This core ships the deterministic `FeatureScorer`.
pub trait RiskScorer: Send + Sync {
    fn score(&self, action: &Action, context: &AgentContext) -> RiskScore;
}

/// Layer 3 local-LLM explainer (post-MVP). Optional, off by default, and
/// never on the critical path. This trait has no implementation and adds
/// no dependencies.
pub trait Explainer: Send + Sync {
    fn explain(&self, action: &Action, decision: &Decision) -> Option<String>;
}

/// Off-by-default Layer 3 stub. Always returns `None`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopExplainer;

impl Explainer for NoopExplainer {
    fn explain(&self, _action: &Action, _decision: &Decision) -> Option<String> {
        None
    }
}

/// Apply a Layer 2 score to a Layer 1 decision.
///
/// Deny and Ask are left as-is (aside from recording the score). Allow
/// becomes Ask when `score >= threshold`. `rule_id` is cleared on
/// escalation so the wire format matches unmatched/scorer Asks.
pub fn apply_score(
    mut decision: Decision,
    score: RiskScore,
    threshold: RiskScore,
    hits: Option<&FeatureHits>,
) -> Decision {
    decision.risk_score = score;
    if decision.outcome != Outcome::Allow || score.value() < threshold.value() {
        return decision;
    }
    decision.outcome = Outcome::Ask;
    decision.rule_id = None;
    if decision.severity < Severity::Medium {
        decision.severity = Severity::Medium;
    }
    decision.reason_user = escalation_reason_user(hits);
    decision.reason_agent = "Privaku Agent Shield is asking the user because this action looks risky. Wait for the answer; do not retry with a different host or tool.".to_string();
    decision
}

fn escalation_reason_user(hits: Option<&FeatureHits>) -> String {
    if let Some(hits) = hits {
        if hits.large_file_body && hits.unknown_host {
            return "No rule matched, but the risk scorer flagged a POST of a large file to an unknown host.".to_string();
        }
        let names = hits.fired_names();
        if !names.is_empty() {
            return format!(
                "No rule matched, but the risk scorer flagged this action ({}).",
                names.join(", ")
            );
        }
    }
    "No rule matched, but the risk scorer flagged this action.".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Decision;

    fn allow() -> Decision {
        Decision::allow_unmatched()
    }

    fn deny() -> Decision {
        Decision {
            outcome: Outcome::Deny,
            rule_id: Some("secrets.ssh_private_key".to_string()),
            matched_rule_ids: vec!["secrets.ssh_private_key".to_string()],
            severity: Severity::Critical,
            reason_user: "blocked".to_string(),
            reason_agent: "blocked".to_string(),
            risk_score: RiskScore::MIN,
        }
    }

    #[test]
    fn apply_score_escalates_allow_at_threshold() {
        let threshold = RiskScore::new(0.7).unwrap();
        let hits = FeatureHits {
            network_sink: true,
            unknown_host: true,
            large_file_body: true,
            ..FeatureHits::default()
        };
        let decided = apply_score(
            allow(),
            RiskScore::new(0.82).unwrap(),
            threshold,
            Some(&hits),
        );
        assert_eq!(decided.outcome, Outcome::Ask);
        assert!(decided.rule_id.is_none());
        assert_eq!(decided.severity, Severity::Medium);
        assert!((decided.risk_score.value() - 0.82).abs() < f64::EPSILON);
        assert!(decided.reason_user.contains("unknown host"));
    }

    #[test]
    fn apply_score_never_downgrades_deny() {
        let threshold = RiskScore::new(0.7).unwrap();
        let decided = apply_score(deny(), RiskScore::MAX, threshold, None);
        assert_eq!(decided.outcome, Outcome::Deny);
        assert_eq!(decided.rule_id.as_deref(), Some("secrets.ssh_private_key"));
        assert_eq!(decided.risk_score, RiskScore::MAX);
    }

    #[test]
    fn apply_score_does_not_escalate_below_threshold() {
        let threshold = RiskScore::new(0.7).unwrap();
        let decided = apply_score(allow(), RiskScore::new(0.05).unwrap(), threshold, None);
        assert_eq!(decided.outcome, Outcome::Allow);
        assert!((decided.risk_score.value() - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn noop_explainer_returns_none() {
        let explainer = NoopExplainer;
        assert!(explainer
            .explain(
                &Action::new(
                    AgentContext {
                        agent: crate::model::AgentKind::Claude,
                        session_id: "s".to_string(),
                        cwd: std::path::PathBuf::from("/w"),
                        autonomous: false,
                    },
                    crate::model::ActionKind::FileRead {
                        path: std::path::PathBuf::from("/w/a.rs"),
                    },
                ),
                &allow()
            )
            .is_none());
    }
}
