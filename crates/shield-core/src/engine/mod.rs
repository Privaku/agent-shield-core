//! Policy matching and decision resolution.
//!
//! Every matching rule is retained in [`Decision::matched_rule_ids`].
//! Resolution normally follows `Deny > Ask > Allow`, then severity, then
//! policy order. A matching `allow` from the user layer is the one exemption:
//! when it has a strictly higher specificity score than every matching Ask,
//! it settles those Asks. Specificity counts populated matcher constraints
//! and rewards exact globs over wildcard globs, so an M15 `always_allow`
//! rule can add agent/path/argument scope and be recognizably narrower.
//! No Allow rule ever downgrades a Deny; critical Denies therefore remain
//! absolute unless the user explicitly redefines them during policy loading.

mod matcher;
mod scripts;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::path::PathBuf;

use thiserror::Error;

use std::sync::Arc;

use crate::model::{Action, AgentContext, Decision, Outcome, RiskScore, Severity};
use crate::paths::{PathContext, SensitivePathCatalog};
use crate::policy::{Layer, Match, Policy, PolicyRule};
use crate::score::{self, FeatureScorer, RiskScorer, ScoreError};

use matcher::{matches_rule, validate_globs, ActionFacts};

pub use scripts::{MAX_SCAN_DEPTH, MAX_SCRIPT_BYTES};

/// A policy or embedded-catalog problem found while constructing an engine.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("rule `{rule_id}` cannot be compiled: {message}")]
    Rule { rule_id: String, message: String },
    #[error(transparent)]
    Catalog(#[from] crate::paths::CatalogError),
    #[error(transparent)]
    Weights(#[from] ScoreError),
}

/// A compiled policy evaluator for one home/cwd path context.
pub struct Engine {
    policy: Policy,
    path_context: PathContext,
    sensitive: crate::paths::CompiledSensitiveCatalog,
    scorer: FeatureScorer,
    extra_scorer: Option<Arc<dyn RiskScorer>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("policy", &self.policy)
            .field("path_context", &self.path_context)
            .field("has_extra_scorer", &self.extra_scorer.is_some())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Compile a merged policy. Invalid globs fail construction rather than
    /// silently creating rules that can never match.
    pub fn new(policy: Policy, path_context: PathContext) -> Result<Self, EngineError> {
        for policy_rule in &policy.rules {
            validate_globs(&policy_rule.rule.matcher, &path_context).map_err(|error| {
                EngineError::Rule {
                    rule_id: policy_rule.rule.id.clone(),
                    message: error.to_string(),
                }
            })?;
        }
        let sensitive =
            SensitivePathCatalog::embedded()?.compile(&path_context, cfg!(target_os = "macos"))?;
        Ok(Self {
            policy,
            path_context,
            sensitive,
            scorer: FeatureScorer::embedded()?,
            extra_scorer: None,
        })
    }

    /// Attach an extra Layer 2 backend (the optional ONNX scorer). The
    /// engine keeps the maximum of the feature score and this score.
    pub fn with_extra_scorer(mut self, scorer: Arc<dyn RiskScorer>) -> Self {
        self.extra_scorer = Some(scorer);
        self
    }

    /// Evaluate one action against every rule.
    ///
    /// Shell parse errors return Ask, never Allow. Runtime matcher errors
    /// return Deny. Policy-load and compilation failures occur before this
    /// method and callers must fail closed on [`EngineError`].
    ///
    /// Interpreter script files (and `-c`/`-e` bodies) are read and evaluated
    /// against the same policy. Unreadable or oversized files (over
    /// [`MAX_SCRIPT_BYTES`]) are Ask, never Allow.
    pub fn evaluate(&self, action: &Action, context: &AgentContext) -> Decision {
        let mut visited = HashSet::new();
        self.evaluate_with_scripts(action, context, 0, &mut visited)
    }

    fn evaluate_with_scripts(
        &self,
        action: &Action,
        context: &AgentContext,
        depth: usize,
        visited: &mut HashSet<PathBuf>,
    ) -> Decision {
        let base = self.evaluate_rules(action, context);
        if depth >= scripts::MAX_SCAN_DEPTH {
            return base;
        }
        match scripts::derived_actions(action, context, &self.path_context, visited) {
            Ok(extras) => {
                let had_network = extras
                    .iter()
                    .any(|extra| matches!(extra.kind, crate::model::ActionKind::Network { .. }));
                let mut decision = base;
                for extra in extras {
                    let inner = self.evaluate_with_scripts(&extra, context, depth + 1, visited);
                    decision = scripts::combine_keep_ids(decision, inner);
                }
                if had_network && decision.outcome == Outcome::Allow {
                    decision = scripts::combine_keep_ids(
                        decision,
                        script_scan_ask("Interpreter script contains an embedded network call"),
                    );
                }
                decision
            }
            Err(scripts::ScanError::Unreadable) => scripts::combine_keep_ids(
                base,
                script_scan_ask("Agent Shield could not read an interpreter script file"),
            ),
            Err(scripts::ScanError::Oversized { size }) => scripts::combine_keep_ids(
                base,
                script_scan_ask(format!(
                    "Interpreter script file is {size} bytes; the scan cap is {} bytes",
                    scripts::MAX_SCRIPT_BYTES
                )),
            ),
        }
    }

    fn evaluate_rules(&self, action: &Action, context: &AgentContext) -> Decision {
        let facts = match ActionFacts::new(action, context) {
            Ok(facts) => facts,
            Err(error) => return parse_error_decision(error.to_string()),
        };
        let mut matched = Vec::new();
        for rule in &self.policy.rules {
            match matches_rule(
                &rule.rule.matcher,
                &facts,
                &self.path_context,
                &self.sensitive,
            ) {
                Ok(true) => matched.push(rule),
                Ok(false) => {}
                Err(error) => return internal_error_decision(error.to_string()),
            }
        }
        let decision = if matched.is_empty() {
            default_decision(self.policy.defaults.unmatched)
        } else {
            resolve(matched)
        };
        self.apply_layer2(action, context, decision)
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    fn apply_layer2(
        &self,
        action: &Action,
        context: &AgentContext,
        decision: Decision,
    ) -> Decision {
        if matches!(
            decision.rule_id.as_deref(),
            Some("parse_error") | Some("matcher_error")
        ) {
            return decision;
        }
        let (hits, mut score) =
            self.scorer
                .evaluate(action, context, &self.path_context, &self.sensitive);
        if let Some(extra) = &self.extra_scorer {
            let other = extra.score(action, context);
            if other.value() > score.value() {
                score = other;
            }
        }
        score::apply_score(
            decision,
            score,
            self.policy.defaults.ask_threshold,
            Some(&hits),
        )
    }
}

fn resolve(matched: Vec<&PolicyRule>) -> Decision {
    let matched_ids: Vec<String> = matched.iter().map(|rule| rule.rule.id.clone()).collect();

    if let Some(winner) = best(
        matched
            .iter()
            .copied()
            .filter(|rule| rule.rule.decision == Outcome::Deny),
    ) {
        return rule_decision(winner, matched_ids);
    }

    let asks: Vec<_> = matched
        .iter()
        .copied()
        .filter(|rule| rule.rule.decision == Outcome::Ask)
        .collect();
    if !asks.is_empty() {
        let ask_specificity = asks
            .iter()
            .map(|rule| specificity(&rule.rule.matcher))
            .max()
            .unwrap_or(0);
        let exemption = best(matched.iter().copied().filter(|rule| {
            rule.layer == Layer::User
                && rule.rule.decision == Outcome::Allow
                && specificity(&rule.rule.matcher) > ask_specificity
        }));
        if let Some(winner) = exemption {
            return rule_decision(winner, matched_ids);
        }
        return rule_decision(best(asks).expect("asks is non-empty"), matched_ids);
    }

    rule_decision(best(matched).expect("matched is non-empty"), matched_ids)
}

fn best<'a>(rules: impl IntoIterator<Item = &'a PolicyRule>) -> Option<&'a PolicyRule> {
    rules.into_iter().max_by(|left, right| {
        let strictness =
            left.rule.severity.cmp(&right.rule.severity).then_with(|| {
                specificity(&left.rule.matcher).cmp(&specificity(&right.rule.matcher))
            });
        if strictness == Ordering::Equal {
            Ordering::Greater
        } else {
            strictness
        }
    })
}

fn rule_decision(rule: &PolicyRule, matched_rule_ids: Vec<String>) -> Decision {
    let reason_user = rule
        .rule
        .description
        .clone()
        .unwrap_or_else(|| format!("Matched policy rule {}", rule.rule.id));
    let reason_agent = rule.rule.agent_message.clone().unwrap_or_else(|| {
        format!(
            "{} by Privaku Agent Shield policy rule {}.",
            match rule.rule.decision {
                Outcome::Allow => "Allowed",
                Outcome::Ask => "Approval required",
                Outcome::Deny => "Blocked; do not retry this action",
            },
            rule.rule.id
        )
    });
    Decision {
        outcome: rule.rule.decision,
        rule_id: Some(rule.rule.id.clone()),
        matched_rule_ids,
        severity: rule.rule.severity,
        reason_user,
        reason_agent,
        risk_score: RiskScore::MIN,
    }
}

fn default_decision(outcome: Outcome) -> Decision {
    Decision {
        outcome,
        rule_id: None,
        matched_rule_ids: Vec::new(),
        severity: if outcome == Outcome::Allow {
            Severity::Info
        } else {
            Severity::Medium
        },
        reason_user: "No policy rule matched".to_string(),
        reason_agent: match outcome {
            Outcome::Allow => "Allowed by Privaku Agent Shield.".to_string(),
            Outcome::Ask => "Approval required by the default Agent Shield policy.".to_string(),
            Outcome::Deny => {
                "Blocked by the default Agent Shield policy; do not retry.".to_string()
            }
        },
        risk_score: RiskScore::MIN,
    }
}

fn script_scan_ask(detail: impl Into<String>) -> Decision {
    let detail = detail.into();
    Decision {
        outcome: Outcome::Ask,
        rule_id: Some("script_scan".to_string()),
        matched_rule_ids: vec!["script_scan".to_string()],
        severity: Severity::High,
        reason_user: detail,
        reason_agent:
            "Approval is required because Agent Shield could not safely inspect an interpreter script."
                .to_string(),
        risk_score: RiskScore::MAX,
    }
}

fn parse_error_decision(detail: String) -> Decision {
    Decision {
        outcome: Outcome::Ask,
        rule_id: Some("parse_error".to_string()),
        matched_rule_ids: Vec::new(),
        severity: Severity::High,
        reason_user: format!("Agent Shield could not safely evaluate the action: {detail}"),
        reason_agent:
            "Approval is required because Agent Shield could not safely parse this action."
                .to_string(),
        risk_score: RiskScore::MAX,
    }
}

fn internal_error_decision(detail: String) -> Decision {
    Decision {
        outcome: Outcome::Deny,
        rule_id: Some("matcher_error".to_string()),
        matched_rule_ids: Vec::new(),
        severity: Severity::Critical,
        reason_user: format!("Agent Shield could not safely evaluate the action: {detail}"),
        reason_agent:
            "Blocked because Agent Shield could not evaluate this action safely; do not retry."
                .to_string(),
        risk_score: RiskScore::MAX,
    }
}

fn specificity(matcher: &Match) -> usize {
    let mut score = 0;
    for patterns in [
        &matcher.program,
        &matcher.args_any,
        &matcher.args_all,
        &matcher.raw_any,
        &matcher.flags,
        &matcher.paths,
        &matcher.except_paths,
    ]
    .into_iter()
    .flatten()
    {
        score += 4 + patterns
            .iter()
            .map(|pattern| pattern_weight(pattern))
            .sum::<usize>();
    }
    score += usize::from(matcher.access.is_some()) * 4;
    score += usize::from(matcher.network_sink.is_some()) * 4;
    score += usize::from(matcher.secret_content.is_some()) * 4;
    score += usize::from(matcher.outside_workspace.is_some()) * 4;
    score += usize::from(matcher.dataflow.is_some()) * 8;
    score += usize::from(matcher.agent.is_some()) * 8;
    if let Some(mcp) = &matcher.mcp {
        score += 4;
        score += mcp.server.as_deref().map_or(0, pattern_weight);
        score += mcp.tool.as_deref().map_or(0, pattern_weight);
        score += usize::from(mcp.arg.is_some()) * 4;
    }
    if let Some(stages) = &matcher.pipeline {
        score += 8 + stages.iter().map(specificity).sum::<usize>();
    }
    if let Some(alternatives) = &matcher.any {
        score += 4 + alternatives.iter().map(specificity).max().unwrap_or(0);
    }
    score
}

fn pattern_weight(pattern: &str) -> usize {
    if pattern.contains(['*', '?', '[', ']']) {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_errors_ask_but_internal_matcher_errors_deny() {
        assert_eq!(
            parse_error_decision("bad shell".to_string()).outcome,
            Outcome::Ask
        );
        let internal = internal_error_decision("matcher failed".to_string());
        assert_eq!(internal.outcome, Outcome::Deny);
        assert_eq!(internal.rule_id.as_deref(), Some("matcher_error"));
        assert_eq!(internal.severity, Severity::Critical);
    }
}
