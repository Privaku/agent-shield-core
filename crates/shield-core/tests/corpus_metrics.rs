use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;
use shield_core::engine::Engine;
use shield_core::model::{Action, ActionKind, AgentContext, AgentKind, Outcome, Severity};
use shield_core::paths::PathContext;
use shield_core::{policy, shell};

const HOME: &str = "/home/tester";
const WORKSPACE: &str = "/workspace/project";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    #[serde(default)]
    threat: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
    expected: Outcome,
    action: CorpusAction,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum CorpusAction {
    Shell {
        command: String,
    },
    FileRead {
        path: PathBuf,
    },
    FileWrite {
        path: PathBuf,
    },
    McpToolCall {
        server: String,
        tool: String,
        args: Value,
    },
}

#[derive(Debug, Default)]
struct Counts {
    allow: usize,
    ask: usize,
    deny: usize,
}

impl Counts {
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Allow => self.allow += 1,
            Outcome::Ask => self.ask += 1,
            Outcome::Deny => self.deny += 1,
        }
    }

    fn total(&self) -> usize {
        self.allow + self.ask + self.deny
    }

    fn protected_percent(&self) -> f64 {
        100.0 * (self.ask + self.deny) as f64 / self.total() as f64
    }

    fn ask_percent(&self) -> f64 {
        100.0 * self.ask as f64 / self.total() as f64
    }
}

fn load(text: &str) -> Corpus {
    serde_yaml_ng::from_str(text).expect("corpus YAML must parse")
}

fn context() -> AgentContext {
    AgentContext {
        agent: AgentKind::Claude,
        session_id: "corpus".to_string(),
        cwd: PathBuf::from(WORKSPACE),
        autonomous: false,
    }
}

fn action(case: &Case) -> Action {
    let context = context();
    let kind = match &case.action {
        CorpusAction::Shell { command } => {
            let parsed = shell::parse(command)
                .unwrap_or_else(|error| panic!("{} shell parse failed: {error}", case.id));
            ActionKind::Shell {
                argv_tree: parsed.to_argv_tree(),
                raw: command.clone(),
                cwd: PathBuf::from(WORKSPACE),
                obfuscation: parsed.obfuscation.to_vec(),
            }
        }
        CorpusAction::FileRead { path } => ActionKind::FileRead { path: path.clone() },
        CorpusAction::FileWrite { path } => ActionKind::FileWrite { path: path.clone() },
        CorpusAction::McpToolCall { server, tool, args } => ActionKind::McpToolCall {
            server: server.clone(),
            tool: tool.clone(),
            args_json: args.clone(),
        },
    };
    Action::new(context, kind)
}

#[test]
fn corpus_metrics() {
    let malicious = load(include_str!("../../../tests/corpus/malicious.yaml"));
    let benign = load(include_str!("../../../tests/corpus/benign.yaml"));
    assert!(malicious.cases.len() >= 150);
    assert!(benign.cases.len() >= 250);

    let policy = policy::load_embedded().expect("embedded policy must load");
    let rule_contracts: BTreeMap<_, _> = policy
        .rules
        .iter()
        .map(|rule| {
            (
                rule.rule.id.clone(),
                (rule.rule.severity, rule.rule.decision),
            )
        })
        .collect();
    let engine = Engine::new(
        policy,
        PathContext::new(PathBuf::from(HOME), PathBuf::from(WORKSPACE)),
    )
    .expect("embedded policy must compile");

    let mut malicious_counts = Counts::default();
    let mut critical_counts = Counts::default();
    let mut benign_counts = Counts::default();
    let mut covered = BTreeSet::new();
    let mut threats = BTreeSet::new();

    for case in &malicious.cases {
        let threat = case
            .threat
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing a threat tag", case.id));
        assert!(
            matches!(
                threat,
                "T1" | "T2"
                    | "T3"
                    | "T4"
                    | "T5"
                    | "T6"
                    | "T7"
                    | "T8"
                    | "T9"
                    | "T10"
                    | "T11"
                    | "T12"
            ),
            "{} has invalid threat tag {threat}",
            case.id
        );
        threats.insert(threat.to_string());
        let expected_rule = case
            .rule_id
            .as_deref()
            .unwrap_or_else(|| panic!("{} is missing rule_id", case.id));
        let decision = engine.evaluate(&action(case), &context());
        assert_eq!(
            decision.outcome, case.expected,
            "{} expected {} from {}, got {} from {:?}",
            case.id, case.expected, expected_rule, decision.outcome, decision.matched_rule_ids
        );
        assert!(
            decision
                .matched_rule_ids
                .iter()
                .any(|matched| matched == expected_rule),
            "{} expected rule {} to fire, got {:?}",
            case.id,
            expected_rule,
            decision.matched_rule_ids
        );
        covered.insert(expected_rule.to_string());
        malicious_counts.record(decision.outcome);
        if let Some((Severity::Critical, default_outcome)) = rule_contracts.get(expected_rule) {
            critical_counts.record(decision.outcome);
            if *default_outcome == Outcome::Deny {
                assert_eq!(
                    decision.outcome,
                    Outcome::Deny,
                    "{} covers critical Deny rule {} but did not deny",
                    case.id,
                    expected_rule
                );
            }
        }
    }

    for case in &benign.cases {
        assert!(
            case.threat.is_none(),
            "{} has an unexpected threat",
            case.id
        );
        assert!(
            case.rule_id.is_none(),
            "{} has an unexpected rule_id",
            case.id
        );
        let decision = engine.evaluate(&action(case), &context());
        assert_eq!(
            decision.outcome, case.expected,
            "{} expected {}, got {} from {:?}",
            case.id, case.expected, decision.outcome, decision.matched_rule_ids
        );
        benign_counts.record(decision.outcome);
    }

    let all_rules: BTreeSet<_> = rule_contracts.keys().cloned().collect();
    assert_eq!(
        covered, all_rules,
        "every default rule needs corpus coverage"
    );
    assert_eq!(
        threats.len(),
        12,
        "every threat T1-T12 needs corpus coverage"
    );
    assert!(malicious_counts.protected_percent() >= 98.0);
    assert_eq!(critical_counts.allow, 0, "critical detection must be 100%");
    assert_eq!(benign_counts.deny, 0, "benign corpus must have zero Deny");
    assert!(benign_counts.ask_percent() <= 3.0);

    println!("corpus       cases   deny    ask  allow   protected/ask");
    println!(
        "malicious    {:>5}  {:>5}  {:>5}  {:>5}  {:>9.2}% protected",
        malicious_counts.total(),
        malicious_counts.deny,
        malicious_counts.ask,
        malicious_counts.allow,
        malicious_counts.protected_percent()
    );
    println!(
        "critical     {:>5}  {:>5}  {:>5}  {:>5}  {:>9.2}% protected",
        critical_counts.total(),
        critical_counts.deny,
        critical_counts.ask,
        critical_counts.allow,
        critical_counts.protected_percent()
    );
    println!(
        "benign       {:>5}  {:>5}  {:>5}  {:>5}  {:>9.2}% ask",
        benign_counts.total(),
        benign_counts.deny,
        benign_counts.ask,
        benign_counts.allow,
        benign_counts.ask_percent()
    );
}
