//! Log-only trial harness (amendment 002 item 4).
//!
//! Replays scripted agent sessions from 2–3 public repos through the engine.
//! Commands are not executed. Prints Ask / Deny / Allow counts.

use std::path::PathBuf;

use serde::Deserialize;
use shield_core::engine::Engine;
use shield_core::model::{Action, ActionKind, AgentContext, AgentKind, ArgvTree, Outcome};
use shield_core::paths::PathContext;
use shield_core::{policy, shell};

#[derive(Debug, Deserialize)]
struct Trial {
    sessions: Vec<Session>,
}

#[derive(Debug, Deserialize)]
struct Session {
    repo: String,
    name: String,
    commands: Vec<String>,
}

#[test]
fn log_only_trial_against_public_repo_sessions() {
    let trial: Trial = serde_yaml_ng::from_str(include_str!("../../../tests/trial/sessions.yaml"))
        .expect("tests/trial/sessions.yaml");
    assert!(
        trial.sessions.len() >= 2,
        "need traces from at least two public repos"
    );

    let policy = policy::load_embedded().unwrap();
    let engine = Engine::new(
        policy,
        PathContext::new("/home/tester", "/workspace/project"),
    )
    .unwrap();
    let context = AgentContext {
        agent: AgentKind::Claude,
        session_id: "trial".to_string(),
        cwd: PathBuf::from("/workspace/project"),
        autonomous: false,
    };

    let mut allow = 0usize;
    let mut ask = 0usize;
    let mut deny = 0usize;
    let mut asks = Vec::new();
    let mut denies = Vec::new();

    println!("trial (log-only; commands are not executed)");
    for session in &trial.sessions {
        println!("repo {} ({})", session.name, session.repo);
        for command in &session.commands {
            let (argv_tree, obfuscation) = match shell::parse(command) {
                Ok(tree) => (tree.to_argv_tree(), tree.obfuscation.to_vec()),
                Err(_) => (
                    ArgvTree::Unparsed {
                        raw: command.clone(),
                    },
                    Vec::new(),
                ),
            };
            let action = Action::new(
                context.clone(),
                ActionKind::Shell {
                    argv_tree,
                    raw: command.clone(),
                    cwd: context.cwd.clone(),
                    obfuscation,
                },
            );
            let decision = engine.evaluate(&action, &context);
            println!("  {:<8} {}", decision.outcome, command);
            match decision.outcome {
                Outcome::Allow => allow += 1,
                Outcome::Ask => {
                    ask += 1;
                    asks.push(format!("{}: {command}", session.name));
                }
                Outcome::Deny => {
                    deny += 1;
                    denies.push(format!("{}: {command}", session.name));
                }
            }
        }
    }

    let total = allow + ask + deny;
    println!();
    println!("trial totals: {total} commands, {deny} Deny, {ask} Ask, {allow} Allow");
    if !asks.is_empty() {
        println!("asks:\n  {}", asks.join("\n  "));
    }
    if !denies.is_empty() {
        println!("denies:\n  {}", denies.join("\n  "));
    }

    assert!(total >= 30, "trial should replay a full agent-session size");
    assert_eq!(
        deny, 0,
        "benign public-repo sessions must not Deny: {denies:?}"
    );
    let ask_pct = 100.0 * ask as f64 / total as f64;
    assert!(
        ask_pct <= 10.0,
        "trial Ask rate {ask_pct:.1}% exceeds 10% ({asks:?})"
    );
}
