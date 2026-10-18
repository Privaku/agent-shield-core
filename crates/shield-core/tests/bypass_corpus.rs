//! Adversarial bypass suite (amendment 002 item 2).
//!
//! Prints caught vs missed. Unexpected Allows fail the test. Remaining
//! documented misses (`known_miss: true`) are listed and must appear in
//! README known limitations.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use serde::Deserialize;
use shield_core::engine::Engine;
use shield_core::model::{Action, ActionKind, AgentContext, AgentKind, ArgvTree, Outcome};
use shield_core::paths::PathContext;
use shield_core::{policy, shell};

#[derive(Debug, Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    category: String,
    command: String,
    expected: Outcome,
    #[serde(default)]
    known_miss: bool,
    #[serde(default)]
    setup: Option<String>,
}

struct Counts {
    caught: usize,
    missed: usize,
    documented: usize,
}

fn load() -> Corpus {
    serde_yaml_ng::from_str(include_str!("../../../tests/corpus/bypass.yaml"))
        .expect("bypass.yaml must parse")
}

fn shell_action(raw: &str, cwd: &Path) -> Action {
    let context = AgentContext {
        agent: AgentKind::Claude,
        session_id: "bypass".to_string(),
        cwd: cwd.to_path_buf(),
        autonomous: false,
    };
    let (argv_tree, obfuscation) = match shell::parse(raw) {
        Ok(tree) => (tree.to_argv_tree(), tree.obfuscation.to_vec()),
        Err(_) => (
            ArgvTree::Unparsed {
                raw: raw.to_string(),
            },
            Vec::new(),
        ),
    };
    Action::new(
        context,
        ActionKind::Shell {
            argv_tree,
            raw: raw.to_string(),
            cwd: cwd.to_path_buf(),
            obfuscation,
        },
    )
}

fn apply_setup(setup: Option<&str>, home: &Path, cwd: &Path) {
    match setup {
        Some("symlink-ssh") => {
            let link_dir = cwd.join("linked-keys");
            fs::create_dir_all(&link_dir).unwrap();
            let _ = fs::remove_file(link_dir.join("id_rsa"));
            symlink(home.join(".ssh/id_rsa"), link_dir.join("id_rsa")).unwrap();
        }
        Some("python-steal") | Some("python-file-home") => {
            fs::write(
                cwd.join("steal.py"),
                format!("open('{}/.ssh/id_rsa').read()\n", home.display()),
            )
            .unwrap();
        }
        Some(other) => panic!("unknown bypass setup {other}"),
        None => {}
    }
}

#[test]
fn bypass_corpus_reports_caught_versus_missed() {
    let corpus = load();
    assert!(
        corpus.cases.len() >= 20,
        "bypass corpus must cover the amendment 002 categories"
    );

    // Keep the tree under /tmp so macOS /var/folders random components are not
    // copied into commands (they trip secrets.content_in_args).
    let temp = tempfile::Builder::new()
        .prefix("as-bypass-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = temp.path().join("home");
    let cwd = temp.path().join("work");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(home.join(".ssh/id_rsa"), "CANARY-DO-NOT-USE\n").unwrap();
    fs::write(home.join(".ssh/id_ed25519"), "CANARY-DO-NOT-USE\n").unwrap();

    let policy = policy::load_embedded().expect("embedded policy");
    let engine = Engine::new(policy, PathContext::new(&home, &cwd)).unwrap();

    let mut counts = Counts {
        caught: 0,
        missed: 0,
        documented: 0,
    };
    let mut by_category: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut unexpected = Vec::new();
    let mut documented_misses = Vec::new();

    println!("bypass id                              cat            expected  got     status");
    for case in &corpus.cases {
        apply_setup(case.setup.as_deref(), &home, &cwd);
        let command = case
            .command
            .replace("/home/tester", &home.to_string_lossy())
            .replace("$HOME", &home.to_string_lossy());
        let action = shell_action(&command, &cwd);
        let decision = engine.evaluate(&action, &action.context);
        let protected = matches!(decision.outcome, Outcome::Deny | Outcome::Ask);
        let entry = by_category.entry(case.category.clone()).or_insert((0, 0));
        if protected {
            counts.caught += 1;
            entry.0 += 1;
        } else {
            counts.missed += 1;
            entry.1 += 1;
        }

        let status = if case.known_miss {
            assert_eq!(
                case.expected,
                Outcome::Allow,
                "{} known_miss must expect allow",
                case.id
            );
            assert_eq!(
                decision.outcome,
                Outcome::Allow,
                "{} marked known_miss but was caught as {}",
                case.id,
                decision.outcome
            );
            counts.documented += 1;
            documented_misses.push(case.id.clone());
            "DOCUMENTED_MISS"
        } else if decision.outcome == case.expected {
            "caught"
        } else if case.expected != Outcome::Allow && decision.outcome == Outcome::Allow {
            unexpected.push(format!(
                "{} expected {} got Allow ({:?})",
                case.id, case.expected, decision.matched_rule_ids
            ));
            "UNEXPECTED_MISS"
        } else if decision.outcome != case.expected {
            unexpected.push(format!(
                "{} expected {} got {} ({:?})",
                case.id, case.expected, decision.outcome, decision.matched_rule_ids
            ));
            "MISMATCH"
        } else {
            "caught"
        };

        println!(
            "{:<36} {:<14} {:<9} {:<7} {status}",
            case.id, case.category, case.expected, decision.outcome
        );
    }

    println!();
    println!("category        caught  missed");
    for (category, (caught, missed)) in &by_category {
        println!("{category:<15} {caught:>6}  {missed:>6}");
    }
    println!();
    println!(
        "bypass totals: {} cases, {} caught, {} missed ({} documented)",
        corpus.cases.len(),
        counts.caught,
        counts.missed,
        counts.documented
    );
    if !documented_misses.is_empty() {
        println!("documented misses: {}", documented_misses.join(", "));
    }

    assert!(
        unexpected.is_empty(),
        "unexpected bypass results:\n{}",
        unexpected.join("\n")
    );
}
