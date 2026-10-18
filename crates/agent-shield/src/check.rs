use std::path::{Path, PathBuf};
use std::process::ExitCode;

use shield_audit::{AuditWriter, PlatformPaths};
use shield_core::engine::Engine;
use shield_core::model::{
    Action, ActionKind, AgentContext, AgentKind, ArgvTree, Decision, Outcome, RiskScore, Severity,
};
use shield_core::paths::PathContext;
use shield_core::{policy, shell};

pub struct Options {
    pub shell: Option<String>,
    pub read: Option<String>,
    pub mcp: Option<Vec<String>>,
    pub cwd: Option<PathBuf>,
    pub agent: Option<AgentKind>,
    pub json: bool,
}

pub fn run(options: Options) -> ExitCode {
    let selected = usize::from(options.shell.is_some())
        + usize::from(options.read.is_some())
        + usize::from(options.mcp.is_some());
    if selected != 1 {
        eprintln!("error: specify exactly one of --shell, --read, or --mcp");
        return ExitCode::from(2);
    }

    let cwd = match &options.cwd {
        Some(cwd) => absolute_cwd(cwd.clone()),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    let default_agent = if options.mcp.is_some() {
        AgentKind::Mcp
    } else {
        AgentKind::Claude
    };
    let context = AgentContext {
        agent: options.agent.unwrap_or(default_agent),
        session_id: "check".to_string(),
        cwd: cwd.clone(),
        autonomous: false,
    };

    let action = match build_action(&options, &context, &cwd) {
        Ok(action) => action,
        Err(message) => return print_decision(&failure_decision(message), options.json),
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let paths = policy::Paths::new(home.as_deref(), Some(&cwd));
    let policy = match policy::load(&paths) {
        Ok(policy) => policy,
        Err(error) => {
            return audit_and_print(
                &action,
                failure_decision(format!("cannot load policy: {error}")),
                options.json,
            );
        }
    };
    let engine = match Engine::new(policy, PathContext::from_env(&cwd)) {
        Ok(engine) => engine,
        Err(error) => {
            return audit_and_print(
                &action,
                failure_decision(format!("cannot compile policy: {error}")),
                options.json,
            );
        }
    };
    audit_and_print(&action, engine.evaluate(&action, &context), options.json)
}

fn build_action(options: &Options, context: &AgentContext, cwd: &Path) -> Result<Action, String> {
    let kind = if let Some(raw) = &options.shell {
        let (argv_tree, obfuscation) = match shell::parse(raw) {
            Ok(tree) => (tree.to_argv_tree(), tree.obfuscation.to_vec()),
            Err(_) => (ArgvTree::Unparsed { raw: raw.clone() }, Vec::new()),
        };
        ActionKind::Shell {
            argv_tree,
            raw: raw.clone(),
            cwd: cwd.to_path_buf(),
            obfuscation,
        }
    } else if let Some(path) = &options.read {
        ActionKind::FileRead {
            path: PathBuf::from(path),
        }
    } else {
        let values = options.mcp.as_ref().expect("one action was selected");
        let args_json = serde_json::from_str(&values[2])
            .map_err(|error| format!("invalid MCP arguments JSON: {error}"))?;
        ActionKind::McpToolCall {
            server: values[0].clone(),
            tool: values[1].clone(),
            args_json,
        }
    };
    Ok(Action::new(context.clone(), kind))
}

fn absolute_cwd(cwd: PathBuf) -> PathBuf {
    if cwd.is_absolute() {
        cwd
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(cwd)
    }
}

fn failure_decision(message: String) -> Decision {
    Decision {
        outcome: Outcome::Deny,
        rule_id: Some("internal_error".to_string()),
        matched_rule_ids: Vec::new(),
        severity: Severity::Critical,
        reason_user: message,
        reason_agent:
            "Blocked because Agent Shield could not evaluate the action safely; do not retry."
                .to_string(),
        risk_score: RiskScore::MAX,
    }
}

fn audit_and_print(action: &Action, decision: Decision, json: bool) -> ExitCode {
    let approver = match decision.outcome {
        Outcome::Allow | Outcome::Deny => Some("policy"),
        Outcome::Ask => None,
    };
    let writer = match AuditWriter::new(&PlatformPaths::from_env()) {
        Ok(writer) => writer,
        Err(error) => {
            return print_decision(
                &failure_decision(format!("cannot initialize audit log: {error}")),
                json,
            );
        }
    };
    if let Err(error) = writer.append(action, &decision, approver) {
        return print_decision(
            &failure_decision(format!("cannot write audit log: {error}")),
            json,
        );
    }
    print_decision(&decision, json)
}

fn print_decision(decision: &Decision, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string(decision).expect("Decision is serializable")
        );
    } else {
        let rule = decision
            .rule_id
            .as_deref()
            .map_or(String::new(), |id| format!(" [{id}]"));
        println!(
            "{}{}: {}",
            decision.outcome.as_str().to_ascii_uppercase(),
            rule,
            decision.reason_user
        );
    }
    match decision.outcome {
        Outcome::Allow => ExitCode::SUCCESS,
        Outcome::Ask => ExitCode::from(10),
        Outcome::Deny => ExitCode::from(20),
    }
}
