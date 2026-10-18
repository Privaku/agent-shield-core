//! Policy rule CLI operations.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use clap::ValueEnum;
use shield_core::policy::{self, Layer, Paths, Policy};

/// Exit code for an invalid or unreadable policy. Usage errors are clap's 2.
const EXIT_INVALID: u8 = 1;

/// `--as` values for `rules validate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LayerArg {
    /// Validate as `rules/default.yaml` itself (no overlay rules apply).
    Embedded,
    /// Validate as ~/.config/privaku/agent-shield/policy.yaml.
    User,
    /// Validate as a project `.agent-shield.yaml`.
    Project,
}

impl From<LayerArg> for Layer {
    fn from(arg: LayerArg) -> Self {
        match arg {
            LayerArg::Embedded => Layer::Embedded,
            LayerArg::User => Layer::User,
            LayerArg::Project => Layer::Project,
        }
    }
}

/// Layer to assume for a file when `--as` is not given: a file named like
/// the project policy is a project file, anything else is a user file.
fn infer_layer(file: &Path) -> Layer {
    match file.file_name().and_then(|n| n.to_str()) {
        Some(name) if name == Paths::PROJECT_POLICY_FILE => Layer::Project,
        _ => Layer::User,
    }
}

pub fn list(json: bool) -> ExitCode {
    let policy = match policy::load(&Paths::from_env()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!("The policy did not load; every action is denied until this is fixed.");
            return ExitCode::from(EXIT_INVALID);
        }
    };
    if json {
        match serde_json::to_string_pretty(&policy) {
            Ok(text) => println!("{text}"),
            Err(err) => {
                eprintln!("error: cannot serialise policy: {err}");
                return ExitCode::from(EXIT_INVALID);
            }
        }
    } else {
        print!("{}", render(&policy));
    }
    ExitCode::SUCCESS
}

pub fn validate(file: &Path, layer: Option<LayerArg>) -> ExitCode {
    let layer = layer.map_or_else(|| infer_layer(file), Layer::from);
    match policy::validate_path(&Paths::from_env(), file, layer) {
        Ok(policy) => {
            let own = policy.sources.last().map_or(0, |s| s.rule_count);
            let how = match layer {
                Layer::Embedded => "as the embedded default".to_string(),
                Layer::User => "as the user policy over the embedded default".to_string(),
                Layer::Project => format!(
                    "as a project policy over {}",
                    if policy.sources.iter().any(|s| s.layer == Layer::User) {
                        "the embedded default and the user policy"
                    } else {
                        "the embedded default (no user policy found)"
                    }
                ),
            };
            println!(
                "OK: {} is valid ({own} {} in file, {} enabled after merge, validated {how})",
                file.display(),
                plural(own, "rule"),
                policy.rules.len(),
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(EXIT_INVALID)
        }
    }
}

/// Write the embedded default policy reference to `docs/RULES.md`.
pub fn docs() -> ExitCode {
    let policy = match policy::load_embedded() {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(EXIT_INVALID);
        }
    };
    let path = Path::new("docs/RULES.md");
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!("error: cannot create {}: {err}", parent.display());
            return ExitCode::from(EXIT_INVALID);
        }
    }
    if let Err(err) = fs::write(path, render_docs(&policy)) {
        eprintln!("error: cannot write {}: {err}", path.display());
        return ExitCode::from(EXIT_INVALID);
    }
    println!("Wrote {} ({} rules)", path.display(), policy.rules.len());
    ExitCode::SUCCESS
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

fn render_docs(policy: &Policy) -> String {
    let mut out = String::from(
        "# Agent Shield Default Rules\n\n\
         This reference is generated from `rules/default.yaml`. Run \
         `agent-shield rules docs` after changing the default policy.\n\n",
    );
    out.push_str("## Defaults\n\n");
    out.push_str("| Setting | Value |\n|---|---|\n");
    let defaults = &policy.defaults;
    out.push_str(&format!(
        "| Unmatched action | `{}` |\n",
        defaults.unmatched
    ));
    out.push_str(&format!(
        "| Ask timeout | `{}` seconds |\n",
        defaults.ask_timeout_seconds
    ));
    out.push_str(&format!("| On timeout | `{}` |\n", defaults.on_timeout));
    out.push_str(&format!("| No UI | `{}` |\n", defaults.on_no_ui));
    out.push_str(&format!(
        "| Ask threshold | `{}` |\n\n",
        defaults.ask_threshold
    ));
    out.push_str("## Rule summary\n\n");
    out.push_str("| Rule | Severity | Decision | Description |\n|---|---|---|---|\n");
    for policy_rule in &policy.rules {
        let rule = &policy_rule.rule;
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} |\n",
            rule.id,
            rule.severity,
            rule.decision,
            rule.description
                .as_deref()
                .unwrap_or("")
                .replace('|', "\\|")
        ));
    }
    for policy_rule in &policy.rules {
        let rule = &policy_rule.rule;
        out.push_str(&format!("\n## `{}`\n\n", rule.id));
        if let Some(description) = &rule.description {
            out.push_str(description);
            out.push_str("\n\n");
        }
        out.push_str(&format!(
            "- Severity: `{}`\n- Decision: `{}`\n\n",
            rule.severity, rule.decision
        ));
        out.push_str("Match:\n\n```json\n");
        out.push_str(
            &serde_json::to_string_pretty(&rule.matcher).expect("policy matchers always serialize"),
        );
        out.push_str("\n```\n\nAgent guidance:\n\n> ");
        out.push_str(
            &rule
                .agent_message
                .as_deref()
                .unwrap_or("Follow the policy decision and ask the user before retrying.")
                .trim()
                .replace('\n', "\n> "),
        );
        out.push('\n');
    }
    out
}

/// Human-readable table of the merged policy.
fn render(policy: &Policy) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Policy v{}: {} {} enabled, {} disabled\n",
        policy.version,
        policy.rules.len(),
        plural(policy.rules.len(), "rule"),
        policy.disabled.len()
    ));
    out.push_str("Sources (later layers override earlier ones):\n");
    for source in &policy.sources {
        out.push_str(&format!(
            "  {:<9} {}  ({} {})\n",
            source.layer.as_str(),
            source.name,
            source.rule_count,
            plural(source.rule_count, "rule")
        ));
    }
    let d = &policy.defaults;
    out.push_str(&format!(
        "Defaults: unmatched={} ask_timeout_seconds={} on_timeout={} on_no_ui={} ask_threshold={}\n\n",
        d.unmatched, d.ask_timeout_seconds, d.on_timeout, d.on_no_ui, d.ask_threshold
    ));

    let id_w = policy
        .rules
        .iter()
        .map(|r| r.rule.id.len())
        .chain(std::iter::once(2))
        .max()
        .unwrap_or(2);
    out.push_str(&format!(
        "{:<id_w$}  {:<8}  {:<8}  {:<8}  DESCRIPTION\n",
        "ID", "SEVERITY", "DECISION", "LAYER"
    ));
    for r in &policy.rules {
        out.push_str(&format!(
            "{:<id_w$}  {:<8}  {:<8}  {:<8}  {}\n",
            r.rule.id,
            r.rule.severity.as_str(),
            r.rule.decision.as_str(),
            r.layer.as_str(),
            r.rule.description.as_deref().unwrap_or("")
        ));
    }
    if !policy.disabled.is_empty() {
        out.push_str("\nDisabled:\n");
        for d in &policy.disabled {
            out.push_str(&format!(
                "  {}  (by {} file {})\n",
                d.id,
                d.layer.as_str(),
                d.source
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_is_inferred_from_the_file_name() {
        assert_eq!(
            infer_layer(Path::new("repo/.agent-shield.yaml")),
            Layer::Project
        );
        assert_eq!(infer_layer(Path::new(".agent-shield.yaml")), Layer::Project);
        assert_eq!(infer_layer(Path::new("policy.yaml")), Layer::User);
        assert_eq!(infer_layer(Path::new("/x/agent-shield.yaml")), Layer::User);
    }

    #[test]
    fn render_lists_every_enabled_rule() {
        let policy = policy::load_embedded().unwrap();
        let text = render(&policy);
        assert!(text.starts_with("Policy v1: "));
        for rule in &policy.rules {
            assert!(text.contains(&rule.rule.id), "{text}");
        }
        assert!(text.contains("ask_threshold=0.70"), "{text}");
        assert!(!text.contains("Disabled:"));
    }

    #[test]
    fn committed_rules_documentation_is_current() {
        let policy = policy::load_embedded().unwrap();
        assert_eq!(
            render_docs(&policy),
            include_str!("../../../docs/RULES.md"),
            "run `cargo run -p agent-shield -- rules docs`"
        );
    }
}
