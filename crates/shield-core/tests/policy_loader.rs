//! M3 acceptance: loading, validating and merging policy layers.

use std::path::Path;

use shield_core::model::{AgentKind, Outcome, Severity};
use shield_core::policy::{
    self, Access, Layer, Paths, Policy, PolicyError, PolicyErrorKind, Source, EMBEDDED_NAME,
};

const BASE: &str = r#"
version: 1
defaults:
  unmatched: allow
  ask_timeout_seconds: 30
  on_timeout: deny
  on_no_ui: deny
  ask_threshold: 0.7
rules:
  - id: secrets.ssh_private_key
    description: Reading or copying SSH private keys
    severity: critical
    decision: deny
    match:
      access: [read, copy, send]
      paths: ["~/.ssh/id_*", "~/.ssh/*.pem", "~/.ssh/*_key"]
      except_paths: ["~/.ssh/*.pub", "~/.ssh/known_hosts", "~/.ssh/config"]
    agent_message: Blocked.
  - id: exfil.upload_file
    description: Uploading any file
    severity: high
    decision: ask
    match:
      program: [curl, wget]
      args_any: ["-T", "-F", "--data-binary"]
  - id: priv.sudo
    severity: high
    decision: ask
    match:
      program: sudo
"#;

fn src(layer: Layer, name: &str, text: &str) -> Source {
    Source::new(layer, name, text)
}

fn load_layers(user: Option<&str>, project: Option<&str>) -> Result<Policy, PolicyError> {
    let mut sources = vec![src(Layer::Embedded, "base.yaml", BASE)];
    if let Some(u) = user {
        sources.push(src(Layer::User, "user.yaml", u));
    }
    if let Some(p) = project {
        sources.push(src(Layer::Project, "project.yaml", p));
    }
    policy::load_sources(&sources)
}

fn parse_as(layer: Layer, text: &str) -> Result<Policy, PolicyError> {
    match layer {
        Layer::Embedded => policy::load_sources(&[src(layer, "file.yaml", text)]),
        Layer::User => load_layers(Some(text), None),
        Layer::Project => load_layers(None, Some(text)),
    }
}

fn ids(policy: &Policy) -> Vec<&str> {
    policy.rules.iter().map(|r| r.rule.id.as_str()).collect()
}

fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
        .unwrap_or_else(|| panic!("{needle:?} not in text"))
}

// --- valid policies ---------------------------------------------------------

#[test]
fn embedded_default_loads_and_is_well_formed() {
    let policy = policy::load_embedded().expect("embedded default must load");
    assert_eq!(policy.version, 1);
    assert_eq!(policy.defaults.unmatched, Outcome::Allow);
    assert_eq!(policy.defaults.ask_timeout_seconds, 30);
    assert_eq!(policy.defaults.on_timeout, Outcome::Deny);
    assert_eq!(policy.defaults.on_no_ui, Outcome::Deny);
    assert_eq!(policy.defaults.ask_threshold.value(), 0.7);
    assert_eq!(policy.sources.len(), 1);
    assert_eq!(policy.sources[0].layer, Layer::Embedded);
    assert_eq!(policy.sources[0].name, EMBEDDED_NAME);

    let ssh = policy
        .rule("secrets.ssh_private_key")
        .expect("excerpt rule present");
    assert_eq!(ssh.layer, Layer::Embedded);
    assert!(ssh.rule.is_critical());
    assert_eq!(ssh.rule.decision, Outcome::Deny);
    assert_eq!(
        ssh.rule.matcher.access.as_deref(),
        Some(&[Access::Read, Access::Copy, Access::Send][..])
    );
    assert!(ssh
        .rule
        .agent_message
        .as_deref()
        .unwrap()
        .contains("Do not retry"));
    for rule in &policy.rules {
        assert!(
            rule.rule.agent_message.is_some(),
            "{} has no message",
            rule.rule.id
        );
    }
}

#[test]
fn valid_policy_parses_every_match_key() {
    let text = r#"
version: 1
rules:
  - id: full.match
    description: every key the M6 engine understands
    severity: medium
    decision: ask
    match:
      access: [read, write, delete, copy, send, exec]
      paths: ["~/.aws/**"]
      except_paths: ["~/.aws/cli/**"]
      program: [cat, cp]
      args_any: ["-r"]
      flags: ["--recursive"]
      pipeline:
        - { program: curl }
        - { program: [sh, bash] }
      dataflow: { source: secret_file, sink: network }
      network_sink: true
      secret_content: false
      mcp: { server: filesystem, tool: "read_*", arg: /path }
      agent: [claude, cursor, codex, mcp, shim]
    agent_message: Ask first.
"#;
    let policy = parse_as(Layer::Project, text).expect("valid policy");
    let rule = &policy.rule("full.match").unwrap().rule;
    let m = &rule.matcher;
    assert_eq!(rule.severity, Severity::Medium);
    assert_eq!(rule.decision, Outcome::Ask);
    assert_eq!(m.access.as_ref().unwrap().len(), 6);
    assert_eq!(
        m.program.as_deref(),
        Some(&["cat".to_string(), "cp".to_string()][..])
    );
    let stages = m.pipeline.as_ref().unwrap();
    assert_eq!(stages.len(), 2);
    assert_eq!(
        stages[0].program.as_deref(),
        Some(&["curl".to_string()][..])
    );
    assert_eq!(m.dataflow.as_ref().unwrap().sink, "network");
    assert_eq!(m.network_sink, Some(true));
    assert_eq!(m.secret_content, Some(false));
    assert_eq!(m.mcp.as_ref().unwrap().arg.as_deref(), Some("/path"));
    assert_eq!(m.agent.as_ref().unwrap()[0], AgentKind::Claude);
}

/// The published rules excerpt must parse as an embedded policy.
#[test]
fn plan_section_5_excerpt_parses_verbatim() {
    let plan = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/policy/plan-section-5.md");
    let plan = std::fs::read_to_string(&plan).expect("canonical plan is readable");
    let marker = "**YAML schema excerpt (`rules/default.yaml`):**";
    let after = &plan[plan.find(marker).expect("§5 excerpt heading") + marker.len()..];
    let start = after.find("```yaml\n").expect("yaml fence") + "```yaml\n".len();
    let excerpt = &after[start..start + after[start..].find("\n```").expect("closing fence")];

    let policy =
        policy::load_sources(&[src(Layer::Embedded, "plan-excerpt.yaml", excerpt)]).unwrap();
    assert_eq!(
        ids(&policy),
        ["secrets.ssh_private_key", "rce.pipe_to_shell"]
    );
    assert_eq!(policy.defaults.unmatched, Outcome::Allow);
    assert_eq!(policy.defaults.ask_timeout_seconds, 30);
    assert_eq!(policy.defaults.on_timeout, Outcome::Deny);
    assert_eq!(policy.defaults.on_no_ui, Outcome::Deny);
    assert_eq!(policy.defaults.ask_threshold.value(), 0.7);

    let ssh = &policy.rule("secrets.ssh_private_key").unwrap().rule;
    assert!(ssh.is_critical());
    assert_eq!(ssh.decision, Outcome::Deny);
    assert_eq!(ssh.matcher.except_paths.as_ref().unwrap().len(), 3);
    assert!(ssh
        .agent_message
        .as_deref()
        .unwrap()
        .contains("Do not retry"));

    let pipe = &policy.rule("rce.pipe_to_shell").unwrap().rule;
    assert!(pipe.description.is_none());
    assert_eq!(pipe.matcher.pipeline.as_ref().unwrap().len(), 2);
}

#[test]
fn minimal_overlay_only_needs_a_version() {
    let policy = parse_as(Layer::Project, "version: 1\n").unwrap();
    assert_eq!(
        ids(&policy),
        ["secrets.ssh_private_key", "exfil.upload_file", "priv.sudo"]
    );
    assert_eq!(policy.sources.len(), 2);
    assert_eq!(policy.sources[1].rule_count, 0);
}

// --- rejected files ---------------------------------------------------------

#[test]
fn duplicate_ids_are_rejected_with_both_lines() {
    let text = r#"
version: 1
rules:
  - id: dup.rule
    severity: low
    decision: ask
    match: { program: a }
  - id: other.rule
    severity: low
    decision: ask
    match: { program: b }
  - id: dup.rule
    severity: low
    decision: ask
    match: { program: c }
"#;
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::DuplicateId);
    assert_eq!(err.file, "project.yaml");
    assert_eq!(err.rule_id.as_deref(), Some("dup.rule"));
    assert_eq!(err.line, Some(12));
    assert!(err.message.contains("first defined at line 4"), "{err}");
    assert_eq!(
        err.to_string(),
        "project.yaml:12: rule `dup.rule`: duplicate rule id; first defined at line 4"
    );
}

#[test]
fn unknown_top_level_field_is_rejected_with_line() {
    let text = "version: 1\nrulez:\n  - id: x.y\n";
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.line, Some(2));
    assert_eq!(err.rule_id, None);
    assert!(err.message.contains("unknown field `rulez`"), "{err}");
}

#[test]
fn unknown_rule_field_is_rejected_with_line_and_rule_id() {
    let text = r#"
version: 1
rules:
  - id: ok.rule
    severity: low
    decision: ask
    match: { program: a }
  - id: typo.rule
    severity: low
    decision: ask
    match: { program: b }
    agent_mesage: oops
"#;
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.rule_id.as_deref(), Some("typo.rule"));
    assert_eq!(err.line, Some(line_of(text, "agent_mesage")));
    assert!(
        err.message.contains("unknown field `agent_mesage`"),
        "{err}"
    );
    assert!(
        !err.message.contains(" at line "),
        "location is rendered once: {err}"
    );
}

#[test]
fn unknown_match_and_defaults_fields_are_rejected() {
    let text = r#"
version: 1
rules:
  - id: typo.match
    severity: low
    decision: ask
    match:
      programs: [a]
"#;
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.rule_id.as_deref(), Some("typo.match"));
    assert_eq!(err.line, Some(line_of(text, "programs")));
    assert!(err.message.contains("unknown field `programs`"), "{err}");

    let text = "version: 1\ndefaults:\n  ask_timeout: 5\n";
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.line, Some(3));
    assert!(err.message.contains("unknown field `ask_timeout`"), "{err}");
}

#[test]
fn bad_decision_values_are_rejected() {
    for bad in ["block", "Deny", "ALLOW", "true", "1"] {
        let text = format!(
            "version: 1\nrules:\n  - id: bad.decision\n    severity: high\n    decision: {bad}\n    match: {{ program: a }}\n"
        );
        let err = parse_as(Layer::Project, &text).unwrap_err();
        assert_eq!(err.kind, PolicyErrorKind::Parse, "{bad}: {err}");
        assert_eq!(err.rule_id.as_deref(), Some("bad.decision"), "{bad}: {err}");
        assert_eq!(err.line, Some(5), "{bad}: {err}");
        assert!(
            err.message
                .contains("expected one of `allow`, `ask`, `deny`")
                || err.message.contains("decision"),
            "{bad}: {err}"
        );
    }
}

#[test]
fn bad_severity_and_missing_required_keys_are_rejected() {
    let text = "version: 1\nrules:\n  - id: bad.severity\n    severity: fatal\n    decision: deny\n    match: { program: a }\n";
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.rule_id.as_deref(), Some("bad.severity"));
    assert_eq!(err.line, Some(4));

    let text = "version: 1\nrules:\n  - id: no.match\n    severity: high\n    decision: deny\n";
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.rule_id.as_deref(), Some("no.match"));
    assert!(err.message.contains("missing field `match`"), "{err}");

    let text =
        "version: 1\nrules:\n  - severity: high\n    decision: deny\n    match: { program: a }\n";
    let err = parse_as(Layer::Project, text).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert!(err.message.contains("missing field `id`"), "{err}");

    let err = parse_as(Layer::Project, "rules: []\n").unwrap_err();
    assert!(err.message.contains("missing field `version`"), "{err}");
}

#[test]
fn malformed_yaml_and_wrong_types_are_rejected() {
    let err = parse_as(Layer::Project, "version: 1\nrules:\n  - id: [\n").unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert!(err.line.is_some(), "{err}");

    let err = parse_as(Layer::Project, "version: 1\nrules: 5\n").unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.line, Some(2));

    let err = parse_as(
        Layer::Project,
        "version: 1\ndefaults:\n  ask_threshold: 1.5\n",
    )
    .unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Parse);
    assert_eq!(err.line, Some(3));
    assert!(err.message.contains("0.0..=1.0"), "{err}");
}

#[test]
fn semantic_checks_reject_bad_versions_ids_and_matches() {
    let err = parse_as(Layer::Project, "version: 2\n").unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert_eq!(err.line, Some(1));
    assert!(
        err.message.contains("unsupported policy version 2"),
        "{err}"
    );

    let rule = |id: &str, m: &str| {
        format!("version: 1\nrules:\n  - id: {id}\n    severity: low\n    decision: ask\n    match: {m}\n")
    };

    let err = parse_as(Layer::Project, &rule("empty.match", "{}")).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert_eq!(err.rule_id.as_deref(), Some("empty.match"));
    assert_eq!(err.line, Some(3));
    assert!(err.message.contains("`match` is empty"), "{err}");

    let err = parse_as(Layer::Project, &rule("\"bad id\"", "{ program: a }")).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert_eq!(err.rule_id.as_deref(), Some("bad id"));

    let err = parse_as(Layer::Project, &rule("trailing.", "{ program: a }")).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);

    let err = parse_as(
        Layer::Project,
        &rule("only.except", "{ except_paths: [a] }"),
    )
    .unwrap_err();
    assert!(err.message.contains("except_paths` requires"), "{err}");

    let err = parse_as(Layer::Project, &rule("empty.list", "{ program: [] }")).unwrap_err();
    assert!(err.message.contains("must not be an empty list"), "{err}");

    let err = parse_as(
        Layer::Project,
        &rule("empty.stage", "{ pipeline: [{ program: a }, {}] }"),
    )
    .unwrap_err();
    assert!(
        err.message.contains("`match.pipeline[1]` is empty"),
        "{err}"
    );

    let err = parse_as(Layer::Project, &rule("bad.ptr", "{ mcp: { arg: path } }")).unwrap_err();
    assert!(err.message.contains("JSON pointer"), "{err}");
}

#[test]
fn fail_open_defaults_are_rejected() {
    for key in ["on_timeout", "on_no_ui"] {
        let text = format!("version: 1\ndefaults:\n  {key}: allow\n");
        let err = parse_as(Layer::User, &text).unwrap_err();
        assert_eq!(err.kind, PolicyErrorKind::Invalid);
        assert_eq!(err.line, Some(3));
        assert!(err.message.contains("would fail open"), "{err}");
    }
    let ok = parse_as(Layer::User, "version: 1\ndefaults:\n  on_timeout: ask\n").unwrap();
    assert_eq!(ok.defaults.on_timeout, Outcome::Ask);
}

// --- merge order ------------------------------------------------------------

#[test]
fn merge_overlays_defaults_in_order() {
    let user = "version: 1\ndefaults:\n  ask_threshold: 0.5\n  ask_timeout_seconds: 10\n";
    let project = "version: 1\ndefaults:\n  ask_timeout_seconds: 60\n";
    let policy = load_layers(Some(user), Some(project)).unwrap();
    assert_eq!(policy.defaults.ask_threshold.value(), 0.5);
    assert_eq!(policy.defaults.ask_timeout_seconds, 60);
    assert_eq!(policy.defaults.unmatched, Outcome::Allow);
    assert_eq!(policy.defaults.on_timeout, Outcome::Deny);
}

#[test]
fn merge_keeps_base_order_overrides_in_place_and_appends_additions() {
    let user = r#"
version: 1
rules:
  - id: user.added
    severity: low
    decision: ask
    match: { program: foo }
  - id: priv.sudo
    description: user says deny
    severity: high
    decision: deny
    match: { program: sudo }
"#;
    let project = r#"
version: 1
rules:
  - id: project.added
    severity: low
    decision: ask
    match: { program: bar }
  - id: user.added
    description: project tightens the user rule
    severity: high
    decision: deny
    match: { program: foo }
"#;
    let policy = load_layers(Some(user), Some(project)).unwrap();
    assert_eq!(
        ids(&policy),
        [
            "secrets.ssh_private_key",
            "exfil.upload_file",
            "priv.sudo",
            "user.added",
            "project.added"
        ]
    );
    let sudo = policy.rule("priv.sudo").unwrap();
    assert_eq!(sudo.layer, Layer::User);
    assert_eq!(sudo.source, "user.yaml");
    assert_eq!(sudo.rule.decision, Outcome::Deny);

    let added = policy.rule("user.added").unwrap();
    assert_eq!(added.layer, Layer::Project);
    assert_eq!(added.rule.decision, Outcome::Deny);
    assert_eq!(
        added.rule.description.as_deref(),
        Some("project tightens the user rule")
    );

    assert_eq!(
        policy.rule("exfil.upload_file").unwrap().layer,
        Layer::Embedded
    );
    assert_eq!(
        policy.sources.iter().map(|s| s.layer).collect::<Vec<_>>(),
        [Layer::Embedded, Layer::User, Layer::Project]
    );
}

#[test]
fn later_layer_wins_when_both_redefine_the_same_rule() {
    let user = "version: 1\nrules:\n  - id: exfil.upload_file\n    severity: high\n    decision: deny\n    match: { program: curl }\n";
    let project = "version: 1\nrules:\n  - id: exfil.upload_file\n    severity: medium\n    decision: ask\n    match: { program: curl }\n";
    let policy = load_layers(Some(user), Some(project)).unwrap();
    let rule = policy.rule("exfil.upload_file").unwrap();
    assert_eq!(rule.layer, Layer::Project);
    assert_eq!(rule.rule.severity, Severity::Medium);
    assert_eq!(rule.rule.decision, Outcome::Ask);
}

#[test]
fn disable_removes_non_critical_rules_from_any_layer() {
    let user = "version: 1\ndisable: [exfil.upload_file]\n";
    let project = "version: 1\ndisable:\n  - priv.sudo\n";
    let policy = load_layers(Some(user), Some(project)).unwrap();
    assert_eq!(ids(&policy), ["secrets.ssh_private_key"]);
    assert!(policy.is_disabled("exfil.upload_file"));
    assert!(policy.is_disabled("priv.sudo"));
    assert_eq!(policy.disabled[0].layer, Layer::User);
    assert_eq!(policy.disabled[1].layer, Layer::Project);
    assert_eq!(policy.disabled[1].source, "project.yaml");
}

#[test]
fn project_can_re_add_a_rule_the_user_disabled() {
    let user = "version: 1\ndisable: [priv.sudo]\n";
    let project = "version: 1\nrules:\n  - id: priv.sudo\n    severity: high\n    decision: ask\n    match: { program: sudo }\n";
    let policy = load_layers(Some(user), Some(project)).unwrap();
    assert!(policy.rule("priv.sudo").is_some());
    assert!(!policy.is_disabled("priv.sudo"));
}

#[test]
fn disabling_an_unknown_rule_is_an_error() {
    let project = "version: 1\ndisable:\n  - priv.sudo\n  - secrets.does_not_exist\n";
    let err = load_layers(None, Some(project)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::UnknownRuleId);
    assert_eq!(err.file, "project.yaml");
    assert_eq!(err.rule_id.as_deref(), Some("secrets.does_not_exist"));
    assert_eq!(err.line, Some(4));

    let twice = "version: 1\ndisable: [priv.sudo, priv.sudo]\n";
    let err = load_layers(None, Some(twice)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert!(err.message.contains("listed twice"), "{err}");

    let both = "version: 1\ndisable: [x.y]\nrules:\n  - id: x.y\n    severity: low\n    decision: ask\n    match: { program: a }\n";
    let err = load_layers(None, Some(both)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert_eq!(err.rule_id.as_deref(), Some("x.y"));
}

#[test]
fn layers_must_be_loaded_in_order() {
    let err = policy::load_sources(&[src(Layer::User, "u.yaml", "version: 1\n")]).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert!(
        err.message.contains("embedded, user, project order"),
        "{err}"
    );

    let err = policy::load_sources(&[
        src(Layer::Embedded, "b.yaml", BASE),
        src(Layer::Project, "p.yaml", "version: 1\n"),
        src(Layer::User, "u.yaml", "version: 1\n"),
    ])
    .unwrap_err();
    assert_eq!(err.file, "u.yaml");
}

// --- critical overrides -----------------------------------------------------

const WEAKEN_SSH: &str = r#"
version: 1
rules:
  - id: secrets.ssh_private_key
    severity: critical
    decision: ask
    match:
      access: [read, copy, send]
      paths: ["~/.ssh/id_*", "~/.ssh/*.pem", "~/.ssh/*_key"]
      except_paths: ["~/.ssh/*.pub", "~/.ssh/known_hosts", "~/.ssh/config"]
"#;

#[test]
fn project_file_cannot_weaken_a_critical_rule() {
    let err = load_layers(None, Some(WEAKEN_SSH)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);
    assert_eq!(err.file, "project.yaml");
    assert_eq!(err.rule_id.as_deref(), Some("secrets.ssh_private_key"));
    assert_eq!(err.line, Some(4));
    assert!(err.message.contains("weakening a critical rule"), "{err}");
    assert!(
        err.message.contains("project files can never do this"),
        "{err}"
    );
}

#[test]
fn project_file_cannot_weaken_a_critical_rule_even_when_user_allows_overrides() {
    let user = "version: 1\nallow_override_critical: true\n";
    let err = load_layers(Some(user), Some(WEAKEN_SSH)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);
    assert_eq!(err.file, "project.yaml");
}

#[test]
fn project_file_cannot_disable_lower_severity_or_narrow_a_critical_rule() {
    let disable = "version: 1\ndisable: [secrets.ssh_private_key]\n";
    let err = load_layers(None, Some(disable)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);
    assert_eq!(err.line, Some(2));
    assert!(err.message.contains("disabling a critical rule"), "{err}");

    let lower = "version: 1\nrules:\n  - id: secrets.ssh_private_key\n    severity: high\n    decision: deny\n    match:\n      access: [read, copy, send]\n      paths: [\"~/.ssh/id_*\", \"~/.ssh/*.pem\", \"~/.ssh/*_key\"]\n      except_paths: [\"~/.ssh/*.pub\", \"~/.ssh/known_hosts\", \"~/.ssh/config\"]\n";
    let err = load_layers(None, Some(lower)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);

    let narrow = "version: 1\nrules:\n  - id: secrets.ssh_private_key\n    severity: critical\n    decision: deny\n    match:\n      paths: [\"~/.ssh/id_rsa\"]\n";
    let err = load_layers(None, Some(narrow)).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);
}

#[test]
fn project_file_may_change_only_the_wording_of_a_critical_rule() {
    let reword = r#"
version: 1
rules:
  - id: secrets.ssh_private_key
    description: Reworded for this project
    severity: critical
    decision: deny
    match:
      access: [read, copy, send]
      paths: ["~/.ssh/id_*", "~/.ssh/*.pem", "~/.ssh/*_key"]
      except_paths: ["~/.ssh/*.pub", "~/.ssh/known_hosts", "~/.ssh/config"]
    agent_message: Still blocked, but friendlier.
"#;
    let policy = load_layers(None, Some(reword)).unwrap();
    let rule = policy.rule("secrets.ssh_private_key").unwrap();
    assert_eq!(rule.layer, Layer::Project);
    assert_eq!(
        rule.rule.description.as_deref(),
        Some("Reworded for this project")
    );
    assert!(rule.rule.is_critical());
}

#[test]
fn project_file_may_make_rules_stricter() {
    let stricter = "version: 1\nrules:\n  - id: exfil.upload_file\n    severity: critical\n    decision: deny\n    match: { program: [curl, wget, scp] }\n";
    let policy = load_layers(None, Some(stricter)).unwrap();
    let rule = policy.rule("exfil.upload_file").unwrap();
    assert!(rule.rule.is_critical());
    assert_eq!(rule.rule.decision, Outcome::Deny);
}

#[test]
fn user_file_cannot_weaken_a_critical_rule_without_the_flag() {
    let err = load_layers(Some(WEAKEN_SSH), None).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);
    assert_eq!(err.file, "user.yaml");
    assert_eq!(err.rule_id.as_deref(), Some("secrets.ssh_private_key"));
    assert!(
        err.message.contains("set `allow_override_critical: true`"),
        "{err}"
    );

    let disable = "version: 1\ndisable: [secrets.ssh_private_key]\n";
    let err = load_layers(Some(disable), None).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);

    let flag_false = format!("allow_override_critical: false\n{WEAKEN_SSH}");
    let err = load_layers(Some(&flag_false), None).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);
}

#[test]
fn user_file_may_weaken_or_disable_a_critical_rule_with_the_flag() {
    let weaken = format!("allow_override_critical: true\n{WEAKEN_SSH}");
    let policy = load_layers(Some(&weaken), None).unwrap();
    let rule = policy.rule("secrets.ssh_private_key").unwrap();
    assert_eq!(rule.layer, Layer::User);
    assert_eq!(rule.rule.decision, Outcome::Ask);

    let disable = "version: 1\nallow_override_critical: true\ndisable: [secrets.ssh_private_key]\n";
    let policy = load_layers(Some(disable), None).unwrap();
    assert!(policy.rule("secrets.ssh_private_key").is_none());
    assert!(policy.is_disabled("secrets.ssh_private_key"));
}

/// M15's `always_allow` appends a scoped `decision: allow` rule to the user
/// file, and a user may relax an Ask-level rule by hand. Neither touches a
/// `critical` rule, so neither needs `allow_override_critical`.
#[test]
fn user_file_may_relax_non_critical_rules_without_the_flag() {
    let user = r#"
version: 1
rules:
  - id: user.always_allow.exfil_upload_file.1a2b3c
    description: Approved by the user on 2026-10-16 via always_allow
    severity: info
    decision: allow
    match:
      program: [curl]
      args_any: ["-F"]
      paths: ["~/projects/demo/dist/*"]
  - id: exfil.upload_file
    description: Uploads are fine on this machine
    severity: low
    decision: allow
    match:
      program: [curl, wget]
      args_any: ["-T", "-F", "--data-binary"]
"#;
    let policy = load_layers(Some(user), None).expect("non-critical relaxations need no flag");
    assert_eq!(
        ids(&policy),
        [
            "secrets.ssh_private_key",
            "exfil.upload_file",
            "priv.sudo",
            "user.always_allow.exfil_upload_file.1a2b3c",
        ]
    );
    let appended = policy
        .rule("user.always_allow.exfil_upload_file.1a2b3c")
        .unwrap();
    assert_eq!(appended.layer, Layer::User);
    assert_eq!(appended.rule.decision, Outcome::Allow);

    let relaxed = &policy.rule("exfil.upload_file").unwrap().rule;
    assert_eq!(relaxed.decision, Outcome::Allow);
    assert_eq!(relaxed.severity, Severity::Low);

    let still_critical = &policy.rule("secrets.ssh_private_key").unwrap().rule;
    assert!(still_critical.is_critical());
    assert_eq!(still_critical.decision, Outcome::Deny);
}

#[test]
fn the_flag_is_rejected_outside_the_user_file() {
    let err = load_layers(None, Some("version: 1\nallow_override_critical: true\n")).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert_eq!(err.file, "project.yaml");
    assert_eq!(err.line, Some(2));
    assert!(
        err.message
            .contains("only honoured in the user policy file"),
        "{err}"
    );

    let embedded = "version: 1\nallow_override_critical: true\n";
    let err = policy::load_sources(&[src(Layer::Embedded, "e.yaml", embedded)]).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);

    let err = policy::load_sources(&[src(
        Layer::Embedded,
        "e.yaml",
        "version: 1\ndisable: [a.b]\n",
    )])
    .unwrap_err();
    assert!(err.message.contains("`disable` is only valid"), "{err}");
}

// --- files on disk ----------------------------------------------------------

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn paths_follow_home_and_project_dir() {
    let paths = Paths::new(Some(Path::new("/home/me")), Some(Path::new("/work/repo")));
    assert_eq!(
        paths.user_policy.as_deref(),
        Some(Path::new(
            "/home/me/.config/privaku/agent-shield/policy.yaml"
        ))
    );
    assert_eq!(
        paths.project_policy.as_deref(),
        Some(Path::new("/work/repo/.agent-shield.yaml"))
    );
    assert_eq!(Paths::embedded_only(), Paths::new(None, None));
}

#[test]
fn load_reads_user_then_project_file_from_injected_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("repo");
    let paths = Paths::new(Some(&home), Some(&repo));

    // Nothing on disk: embedded only.
    let policy = policy::load(&paths).unwrap();
    assert_eq!(policy.sources.len(), 1);

    write(
        paths.user_policy.as_ref().unwrap(),
        "version: 1\ndefaults:\n  ask_threshold: 0.4\nrules:\n  - id: user.rule\n    severity: low\n    decision: ask\n    match: { program: foo }\n",
    );
    let policy = policy::load(&paths).unwrap();
    assert_eq!(policy.sources.len(), 2);
    assert_eq!(policy.defaults.ask_threshold.value(), 0.4);
    assert!(policy.rule("user.rule").is_some());

    write(
        paths.project_policy.as_ref().unwrap(),
        "version: 1\ndisable: [user.rule]\nrules:\n  - id: project.rule\n    severity: low\n    decision: ask\n    match: { program: bar }\n",
    );
    let policy = policy::load(&paths).unwrap();
    assert_eq!(policy.sources.len(), 3);
    assert_eq!(
        policy.sources[2].name,
        paths.project_policy.as_ref().unwrap().display().to_string()
    );
    assert!(policy.rule("user.rule").is_none());
    assert!(policy.rule("project.rule").is_some());
    assert_eq!(policy.defaults.ask_threshold.value(), 0.4);
}

#[test]
fn load_reports_the_offending_file_and_fails_on_unreadable_files() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("repo");
    let paths = Paths::new(Some(&home), Some(&repo));
    let project = paths.project_policy.clone().unwrap();

    write(&project, "version: 1\nrules:\n  - id: bad\n    severity: high\n    decision: nope\n    match: { program: a }\n");
    let err = policy::load(&paths).unwrap_err();
    assert_eq!(err.file, project.display().to_string());
    assert_eq!(err.line, Some(5));
    assert_eq!(err.rule_id.as_deref(), Some("bad"));

    // A directory where the file should be is not "missing": it is an error.
    std::fs::remove_file(&project).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let err = policy::load(&paths).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Io);
    assert_eq!(err.file, project.display().to_string());
}

#[test]
fn validate_path_checks_a_file_as_the_given_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("policy.yaml");
    let none = Paths::embedded_only();

    write(
        &file,
        &format!("allow_override_critical: true\n{WEAKEN_SSH}"),
    );
    assert!(policy::validate_path(&none, &file, Layer::User).is_ok());
    let err = policy::validate_path(&none, &file, Layer::Project).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Invalid);
    assert_eq!(err.file, file.display().to_string());

    write(&file, "version: 1\ndisable: [rce.pipe_to_shell]\n");
    let err = policy::validate_path(&none, &file, Layer::Project).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::CriticalOverride);

    let err =
        policy::validate_path(&none, &tmp.path().join("missing.yaml"), Layer::User).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::Io);
    assert!(err.message.contains("no such file"), "{err}");

    write(&file, policy::EMBEDDED_DEFAULT);
    let policy = policy::validate_path(&none, &file, Layer::Embedded).unwrap();
    assert_eq!(policy.sources.len(), 1);
}

#[test]
fn validate_path_as_project_sits_on_the_user_file_when_present() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("repo");
    let paths = Paths::new(Some(&home), Some(&repo));
    let project = repo.join(".agent-shield.yaml");

    // The project disables a rule only the user file defines.
    write(&project, "version: 1\ndisable: [user.rule]\n");
    let err = policy::validate_path(&paths, &project, Layer::Project).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::UnknownRuleId);

    write(
        paths.user_policy.as_ref().unwrap(),
        "version: 1\nrules:\n  - id: user.rule\n    severity: low\n    decision: ask\n    match: { program: foo }\n",
    );
    let policy = policy::validate_path(&paths, &project, Layer::Project).unwrap();
    assert_eq!(
        policy.sources.iter().map(|s| s.layer).collect::<Vec<_>>(),
        [Layer::Embedded, Layer::User, Layer::Project]
    );
    assert!(policy.is_disabled("user.rule"));

    // Validating as the user layer ignores the user file on disk: the file
    // under test *is* the user file.
    let err = policy::validate_path(&paths, &project, Layer::User).unwrap_err();
    assert_eq!(err.kind, PolicyErrorKind::UnknownRuleId);

    // A broken user file is reported by name when validating a project file.
    write(paths.user_policy.as_ref().unwrap(), "version: 1\nnope: 1\n");
    let err = policy::validate_path(&paths, &project, Layer::Project).unwrap_err();
    assert_eq!(
        err.file,
        paths.user_policy.as_ref().unwrap().display().to_string()
    );
}
