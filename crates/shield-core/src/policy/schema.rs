//! Typed representation of a policy file.
//!
//! Every struct here rejects unknown fields, so a typo in a policy file is an
//! error rather than a rule that silently never matches. The `match` block is
//! typed but permissive: it names every key the M6 matchers understand and
//! validates their shape, while the matching semantics live in M6.

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::model::{AgentKind, Outcome, RiskScore, Severity};

/// The only policy schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Values used when a layer does not set a default.
pub const DEFAULT_ASK_TIMEOUT_SECONDS: u64 = 30;
/// Default `ask_threshold`: risk scores at or above this escalate an Allow.
pub const DEFAULT_ASK_THRESHOLD: f64 = 0.7;

/// One policy file as written on disk (before merging).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Schema version; must equal [`SCHEMA_VERSION`].
    pub version: u32,
    /// Only honoured in the user policy file. Lets that file downgrade or
    /// disable rules with `severity: critical`. A project file that sets it
    /// is rejected.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_override_critical: bool,
    /// Engine defaults. Every key is optional so overlay files can change one
    /// value; unset keys keep the value from the previous layer.
    #[serde(default, skip_serializing_if = "DefaultsPatch::is_empty")]
    pub defaults: DefaultsPatch,
    /// Rules added by this file, or redefinitions of rules from earlier layers
    /// (same `id`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// Ids of rules from earlier layers that this file switches off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disable: Vec<String>,
}

/// Partial `defaults:` block. See [`Defaults`] for the meaning of each key.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmatched: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_no_ui: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_threshold: Option<RiskScore>,
}

impl DefaultsPatch {
    pub fn is_empty(&self) -> bool {
        *self == DefaultsPatch::default()
    }
}

/// Fully resolved engine defaults after merging every layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Outcome for an action no rule matches. The risk scorer may still
    /// escalate an `allow` to an `ask`.
    pub unmatched: Outcome,
    /// How long an Ask waits for a human before `on_timeout` applies.
    pub ask_timeout_seconds: u64,
    /// Outcome when nobody answers an Ask in time. Never `allow`.
    pub on_timeout: Outcome,
    /// Outcome when no approval UI is connected (autonomous mode). Never
    /// `allow`.
    pub on_no_ui: Outcome,
    /// Risk scores at or above this value escalate an Allow to an Ask.
    pub ask_threshold: RiskScore,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            unmatched: Outcome::Allow,
            ask_timeout_seconds: DEFAULT_ASK_TIMEOUT_SECONDS,
            on_timeout: Outcome::Deny,
            on_no_ui: Outcome::Deny,
            ask_threshold: RiskScore::new(DEFAULT_ASK_THRESHOLD)
                .expect("DEFAULT_ASK_THRESHOLD is in range"),
        }
    }
}

impl Defaults {
    /// Overlay `patch` on top of `self`; unset keys are kept.
    pub fn apply(&mut self, patch: &DefaultsPatch) {
        if let Some(v) = patch.unmatched {
            self.unmatched = v;
        }
        if let Some(v) = patch.ask_timeout_seconds {
            self.ask_timeout_seconds = v;
        }
        if let Some(v) = patch.on_timeout {
            self.on_timeout = v;
        }
        if let Some(v) = patch.on_no_ui {
            self.on_no_ui = v;
        }
        if let Some(v) = patch.ask_threshold {
            self.ask_threshold = v;
        }
    }
}

/// One rule. The YAML `decision:` key maps onto [`Outcome`] and `severity:`
/// onto [`Severity`]; both only accept their `snake_case` spellings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, `namespace.name` by convention
    /// (`secrets.ssh_private_key`). Unique within a file; the same id in a
    /// later file redefines the rule.
    pub id: String,
    /// One line for humans, shown in `rules list` and `rules docs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub severity: Severity,
    pub decision: Outcome,
    /// What the rule matches. Interpreted by the M6 engine.
    #[serde(rename = "match")]
    pub matcher: Match,
    /// Returned to the agent when the rule fires. Written so the agent
    /// re-plans instead of retrying the same action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_message: Option<String>,
}

impl Rule {
    /// `true` for rules whose deny can only be relaxed by the user file with
    /// `allow_override_critical: true`.
    pub fn is_critical(&self) -> bool {
        self.severity == Severity::Critical
    }
}

/// How a path is touched. `read`, `copy` and `send` come from the §5 rule
/// table; `write` and `delete` cover `FileWrite`/`FileDelete` actions and
/// `exec` covers running a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
    Delete,
    Copy,
    Send,
    Exec,
}

/// The `match:` block. Every key is optional; a block must set at least one.
/// The M6 engine ANDs the keys that are present.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// At least one nested match block must hold. This expresses the
    /// command-shape alternatives of one stable rule id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Match>>,
    /// Access kinds the `paths` must be touched with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Vec<Access>>,
    /// Globs of sensitive paths (`~` and `$HOME` expanded by M5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Globs excluded from `paths`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub except_paths: Option<Vec<String>>,
    /// Program names after normalisation (`/bin/rm` is `rm`). Accepts a
    /// single string or a list.
    #[serde(
        default,
        deserialize_with = "string_or_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub program: Option<Vec<String>>,
    /// Matches when any argument equals or globs one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_any: Option<Vec<String>>,
    /// Matches when every pattern matches at least one argument.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_all: Option<Vec<String>>,
    /// Matches when the raw shell command matches any of these globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_any: Option<Vec<String>>,
    /// Flags that must be present, in any order (`-r`, `--recursive`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
    /// Ordered pipeline stages; each stage is itself a command matcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<Vec<Match>>,
    /// Data-flow from a source class to a sink class within one pipeline or
    /// command list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataflow: Option<Dataflow>,
    /// Requires (or forbids, with `false`) a network sink in the command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_sink: Option<bool>,
    /// Requires secret-looking content in arguments, URL or MCP args.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_content: Option<bool>,
    /// Requires a referenced path to resolve outside the action workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outside_workspace: Option<bool>,
    /// MCP tool-call matcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpMatch>,
    /// Restricts the rule to actions from these agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Vec<AgentKind>>,
}

impl Match {
    /// `true` when no key is set. Such a block is rejected by validation.
    pub fn is_empty(&self) -> bool {
        *self == Match::default()
    }
}

/// `dataflow: { source: secret_file, sink: network }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dataflow {
    /// Source class, e.g. `secret_file`, `secret_content`, `any_file`.
    pub source: String,
    /// Sink class, e.g. `network`, `shell`, `disk`.
    pub sink: String,
}

/// `mcp: { server: filesystem, tool: "read_*", arg: /path }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpMatch {
    /// Server name glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Tool name glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// JSON pointer into the tool arguments whose value is matched against
    /// `paths`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<String>,
}

impl McpMatch {
    pub fn is_empty(&self) -> bool {
        *self == McpMatch::default()
    }
}

/// Accepts `program: curl` as well as `program: [curl, wget]`.
fn string_or_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrList;

    impl<'de> Visitor<'de> for StringOrList {
        type Value = Option<Vec<String>>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string or a list of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(vec![v.to_string()]))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Some(vec![v]))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
            d.deserialize_any(StringOrList)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(item) = seq.next_element::<String>()? {
                out.push(item);
            }
            Ok(Some(out))
        }
    }

    deserializer.deserialize_any(StringOrList)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_accepts_string_or_list() {
        let one: Match = serde_yaml_ng::from_str("program: curl").unwrap();
        assert_eq!(one.program.as_deref(), Some(&["curl".to_string()][..]));

        let many: Match = serde_yaml_ng::from_str("program: [curl, wget]").unwrap();
        assert_eq!(
            many.program.as_deref(),
            Some(&["curl".to_string(), "wget".to_string()][..])
        );

        assert!(serde_yaml_ng::from_str::<Match>("program: 42").is_err());
        assert!(serde_yaml_ng::from_str::<Match>("program: {a: b}").is_err());
    }

    #[test]
    fn match_rejects_unknown_keys() {
        let err = serde_yaml_ng::from_str::<Match>("programs: [curl]").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn defaults_apply_keeps_unset_keys() {
        let mut d = Defaults::default();
        d.apply(&DefaultsPatch {
            ask_timeout_seconds: Some(5),
            ..DefaultsPatch::default()
        });
        assert_eq!(d.ask_timeout_seconds, 5);
        assert_eq!(d.unmatched, Outcome::Allow);
        assert_eq!(d.on_timeout, Outcome::Deny);
        assert_eq!(d.on_no_ui, Outcome::Deny);
        assert_eq!(d.ask_threshold.value(), DEFAULT_ASK_THRESHOLD);
    }

    #[test]
    fn policy_file_round_trips_through_yaml() {
        let yaml = r#"
version: 1
defaults:
  ask_threshold: 0.5
rules:
  - id: a.b
    description: d
    severity: high
    decision: ask
    match:
      program: [curl]
      args_any: ["-T", "-F"]
    agent_message: m
disable: [c.d]
"#;
        let file: PolicyFile = serde_yaml_ng::from_str(yaml).unwrap();
        let text = serde_yaml_ng::to_string(&file).unwrap();
        let again: PolicyFile = serde_yaml_ng::from_str(&text).unwrap();
        assert_eq!(file, again);
    }
}
