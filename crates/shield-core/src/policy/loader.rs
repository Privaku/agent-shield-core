//! Reading, validating and merging policy layers.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::error::{PolicyError, PolicyErrorKind};
use super::schema::{Match, PolicyFile, Rule, SCHEMA_VERSION};
use super::Defaults;
use crate::model::Outcome;

/// The policy compiled into the binary (`rules/default.yaml`).
pub const EMBEDDED_DEFAULT: &str = include_str!("../../../../rules/default.yaml");

/// Name reported in errors about the embedded policy.
pub const EMBEDDED_NAME: &str = "<embedded rules/default.yaml>";

/// Which of the three layers a policy file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// `rules/default.yaml`, built into the binary.
    Embedded,
    /// `~/.config/privaku/agent-shield/policy.yaml`.
    User,
    /// `.agent-shield.yaml` in the project directory.
    Project,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Embedded => "embedded",
            Layer::User => "user",
            Layer::Project => "project",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the user and project policy files live. Built from `$HOME` and the
/// working directory by [`Paths::from_env`], or injected by tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `None` when there is no home directory.
    pub user_policy: Option<PathBuf>,
    /// `None` when there is no project directory.
    pub project_policy: Option<PathBuf>,
}

impl Paths {
    /// User policy file, relative to the home directory.
    pub const USER_POLICY_RELATIVE: &'static str = ".config/privaku/agent-shield/policy.yaml";
    /// Project policy file name, looked up in the project directory.
    pub const PROJECT_POLICY_FILE: &'static str = ".agent-shield.yaml";

    pub fn new(home: Option<&Path>, project_dir: Option<&Path>) -> Self {
        Paths {
            user_policy: home.map(|h| h.join(Self::USER_POLICY_RELATIVE)),
            project_policy: project_dir.map(|p| p.join(Self::PROJECT_POLICY_FILE)),
        }
    }

    /// Home from `$HOME`, project from the current directory. Either may be
    /// absent; the corresponding layer is then skipped.
    pub fn from_env() -> Self {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from);
        let project = std::env::current_dir().ok();
        Paths::new(home.as_deref(), project.as_deref())
    }

    /// Only the embedded default: no user or project file.
    pub fn embedded_only() -> Self {
        Paths {
            user_policy: None,
            project_policy: None,
        }
    }
}

/// One policy layer as text, before parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub layer: Layer,
    /// Shown in errors and `rules list`.
    pub name: String,
    pub text: String,
}

impl Source {
    pub fn new(layer: Layer, name: impl Into<String>, text: impl Into<String>) -> Self {
        Source {
            layer,
            name: name.into(),
            text: text.into(),
        }
    }

    pub fn embedded() -> Self {
        Source::new(Layer::Embedded, EMBEDDED_NAME, EMBEDDED_DEFAULT)
    }

    /// Read a layer from disk. A missing file is `Ok(None)`; any other I/O
    /// failure is an error, because a policy we cannot read must not be
    /// silently skipped.
    pub fn read(layer: Layer, path: &Path) -> Result<Option<Self>, PolicyError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(Source::new(layer, path.display().to_string(), text))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolicyError::new(
                PolicyErrorKind::Io,
                path.display().to_string(),
                format!("cannot read policy file: {e}"),
            )),
        }
    }
}

/// A rule in the merged policy, remembering which layer last defined it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyRule {
    pub layer: Layer,
    /// File that last defined the rule.
    pub source: String,
    #[serde(flatten)]
    pub rule: Rule,
}

/// A rule switched off by `disable:` in a later layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisabledRule {
    pub id: String,
    /// Layer that disabled it.
    pub layer: Layer,
    pub source: String,
}

/// A layer that took part in the merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedSource {
    pub layer: Layer,
    pub name: String,
    pub rule_count: usize,
}

/// The merged, validated policy the engine evaluates.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Policy {
    pub version: u32,
    pub defaults: Defaults,
    /// Enabled rules in evaluation order: embedded order first, overrides in
    /// place, additions appended per layer.
    pub rules: Vec<PolicyRule>,
    pub disabled: Vec<DisabledRule>,
    pub sources: Vec<LoadedSource>,
}

impl Policy {
    pub fn rule(&self, id: &str) -> Option<&PolicyRule> {
        self.rules.iter().find(|r| r.rule.id == id)
    }

    pub fn is_disabled(&self, id: &str) -> bool {
        self.disabled.iter().any(|d| d.id == id)
    }
}

/// Load and merge the embedded default, the user file and the project file.
///
/// Missing user or project files are skipped. Any other problem is an error;
/// callers must treat a load error as a denied action, never as "no policy".
pub fn load(paths: &Paths) -> Result<Policy, PolicyError> {
    let mut sources = vec![Source::embedded()];
    if let Some(path) = &paths.user_policy {
        sources.extend(Source::read(Layer::User, path)?);
    }
    if let Some(path) = &paths.project_policy {
        sources.extend(Source::read(Layer::Project, path)?);
    }
    load_sources(&sources)
}

/// Load only the embedded default.
pub fn load_embedded() -> Result<Policy, PolicyError> {
    load_sources(&[Source::embedded()])
}

/// Parse and merge the given layers, in order. The first must be the
/// embedded layer; each later layer may appear at most once and in
/// `User`, `Project` order.
pub fn load_sources(sources: &[Source]) -> Result<Policy, PolicyError> {
    let mut parsed = Vec::with_capacity(sources.len());
    let mut previous: Option<Layer> = None;
    for source in sources {
        let in_order = match previous {
            None => source.layer == Layer::Embedded,
            Some(prev) => source.layer > prev,
        };
        if !in_order {
            return Err(PolicyError::new(
                PolicyErrorKind::Invalid,
                source.name.clone(),
                format!(
                    "policy layers must be loaded in embedded, user, project order; got `{}` after {}",
                    source.layer,
                    previous.map_or("nothing".to_string(), |p| format!("`{p}`"))
                ),
            ));
        }
        previous = Some(source.layer);
        parsed.push(parse_source(source)?);
    }
    merge(&parsed)
}

/// Validate one policy file on disk as the given layer.
///
/// The file is merged in the position [`load`] would give it: a user file
/// goes over the embedded default, a project file over the embedded default
/// and the user file from `paths` (when present). That way layer rules such
/// as critical overrides and unknown ids in `disable:` are checked against
/// the same base they will meet at run time.
pub fn validate_path(paths: &Paths, path: &Path, layer: Layer) -> Result<Policy, PolicyError> {
    let source = Source::read(layer, path)?.ok_or_else(|| {
        PolicyError::new(
            PolicyErrorKind::Io,
            path.display().to_string(),
            "cannot read policy file: no such file",
        )
    })?;
    let mut sources = Vec::with_capacity(3);
    if layer > Layer::Embedded {
        sources.push(Source::embedded());
    }
    if layer > Layer::User {
        if let Some(user) = &paths.user_policy {
            sources.extend(Source::read(Layer::User, user)?);
        }
    }
    sources.push(source);
    load_sources(&sources)
}

/// A parsed layer with its text kept for line lookups.
#[derive(Debug, Clone)]
pub struct ParsedSource {
    pub layer: Layer,
    pub name: String,
    pub text: String,
    pub file: PolicyFile,
}

/// Parse one layer and run the checks that need no other layer.
pub fn parse_source(source: &Source) -> Result<ParsedSource, PolicyError> {
    let file = parse_text(&source.name, &source.text)?;
    validate_file(source.layer, &source.name, &source.text, &file)?;
    Ok(ParsedSource {
        layer: source.layer,
        name: source.name.clone(),
        text: source.text.clone(),
        file,
    })
}

/// Deserialize a policy file, turning a serde error into a [`PolicyError`]
/// with the line of the offending value and, when the value sits inside a
/// rule, that rule's id.
fn parse_text(name: &str, text: &str) -> Result<PolicyFile, PolicyError> {
    serde_yaml_ng::from_str::<PolicyFile>(text).map_err(|err| {
        let line = err.location().map(|l| l.line());
        let mut message = err.to_string();
        if line.is_some() {
            if let Some(at) = message.rfind(" at line ") {
                message.truncate(at);
            }
        }
        let mut error = PolicyError::new(PolicyErrorKind::Parse, name, message).at_line(line);
        if let Some(id) = rule_index_in_path(&error.message).and_then(|i| lenient_rule_id(text, i))
        {
            error = error.for_rule(id);
        }
        error
    })
}

/// serde_yaml_ng prefixes messages with the path of the failing value, such
/// as `rules[2].match: unknown field ...`. Extract the rule index from it.
fn rule_index_in_path(message: &str) -> Option<usize> {
    let rest = message.strip_prefix("rules[")?;
    let end = rest.find(']')?;
    rest[..end].parse().ok()
}

/// Best-effort id of the `index`-th rule, read from an untyped parse of the
/// same text. Used only to enrich errors from the typed parse.
fn lenient_rule_id(text: &str, index: usize) -> Option<String> {
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).ok()?;
    value
        .get("rules")?
        .as_sequence()?
        .get(index)?
        .get("id")?
        .as_str()
        .map(str::to_string)
}

/// Checks that only need the file itself.
fn validate_file(
    layer: Layer,
    name: &str,
    text: &str,
    file: &PolicyFile,
) -> Result<(), PolicyError> {
    let invalid = |message: String| PolicyError::new(PolicyErrorKind::Invalid, name, message);

    if file.version != SCHEMA_VERSION {
        return Err(invalid(format!(
            "unsupported policy version {}; this build understands version {SCHEMA_VERSION}",
            file.version
        ))
        .at_line(find_key_line(text, "version")));
    }

    if file.allow_override_critical && layer != Layer::User {
        return Err(invalid(format!(
            "`allow_override_critical` is only honoured in the user policy file (~/{}), not in a {layer} file",
            Paths::USER_POLICY_RELATIVE
        ))
        .at_line(find_key_line(text, "allow_override_critical")));
    }

    if layer == Layer::Embedded && !file.disable.is_empty() {
        return Err(
            invalid("`disable` is only valid in user and project files".to_string())
                .at_line(find_key_line(text, "disable")),
        );
    }

    for (key, value) in [
        ("on_timeout", file.defaults.on_timeout),
        ("on_no_ui", file.defaults.on_no_ui),
    ] {
        if value == Some(Outcome::Allow) {
            return Err(invalid(format!(
                "defaults.{key} must be `deny` or `ask`; `allow` would fail open"
            ))
            .at_line(find_key_line(text, key)));
        }
    }

    let mut seen: Vec<&str> = Vec::with_capacity(file.rules.len());
    for rule in &file.rules {
        let line = find_rule_line(
            text,
            &rule.id,
            seen.iter().filter(|s| **s == rule.id).count(),
        );
        if seen.contains(&rule.id.as_str()) {
            return Err(PolicyError::new(
                PolicyErrorKind::DuplicateId,
                name,
                format!(
                    "duplicate rule id; first defined at line {}",
                    find_rule_line(text, &rule.id, 0).map_or("?".to_string(), |l| l.to_string())
                ),
            )
            .at_line(line)
            .for_rule(&rule.id));
        }
        seen.push(&rule.id);
        validate_rule(rule).map_err(|message| invalid(message).at_line(line).for_rule(&rule.id))?;
    }

    let mut seen_disable: Vec<&str> = Vec::with_capacity(file.disable.len());
    for id in &file.disable {
        let line = find_id_mention_line(text, id, "disable");
        if seen_disable.contains(&id.as_str()) {
            return Err(invalid("listed twice in `disable`".to_string())
                .at_line(line)
                .for_rule(id));
        }
        if seen.contains(&id.as_str()) {
            return Err(invalid(
                "defined in `rules` and listed in `disable` of the same file".to_string(),
            )
            .at_line(line)
            .for_rule(id));
        }
        seen_disable.push(id);
    }
    Ok(())
}

fn validate_rule(rule: &Rule) -> Result<(), String> {
    validate_id(&rule.id)?;
    validate_match(&rule.matcher, "match")
}

/// Ids are `namespace.name`: ASCII letters, digits, `_`, `-` and `.`, with
/// no empty segments.
fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("rule id must not be empty".to_string());
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        return Err(format!(
            "rule id contains {bad:?}; use ASCII letters, digits, `_`, `-` and `.` (for example `secrets.ssh_private_key`)"
        ));
    }
    if id.split('.').any(str::is_empty) {
        return Err("rule id must not start or end with `.` or contain `..`".to_string());
    }
    Ok(())
}

fn validate_match(matcher: &Match, path: &str) -> Result<(), String> {
    if matcher.is_empty() {
        return Err(format!(
            "`{path}` is empty; a rule must specify at least one condition"
        ));
    }
    if matcher.except_paths.is_some() && matcher.paths.is_none() {
        return Err(format!("`{path}.except_paths` requires `{path}.paths`"));
    }
    if let Some(access) = &matcher.access {
        if access.is_empty() {
            return Err(format!("`{path}.access` must not be an empty list"));
        }
    }
    for (key, list) in [
        ("paths", &matcher.paths),
        ("except_paths", &matcher.except_paths),
        ("program", &matcher.program),
        ("args_any", &matcher.args_any),
        ("args_all", &matcher.args_all),
        ("raw_any", &matcher.raw_any),
        ("flags", &matcher.flags),
    ] {
        if let Some(list) = list {
            if list.is_empty() {
                return Err(format!("`{path}.{key}` must not be an empty list"));
            }
            if list.iter().any(|s| s.trim().is_empty()) {
                return Err(format!("`{path}.{key}` contains an empty entry"));
            }
        }
    }
    if let Some(agent) = &matcher.agent {
        if agent.is_empty() {
            return Err(format!("`{path}.agent` must not be an empty list"));
        }
    }
    if let Some(mcp) = &matcher.mcp {
        if mcp.is_empty() {
            return Err(format!(
                "`{path}.mcp` must set at least one of `server`, `tool`, `arg`"
            ));
        }
        if let Some(arg) = &mcp.arg {
            if !arg.starts_with('/') {
                return Err(format!(
                    "`{path}.mcp.arg` must be a JSON pointer starting with `/`"
                ));
            }
        }
    }
    if let Some(dataflow) = &matcher.dataflow {
        if dataflow.source.trim().is_empty() || dataflow.sink.trim().is_empty() {
            return Err(format!(
                "`{path}.dataflow` needs non-empty `source` and `sink`"
            ));
        }
    }
    if let Some(stages) = &matcher.pipeline {
        if stages.is_empty() {
            return Err(format!("`{path}.pipeline` must have at least one stage"));
        }
        for (i, stage) in stages.iter().enumerate() {
            if stage.pipeline.is_some() {
                return Err(format!("`{path}.pipeline[{i}]` must not nest `pipeline`"));
            }
            validate_match(stage, &format!("{path}.pipeline[{i}]"))?;
        }
    }
    if let Some(alternatives) = &matcher.any {
        if alternatives.is_empty() {
            return Err(format!("`{path}.any` must have at least one alternative"));
        }
        for (i, alternative) in alternatives.iter().enumerate() {
            validate_match(alternative, &format!("{path}.any[{i}]"))?;
        }
    }
    Ok(())
}

/// Merge parsed layers in order.
///
/// Later layers overlay `defaults`, redefine rules with the same id, append
/// new rules and remove rules named in `disable`. A `critical` rule may only
/// be weakened (lower decision or severity, different `match`) or disabled
/// by the user layer, and only when that file sets
/// `allow_override_critical: true`. The project layer can never do it.
pub fn merge(layers: &[ParsedSource]) -> Result<Policy, PolicyError> {
    let mut defaults = Defaults::default();
    let mut rules: Vec<PolicyRule> = Vec::new();
    let mut disabled: Vec<DisabledRule> = Vec::new();
    let mut sources = Vec::with_capacity(layers.len());

    for layer in layers {
        defaults.apply(&layer.file.defaults);
        let may_override_critical =
            layer.layer == Layer::User && layer.file.allow_override_critical;
        let override_error = |id: &str, line: Option<usize>, what: &str| {
            let hint = match layer.layer {
                Layer::Project => {
                    "project files can never do this; the user can edit ~/".to_string()
                        + Paths::USER_POLICY_RELATIVE
                }
                _ => "set `allow_override_critical: true` in this file to permit it".to_string(),
            };
            PolicyError::new(
                PolicyErrorKind::CriticalOverride,
                layer.name.clone(),
                format!("{what} a critical rule is not allowed here; {hint}"),
            )
            .at_line(line)
            .for_rule(id)
        };

        for id in &layer.file.disable {
            let line = find_id_mention_line(&layer.text, id, "disable");
            match rules.iter().position(|r| r.rule.id == *id) {
                Some(i) => {
                    if rules[i].rule.is_critical() && !may_override_critical {
                        return Err(override_error(id, line, "disabling"));
                    }
                    rules.remove(i);
                    disabled.push(DisabledRule {
                        id: id.clone(),
                        layer: layer.layer,
                        source: layer.name.clone(),
                    });
                }
                None if disabled.iter().any(|d| d.id == *id) => {}
                None => {
                    return Err(PolicyError::new(
                        PolicyErrorKind::UnknownRuleId,
                        layer.name.clone(),
                        "`disable` names a rule no earlier policy layer defines",
                    )
                    .at_line(line)
                    .for_rule(id));
                }
            }
        }

        for rule in &layer.file.rules {
            let line = find_rule_line(&layer.text, &rule.id, 0);
            let entry = PolicyRule {
                layer: layer.layer,
                source: layer.name.clone(),
                rule: rule.clone(),
            };
            match rules.iter().position(|r| r.rule.id == rule.id) {
                Some(i) => {
                    let old = &rules[i].rule;
                    if old.is_critical() && is_downgrade(old, rule) && !may_override_critical {
                        return Err(override_error(&rule.id, line, "weakening"));
                    }
                    rules[i] = entry;
                }
                None => {
                    disabled.retain(|d| d.id != rule.id);
                    rules.push(entry);
                }
            }
        }

        sources.push(LoadedSource {
            layer: layer.layer,
            name: layer.name.clone(),
            rule_count: layer.file.rules.len(),
        });
    }

    Ok(Policy {
        version: SCHEMA_VERSION,
        defaults,
        rules,
        disabled,
        sources,
    })
}

/// A redefinition weakens a rule when it lowers the decision or severity or
/// changes what is matched. Only `description` and `agent_message` may
/// change freely.
fn is_downgrade(old: &Rule, new: &Rule) -> bool {
    new.decision < old.decision || new.severity < old.severity || new.matcher != old.matcher
}

/// 1-based line of the `occurrence`-th (0-based) `id: <id>` line in `text`.
fn find_rule_line(text: &str, id: &str, occurrence: usize) -> Option<usize> {
    let mut seen = 0usize;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        let line = line.strip_prefix("- ").map_or(line, str::trim_start);
        let Some(value) = line.strip_prefix("id:") else {
            continue;
        };
        if unquote(value) == id {
            if seen == occurrence {
                return Some(i + 1);
            }
            seen += 1;
        }
    }
    None
}

/// 1-based line of the first `key:` at any indentation.
fn find_key_line(text: &str, key: &str) -> Option<usize> {
    text.lines()
        .position(|raw| {
            let line = raw.trim_start();
            let line = line.strip_prefix("- ").map_or(line, str::trim_start);
            line.strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with(':'))
        })
        .map(|i| i + 1)
}

/// 1-based line where `id` is mentioned as a standalone token, searching from
/// the `section:` key onwards first and then the whole file.
fn find_id_mention_line(text: &str, id: &str, section: &str) -> Option<usize> {
    let start = find_key_line(text, section).map_or(0, |l| l - 1);
    let mentions = |from: usize| {
        text.lines()
            .enumerate()
            .skip(from)
            .find(|(_, raw)| {
                raw.split(|c: char| c.is_whitespace() || matches!(c, '[' | ']' | ',' | '"' | '\''))
                    .any(|tok| tok == id)
            })
            .map(|(i, _)| i + 1)
    };
    mentions(start).or_else(|| mentions(0))
}

/// Strip a trailing comment and surrounding quotes from a scalar as written.
fn unquote(value: &str) -> &str {
    let value = value.trim();
    let value = match value.split_once(" #") {
        Some((before, _)) => before.trim_end(),
        None => value,
    };
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_line_lookup_handles_quotes_comments_and_occurrences() {
        let text = "version: 1\nrules:\n  - id: a.b   # first\n    severity: high\n  - id: \"a.b\"\n  -   id: 'c.d'\n";
        assert_eq!(find_rule_line(text, "a.b", 0), Some(3));
        assert_eq!(find_rule_line(text, "a.b", 1), Some(5));
        assert_eq!(find_rule_line(text, "a.b", 2), None);
        assert_eq!(find_rule_line(text, "c.d", 0), Some(6));
        assert_eq!(find_rule_line(text, "zzz", 0), None);
    }

    #[test]
    fn key_and_mention_lookup() {
        let text = "version: 1\ndefaults:\n  on_timeout: allow\ndisable:\n  - x.y\n  - \"p.q\"\nversions: 2\n";
        assert_eq!(find_key_line(text, "version"), Some(1));
        assert_eq!(find_key_line(text, "on_timeout"), Some(3));
        assert_eq!(find_key_line(text, "disable"), Some(4));
        assert_eq!(find_key_line(text, "missing"), None);
        assert_eq!(find_id_mention_line(text, "x.y", "disable"), Some(5));
        assert_eq!(find_id_mention_line(text, "p.q", "disable"), Some(6));
        let flow = "disable: [a.b, \"c.d\"]\n";
        assert_eq!(find_id_mention_line(flow, "c.d", "disable"), Some(1));
    }

    #[test]
    fn rule_index_is_read_from_serde_path() {
        assert_eq!(rule_index_in_path("rules[3].match: unknown field"), Some(3));
        assert_eq!(
            rule_index_in_path("rules[0]: missing field `severity`"),
            Some(0)
        );
        assert_eq!(rule_index_in_path("defaults.ask_threshold: bad"), None);
        assert_eq!(rule_index_in_path("rules: invalid type"), None);
    }
}
