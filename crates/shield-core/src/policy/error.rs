use std::fmt;

use thiserror::Error;

/// Why a policy failed to load. Every error names the file; the line and
/// rule id are filled in whenever they are known.
///
/// Rendered as `file:line: rule `id`: message`, dropping the parts that do
/// not apply (`file: message` for an unreadable file, for example).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub struct PolicyError {
    /// Path of the offending file, or [`EMBEDDED_NAME`](super::EMBEDDED_NAME)
    /// for the built-in policy.
    pub file: String,
    /// 1-based line, when the error can be tied to one.
    pub line: Option<usize>,
    /// Rule the error is about, when it is about a rule.
    pub rule_id: Option<String>,
    pub kind: PolicyErrorKind,
    pub message: String,
}

/// Coarse classification so callers can branch without parsing the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyErrorKind {
    /// The file could not be read.
    Io,
    /// Not valid YAML, or does not fit the schema (unknown field, bad enum
    /// value, wrong type, missing required key).
    Parse,
    /// Well-formed but inconsistent: bad version, empty `match`, bad id,
    /// `on_timeout: allow`, flag in the wrong layer, and so on.
    Invalid,
    /// The same rule id appears twice in one file.
    DuplicateId,
    /// `disable:` names a rule no earlier layer defines.
    UnknownRuleId,
    /// A layer tried to weaken or disable a `critical` rule without being
    /// allowed to.
    CriticalOverride,
}

impl PolicyError {
    pub fn new(kind: PolicyErrorKind, file: impl Into<String>, message: impl Into<String>) -> Self {
        PolicyError {
            file: file.into(),
            line: None,
            rule_id: None,
            kind,
            message: message.into(),
        }
    }

    pub fn at_line(mut self, line: Option<usize>) -> Self {
        self.line = line;
        self
    }

    pub fn for_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.file)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        f.write_str(": ")?;
        if let Some(id) = &self.rule_id {
            write!(f, "rule `{id}`: ")?;
        }
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_omits_missing_parts() {
        let base = PolicyError::new(PolicyErrorKind::Parse, "p.yaml", "boom");
        assert_eq!(base.to_string(), "p.yaml: boom");
        assert_eq!(base.clone().at_line(Some(3)).to_string(), "p.yaml:3: boom");
        assert_eq!(
            base.clone().for_rule("a.b").to_string(),
            "p.yaml: rule `a.b`: boom"
        );
        assert_eq!(
            base.at_line(Some(3)).for_rule("a.b").to_string(),
            "p.yaml:3: rule `a.b`: boom"
        );
    }
}
