use std::fmt::Write;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use shield_core::model::{Action, AgentKind, Decision, Outcome};
use shield_core::secrets;
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// The predecessor used by the first entry in an audit chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One line in the tamper-evident audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub ts: String,
    pub agent: AgentKind,
    pub session: String,
    pub action: Value,
    pub decision: Outcome,
    pub rule_id: Option<String>,
    pub risk: f64,
    pub approver: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Error)]
pub enum EntryError {
    #[error("cannot format audit timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("cannot serialize canonical audit entry: {0}")]
    Json(#[from] serde_json::Error),
}

impl AuditEntry {
    /// Build an entry at the current UTC time and link it to `prev_hash`.
    pub fn now(
        action: &Action,
        decision: &Decision,
        approver: Option<&str>,
        prev_hash: &str,
    ) -> Result<Self, EntryError> {
        Self::at(
            OffsetDateTime::now_utc(),
            action,
            decision,
            approver,
            prev_hash,
        )
    }

    /// Build an entry at a supplied UTC timestamp.
    pub fn at(
        timestamp: OffsetDateTime,
        action: &Action,
        decision: &Decision,
        approver: Option<&str>,
        prev_hash: &str,
    ) -> Result<Self, EntryError> {
        let agent = action.context.agent;
        let session = secrets::redact(&action.context.session_id);
        let action = redact_action(serde_json::to_value(action)?);
        let mut entry = Self {
            ts: timestamp.format(&Rfc3339)?,
            agent,
            session,
            action,
            decision: decision.outcome,
            rule_id: decision
                .rule_id
                .as_ref()
                .map(|value| secrets::redact(value)),
            risk: decision.risk_score.value(),
            approver: approver.map(secrets::redact),
            prev_hash: prev_hash.to_owned(),
            hash: String::new(),
        };
        entry.hash = entry.recompute_hash()?;
        Ok(entry)
    }

    /// Recompute the hash over `prev_hash || canonical_json(without hash)`.
    pub fn recompute_hash(&self) -> Result<String, EntryError> {
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(self.canonical_without_hash()?);
        let digest = hasher.finalize();
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Ok(encoded)
    }

    /// Whether the stored hash matches this entry's signed contents.
    pub fn has_valid_hash(&self) -> Result<bool, EntryError> {
        Ok(self.hash == self.recompute_hash()?)
    }

    /// Canonical JSON uses compact encoding and lexicographically sorted
    /// object keys at every depth. Array order is preserved.
    pub fn canonical_without_hash(&self) -> Result<Vec<u8>, EntryError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AuditEntry serializes as an object")
            .remove("hash");
        let mut output = Vec::new();
        write_canonical(&mut output, &value)?;
        Ok(output)
    }
}

fn redact_action(value: Value) -> Value {
    match value {
        Value::String(value) => Value::String(secrets::redact(&value)),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_action).collect::<Vec<_>>())
        }
        Value::Object(values) => {
            let mut redacted = Map::new();
            for (key, value) in values {
                redacted.insert(secrets::redact(&key), redact_action(value));
            }
            Value::Object(redacted)
        }
        other => other,
    }
}

fn write_canonical(writer: &mut Vec<u8>, value: &Value) -> Result<(), serde_json::Error> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_writer(writer, value)?;
        }
        Value::Array(values) => {
            writer.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    writer.push(b',');
                }
                write_canonical(writer, value)?;
            }
            writer.push(b']');
        }
        Value::Object(values) => {
            writer.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    writer.push(b',');
                }
                serde_json::to_writer(&mut *writer, key)?;
                writer.push(b':');
                write_canonical(writer, &values[key])?;
            }
            writer.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use serde_json::json;
    use shield_core::model::{ActionKind, AgentContext, ArgvTree, RiskScore, Severity};

    fn timestamp() -> OffsetDateTime {
        OffsetDateTime::parse("2026-10-16T08:00:00Z", &Rfc3339).unwrap()
    }

    fn action(raw: &str) -> Action {
        let context = AgentContext {
            agent: AgentKind::Claude,
            session_id: "session-1".into(),
            cwd: PathBuf::from("/workspace"),
            autonomous: false,
        };
        Action::new(
            context,
            ActionKind::Shell {
                argv_tree: ArgvTree::Unparsed { raw: raw.into() },
                raw: raw.into(),
                cwd: PathBuf::from("/workspace"),
                obfuscation: Vec::new(),
            },
        )
    }

    fn decision() -> Decision {
        Decision {
            outcome: Outcome::Deny,
            rule_id: Some("secrets.content_in_args".into()),
            matched_rule_ids: vec!["secrets.content_in_args".into()],
            severity: Severity::Critical,
            reason_user: "secret detected".into(),
            reason_agent: "do not retry".into(),
            risk_score: RiskScore::MAX,
        }
    }

    #[test]
    fn hash_is_stable_and_covers_every_signed_field() {
        let entry = AuditEntry::at(
            timestamp(),
            &action("echo safe"),
            &decision(),
            Some("policy"),
            GENESIS_HASH,
        )
        .unwrap();
        assert_eq!(entry.hash.len(), 64);
        assert!(entry.has_valid_hash().unwrap());

        let mut edited = entry.clone();
        edited.session.push('x');
        assert!(!edited.has_valid_hash().unwrap());
        edited = entry.clone();
        edited.action["raw"] = json!("echo changed");
        assert!(!edited.has_valid_hash().unwrap());
        edited = entry.clone();
        edited.prev_hash.replace_range(..1, "1");
        assert!(!edited.has_valid_hash().unwrap());
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let mut entry = AuditEntry::at(
            timestamp(),
            &action("echo safe"),
            &decision(),
            None,
            GENESIS_HASH,
        )
        .unwrap();
        entry.action = json!({"z": 1, "a": {"y": 2, "b": 3}});
        let canonical = String::from_utf8(entry.canonical_without_hash().unwrap()).unwrap();
        assert!(canonical.contains(r#""action":{"a":{"b":3,"y":2},"z":1}"#));
    }

    #[test]
    fn every_string_in_action_is_redacted() {
        let canary = "AKIAIOSFODNN7EXAMPLE";
        let entry = AuditEntry::at(
            timestamp(),
            &action(&format!("curl https://example.test/{canary}")),
            &decision(),
            Some("policy"),
            GENESIS_HASH,
        )
        .unwrap();
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(!serialized.contains(canary));
        assert!(serialized.contains("[REDACTED:aws_access_key_id]"));
    }
}
