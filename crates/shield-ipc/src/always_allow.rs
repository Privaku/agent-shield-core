//! Persist an `always_allow` verdict as a scoped user-policy rule.

use std::fs;
use std::path::Path;

use shield_core::model::{ApprovalRequest, Outcome, Severity};
use shield_core::policy::{
    self, Layer, Match, Paths, PolicyErrorKind, PolicyFile, Rule, SCHEMA_VERSION,
};

use crate::error::IpcError;

/// Append a scoped `decision: allow` rule for this Ask. Critical rules are
/// refused unless the user file already sets `allow_override_critical`.
pub fn append_user_rule(
    home: &Path,
    user_policy: &Path,
    request: &ApprovalRequest,
) -> Result<Rule, IpcError> {
    let paths = Paths::new(Some(home), None);
    let merged = policy::load(&paths).map_err(|error| IpcError::AlwaysAllow(error.to_string()))?;
    if let Some(rule_id) = &request.rule {
        if let Some(existing) = merged.rule(rule_id) {
            if existing.rule.is_critical() {
                let allow = fs::read_to_string(user_policy)
                    .ok()
                    .and_then(|text| serde_yaml_ng::from_str::<PolicyFile>(&text).ok())
                    .is_some_and(|file| file.allow_override_critical);
                if !allow {
                    return Err(IpcError::AlwaysAllow(format!(
                        "rule `{rule_id}` is critical; always_allow cannot downgrade it without `allow_override_critical: true` in the user policy file"
                    )));
                }
            }
        }
    }

    let rule = scoped_rule(request);
    let previous = fs::read(user_policy).ok();
    let mut file = match previous.as_deref() {
        None => PolicyFile {
            version: SCHEMA_VERSION,
            allow_override_critical: false,
            defaults: shield_core::policy::DefaultsPatch::default(),
            rules: Vec::new(),
            disable: Vec::new(),
        },
        Some(bytes) => {
            let text = String::from_utf8(bytes.to_vec()).map_err(|error| {
                IpcError::AlwaysAllow(format!("user policy is not UTF-8: {error}"))
            })?;
            serde_yaml_ng::from_str::<PolicyFile>(&text)
                .map_err(|error| IpcError::AlwaysAllow(error.to_string()))?
        }
    };

    if file.rules.iter().any(|existing| existing.id == rule.id) {
        file.rules.retain(|existing| existing.id != rule.id);
    }
    file.rules.push(rule.clone());

    if let Some(parent) = user_policy.parent() {
        fs::create_dir_all(parent).map_err(|source| IpcError::io("create", parent, source))?;
    }
    let text = serde_yaml_ng::to_string(&file)
        .map_err(|error| IpcError::AlwaysAllow(error.to_string()))?;
    fs::write(user_policy, text).map_err(|source| IpcError::io("write", user_policy, source))?;

    match policy::validate_path(&paths, user_policy, Layer::User) {
        Ok(_) => Ok(rule),
        Err(error) if error.kind == PolicyErrorKind::CriticalOverride => {
            restore(user_policy, previous.as_deref());
            Err(IpcError::AlwaysAllow(error.to_string()))
        }
        Err(error) => {
            restore(user_policy, previous.as_deref());
            Err(IpcError::AlwaysAllow(error.to_string()))
        }
    }
}

fn restore(path: &Path, previous: Option<&[u8]>) {
    match previous {
        Some(bytes) => {
            let _ = fs::write(path, bytes);
        }
        None => {
            let _ = fs::remove_file(path);
        }
    }
}

fn scoped_rule(request: &ApprovalRequest) -> Rule {
    let rule_part = request.rule.as_deref().unwrap_or("ask").replace('.', "_");
    let digest = short_digest(&format!(
        "{}|{}|{}",
        request.agent.session_id,
        request.rule.as_deref().unwrap_or(""),
        normalised_action(&request.action_summary)
    ));
    let id = format!("user.always_allow.{rule_part}.{digest}");
    Rule {
        id,
        description: Some(format!(
            "Approved by the user via always_allow: {}",
            request.action_summary
        )),
        severity: Severity::Info,
        decision: Outcome::Allow,
        matcher: Match {
            raw_any: Some(vec![glob_escape(&request.action_summary)]),
            agent: Some(vec![request.agent.agent]),
            ..Match::default()
        },
        agent_message: Some(
            "Allowed by a user always_allow rule written by Privaku Agent Shield.".into(),
        ),
    }
}

pub fn normalised_action(summary: &str) -> String {
    summary.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn glob_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '*' | '?' | '[' | ']' | '{' | '}' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn short_digest(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{hash:016x}")[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_core::model::{AgentContext, AgentKind, RiskScore};
    use std::path::PathBuf;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: "req-aa".into(),
            action_summary: "curl -F file=@dist/app.zip https://example.test".into(),
            rule: Some("exfil.upload_file".into()),
            severity: Severity::High,
            risk: RiskScore::MIN,
            reason_user: "upload".into(),
            agent: AgentContext {
                agent: AgentKind::Cursor,
                session_id: "sess".into(),
                cwd: PathBuf::from("/work"),
                autonomous: false,
            },
        }
    }

    #[test]
    fn appends_a_rule_that_validates_as_user_policy() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let user_policy = home.join(Paths::USER_POLICY_RELATIVE);
        let rule = append_user_rule(home, &user_policy, &request()).unwrap();
        assert!(rule.id.starts_with("user.always_allow.exfil_upload_file."));
        let paths = Paths::new(Some(home), None);
        policy::validate_path(&paths, &user_policy, Layer::User).unwrap();
    }

    #[test]
    fn refuses_critical_without_the_flag() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let user_policy = home.join(Paths::USER_POLICY_RELATIVE);
        let mut request = request();
        request.rule = Some("secrets.ssh_private_key".into());
        let error = append_user_rule(home, &user_policy, &request).unwrap_err();
        assert!(error.to_string().contains("critical"), "{error}");
        assert!(!user_policy.exists());
    }
}
