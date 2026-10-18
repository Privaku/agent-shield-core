//! Portable `Dialog` seam for the macOS `osascript` approval fallback.
//!
//! Real `osascript` lives behind `cfg(target_os = "macos")` inside this
//! trait implementation. Linux CI uses [`MockDialog`] or [`PlatformDialog`],
//! which fails closed (Deny).

use std::fmt;

use shield_core::model::{ApprovalRequest, ApprovalVerdict};

/// Prompt a human when the approval daemon is unreachable.
pub trait Dialog: Send + Sync {
    fn prompt(&self, request: &ApprovalRequest) -> Result<ApprovalVerdict, DialogError>;
}

/// Why a fallback dialog could not produce a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogError {
    /// No dialog implementation is available (Linux, tests, headless).
    Unavailable,
    /// The dialog ran but failed or was dismissed.
    Failed(String),
}

impl fmt::Display for DialogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialogError::Unavailable => {
                write!(f, "no approval dialog is available on this platform")
            }
            DialogError::Failed(detail) => write!(f, "approval dialog failed: {detail}"),
        }
    }
}

impl std::error::Error for DialogError {}

/// Production dialog: `osascript` on macOS, unavailable elsewhere.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformDialog;

impl Dialog for PlatformDialog {
    fn prompt(&self, request: &ApprovalRequest) -> Result<ApprovalVerdict, DialogError> {
        #[cfg(target_os = "macos")]
        {
            OsascriptDialog.prompt(request)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DialogError::Unavailable)
        }
    }
}

/// macOS `osascript` "display dialog" fallback. The process spawn is
/// cfg-gated; script construction is shared so Linux can unit-test it.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsascriptDialog;

impl Dialog for OsascriptDialog {
    fn prompt(&self, request: &ApprovalRequest) -> Result<ApprovalVerdict, DialogError> {
        #[cfg(target_os = "macos")]
        {
            run_osascript(request)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DialogError::Unavailable)
        }
    }
}

/// Build the AppleScript shown by [`OsascriptDialog`]. Tested on Linux.
pub fn osascript_source(request: &ApprovalRequest) -> String {
    let text = format_dialog_text(request);
    let escaped = escape_applescript(&text);
    format!(
        r#"display dialog "{escaped}" buttons {{"Deny", "Allow once", "Allow for session", "Always allow"}} default button "Deny" with title "Privaku Agent Shield" giving up after 30"#
    )
}

pub fn format_dialog_text(request: &ApprovalRequest) -> String {
    let rule = request.rule.as_deref().unwrap_or("(none)");
    format!(
        "Privaku Agent Shield needs approval.\n\nAgent: {}\nAction: {}\nRule: {}\nRisk: {}\n\n{}",
        request.agent.agent.as_str(),
        request.action_summary,
        rule,
        request.risk,
        request.reason_user
    )
}

fn escape_applescript(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn run_osascript(request: &ApprovalRequest) -> Result<ApprovalVerdict, DialogError> {
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(osascript_source(request))
        .output()
        .map_err(|error| DialogError::Failed(error.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DialogError::Failed(stderr.trim().to_string()));
    }
    Ok(verdict_from_osascript_stdout(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Map `osascript` button text to a verdict. Used by the macOS impl and tests.
pub fn verdict_from_osascript_stdout(stdout: &str) -> ApprovalVerdict {
    if stdout.contains("Always allow") {
        ApprovalVerdict::AlwaysAllow
    } else if stdout.contains("Allow for session") {
        ApprovalVerdict::AllowSession
    } else if stdout.contains("Allow once") {
        ApprovalVerdict::AllowOnce
    } else {
        ApprovalVerdict::Deny
    }
}

/// In-memory dialog for Linux tests. Records every prompt.
#[derive(Debug, Default)]
pub struct MockDialog {
    responses: std::sync::Mutex<Vec<Result<ApprovalVerdict, DialogError>>>,
    calls: std::sync::Mutex<Vec<ApprovalRequest>>,
}

impl MockDialog {
    pub fn new(responses: Vec<Result<ApprovalVerdict, DialogError>>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<ApprovalRequest> {
        self.calls.lock().expect("mock dialog calls").clone()
    }
}

impl Dialog for MockDialog {
    fn prompt(&self, request: &ApprovalRequest) -> Result<ApprovalVerdict, DialogError> {
        self.calls
            .lock()
            .expect("mock dialog calls")
            .push(request.clone());
        let mut responses = self.responses.lock().expect("mock dialog responses");
        if responses.is_empty() {
            return Err(DialogError::Unavailable);
        }
        responses.remove(0)
    }
}

/// Always fails. Default Linux production dialog.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailingDialog;

impl Dialog for FailingDialog {
    fn prompt(&self, request: &ApprovalRequest) -> Result<ApprovalVerdict, DialogError> {
        let _ = request;
        Err(DialogError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use shield_core::model::{AgentContext, AgentKind, RiskScore, Severity};

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: "dlg-1".into(),
            action_summary: "cat ~/.env".into(),
            rule: Some("secrets.dotenv".into()),
            severity: Severity::High,
            risk: RiskScore::new(0.4).unwrap(),
            reason_user: "Reading a dotenv file".into(),
            agent: AgentContext {
                agent: AgentKind::Claude,
                session_id: "s1".into(),
                cwd: PathBuf::from("/work"),
                autonomous: false,
            },
        }
    }

    #[test]
    fn mock_dialog_records_calls_and_returns_scripted_verdicts() {
        let dialog = MockDialog::new(vec![
            Ok(ApprovalVerdict::AllowOnce),
            Err(DialogError::Failed("cancelled".into())),
        ]);
        let first = dialog.prompt(&request()).unwrap();
        assert_eq!(first, ApprovalVerdict::AllowOnce);
        let second = dialog.prompt(&request()).unwrap_err();
        assert_eq!(second, DialogError::Failed("cancelled".into()));
        assert_eq!(dialog.calls().len(), 2);
        assert_eq!(dialog.calls()[0].id, "dlg-1");
    }

    #[test]
    fn empty_mock_and_failing_dialog_are_unavailable() {
        let empty = MockDialog::new(Vec::new());
        assert_eq!(empty.prompt(&request()), Err(DialogError::Unavailable));
        assert_eq!(
            FailingDialog.prompt(&request()),
            Err(DialogError::Unavailable)
        );
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(
                OsascriptDialog.prompt(&request()),
                Err(DialogError::Unavailable)
            );
            assert_eq!(
                PlatformDialog.prompt(&request()),
                Err(DialogError::Unavailable)
            );
        }
    }

    #[test]
    fn osascript_source_includes_request_fields_and_buttons() {
        let script = osascript_source(&request());
        assert!(script.contains("display dialog"), "{script}");
        assert!(script.contains("Agent: claude"), "{script}");
        assert!(script.contains("Action: cat ~/.env"), "{script}");
        assert!(script.contains("Rule: secrets.dotenv"), "{script}");
        assert!(script.contains("Deny"), "{script}");
        assert!(script.contains("Allow once"), "{script}");
        assert!(script.contains("Allow for session"), "{script}");
        assert!(script.contains("Always allow"), "{script}");
        assert!(script.contains("giving up after 30"), "{script}");
    }

    #[test]
    fn osascript_source_escapes_quotes() {
        let mut request = request();
        request.action_summary = r#"echo "hi""#.into();
        let script = osascript_source(&request);
        assert!(script.contains(r#"echo \"hi\""#), "{script}");
    }

    #[test]
    fn osascript_stdout_maps_buttons() {
        assert_eq!(
            verdict_from_osascript_stdout("button returned:Allow once"),
            ApprovalVerdict::AllowOnce
        );
        assert_eq!(
            verdict_from_osascript_stdout("button returned:Allow for session"),
            ApprovalVerdict::AllowSession
        );
        assert_eq!(
            verdict_from_osascript_stdout("button returned:Always allow"),
            ApprovalVerdict::AlwaysAllow
        );
        assert_eq!(
            verdict_from_osascript_stdout("button returned:Deny"),
            ApprovalVerdict::Deny
        );
        assert_eq!(
            verdict_from_osascript_stdout("gave up:true"),
            ApprovalVerdict::Deny
        );
    }
}
