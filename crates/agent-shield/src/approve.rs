//! `agent-shield approve` — terminal approval UI.
//!
//! Interactive mode uses dialoguer (keys `a`/`s`/`A`/`d`). Non-interactive
//! tests pass `--script a,d,s` and never need a TTY.

use std::collections::VecDeque;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use dialoguer::console::{Key, Term};
use dialoguer::theme::{ColorfulTheme, Theme};
use shield_core::model::{ApprovalRequest, ApprovalVerdict};
use shield_ipc::{format_request, parse_script, verdict_from_key, ApprovalUiSession, IpcError};

const BY: &str = "cli";

pub fn run(script: Option<String>, once: bool) -> ExitCode {
    match run_inner(script, once) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run_inner(script: Option<String>, once: bool) -> Result<()> {
    let mut ui: Box<dyn ApproveUi> = match script {
        Some(script) => Box::new(ScriptedUi::parse(&script)?),
        None => {
            if !io::stdin().is_terminal() && !io::stderr().is_terminal() {
                return Err(anyhow!(
                    "no TTY; pass --script a,s,A,d for non-interactive approval"
                ));
            }
            Box::new(DialoguerUi)
        }
    };
    let mut session =
        ApprovalUiSession::connect().context("cannot connect to the approval daemon")?;
    println!("agent-shield approve: subscribed");
    let _ = io::stdout().flush();
    loop {
        let request = match session.next_request() {
            Ok(request) => request,
            Err(IpcError::Protocol(message)) if message.contains("closed") => break,
            Err(error) => return Err(error.into()),
        };
        let verdict = ui.decide(&request)?;
        session
            .respond(&request.id, verdict, BY)
            .context("cannot send approval response")?;
        if once {
            break;
        }
    }
    Ok(())
}

trait ApproveUi {
    fn decide(&mut self, request: &ApprovalRequest) -> Result<ApprovalVerdict>;
}

struct DialoguerUi;

impl ApproveUi for DialoguerUi {
    fn decide(&mut self, request: &ApprovalRequest) -> Result<ApprovalVerdict> {
        prompt_dialoguer(request)
    }
}

struct ScriptedUi {
    verdicts: VecDeque<ApprovalVerdict>,
}

impl ScriptedUi {
    fn parse(script: &str) -> Result<Self> {
        Ok(Self {
            verdicts: parse_script(script)?.into(),
        })
    }
}

impl ApproveUi for ScriptedUi {
    fn decide(&mut self, request: &ApprovalRequest) -> Result<ApprovalVerdict> {
        eprintln!("{}", format_request(request));
        if let Some(verdict) = self.verdicts.pop_front() {
            eprintln!("scripted verdict: {verdict:?}");
            Ok(verdict)
        } else {
            eprintln!("script exhausted; denying");
            Ok(ApprovalVerdict::Deny)
        }
    }
}

fn prompt_dialoguer(request: &ApprovalRequest) -> Result<ApprovalVerdict> {
    let term = Term::stderr();
    let theme = ColorfulTheme::default();
    let mut heading = String::new();
    theme
        .format_prompt(&mut heading, "Privaku Agent Shield")
        .ok();
    term.write_line("")?;
    term.write_line(&heading)?;
    term.write_line(&format_request(request))?;
    term.write_line("")?;
    term.write_line("[a] Allow once   [s] Allow for session   [A] Always allow   [d] Deny")?;
    loop {
        match term.read_key().context("cannot read approval key")? {
            Key::Char(key) => {
                if let Some(verdict) = verdict_from_key(key) {
                    return Ok(verdict);
                }
            }
            Key::Escape => return Ok(ApprovalVerdict::Deny),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use shield_core::model::{AgentContext, AgentKind, RiskScore, Severity};

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: "t".into(),
            action_summary: "read ~/.env".into(),
            rule: Some("secrets.dotenv".into()),
            severity: Severity::High,
            risk: RiskScore::MIN,
            reason_user: "ask".into(),
            agent: AgentContext {
                agent: AgentKind::Claude,
                session_id: "s".into(),
                cwd: PathBuf::from("/w"),
                autonomous: false,
            },
        }
    }

    #[test]
    fn scripted_ui_plays_verdicts_then_denies() {
        let mut ui = ScriptedUi::parse("a,d").unwrap();
        assert_eq!(ui.decide(&request()).unwrap(), ApprovalVerdict::AllowOnce);
        assert_eq!(ui.decide(&request()).unwrap(), ApprovalVerdict::Deny);
        assert_eq!(ui.decide(&request()).unwrap(), ApprovalVerdict::Deny);
    }
}
