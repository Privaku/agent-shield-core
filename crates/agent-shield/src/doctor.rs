use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use shield_audit::{verify_directory, Paths as AuditPaths, PlatformPaths};
use shield_core::policy::{self, Paths as PolicyPaths};

use crate::install::Installer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Warning,
    Error,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Warning => "WARN",
            Status::Error => "ERROR",
        }
    }
}

#[derive(Debug, Serialize)]
struct Check {
    status: Status,
    message: String,
}

#[derive(Debug, Serialize)]
struct HookCheck {
    agent: String,
    path: String,
    status: Status,
    message: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: u32,
    status: Status,
    binary: Check,
    hooks: Vec<HookCheck>,
    policy: Check,
    audit_log: Check,
    daemon: Check,
}

pub struct Doctor {
    home: PathBuf,
    binary: PathBuf,
    project_dir: PathBuf,
    audit_paths: PlatformPaths,
    socket_path: PathBuf,
}

impl Doctor {
    pub fn from_env() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set"))?;
        let binary = std::env::current_exe()
            .context("cannot locate the current agent-shield binary")?
            .canonicalize()
            .context("cannot resolve the current agent-shield binary")?;
        let project_dir = std::env::current_dir().context("cannot locate the current directory")?;
        let xdg_state_home = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from);
        let audit_override = std::env::var_os(shield_audit::STATE_DIR_ENV).map(PathBuf::from);
        let audit_paths = PlatformPaths::new(Some(home.clone()), xdg_state_home, audit_override);
        let socket_path = shield_ipc::socket_path_from_env()
            .unwrap_or_else(|_| home.join("Library/Application Support/Privaku/agent-shield.sock"));
        Ok(Self::new(
            home,
            binary,
            project_dir,
            audit_paths,
            socket_path,
        ))
    }

    pub fn new(
        home: PathBuf,
        binary: PathBuf,
        project_dir: PathBuf,
        audit_paths: PlatformPaths,
        socket_path: PathBuf,
    ) -> Self {
        Self {
            home,
            binary,
            project_dir,
            audit_paths,
            socket_path,
        }
    }

    fn examine(&self) -> DoctorReport {
        let binary = if self.binary.is_absolute() && self.binary.is_file() {
            Check {
                status: Status::Ok,
                message: self.binary.display().to_string(),
            }
        } else {
            Check {
                status: Status::Error,
                message: format!(
                    "current binary path is not an absolute file: {}",
                    self.binary.display()
                ),
            }
        };

        let installer = Installer::new(self.home.clone(), self.binary.clone());
        let hooks = installer
            .inspect_hooks()
            .into_iter()
            .map(|inspection| {
                let (status, message) = if !inspection.detected {
                    (Status::Warning, inspection.issues.join("; "))
                } else if inspection.issues.is_empty() {
                    (
                        Status::Ok,
                        "hook is installed and points at the current binary".to_string(),
                    )
                } else {
                    (Status::Error, inspection.issues.join("; "))
                };
                HookCheck {
                    agent: inspection.agent.as_str().to_string(),
                    path: inspection.path.display().to_string(),
                    status,
                    message,
                }
            })
            .collect::<Vec<_>>();

        let policy =
            match policy::load(&PolicyPaths::new(Some(&self.home), Some(&self.project_dir))) {
                Ok(loaded) => Check {
                    status: Status::Ok,
                    message: format!(
                        "policy v{} is valid ({} enabled rules)",
                        loaded.version,
                        loaded.rules.len()
                    ),
                },
                Err(error) => Check {
                    status: Status::Error,
                    message: error.to_string(),
                },
            };

        let audit_log = match self.audit_paths.directory() {
            Err(error) => Check {
                status: Status::Error,
                message: error.to_string(),
            },
            Ok(directory) if !directory.exists() => Check {
                status: Status::Warning,
                message: format!("no audit log yet at {}", directory.display()),
            },
            Ok(directory) => match verify_directory(&directory) {
                Ok(report) => Check {
                    status: Status::Ok,
                    message: format!(
                        "{} entries across {} file(s); chain is valid",
                        report.entries, report.files
                    ),
                },
                Err(error) => Check {
                    status: Status::Error,
                    message: error.to_string(),
                },
            },
        };

        let daemon = daemon_status(&self.socket_path);
        let status = std::iter::once(binary.status)
            .chain(hooks.iter().map(|hook| hook.status))
            .chain([policy.status, audit_log.status, daemon.status])
            .max()
            .unwrap_or(Status::Ok);
        DoctorReport {
            schema_version: 1,
            status,
            binary,
            hooks,
            policy,
            audit_log,
            daemon,
        }
    }
}

pub fn run(json: bool) -> ExitCode {
    let report = match Doctor::from_env() {
        Ok(doctor) => doctor.examine(),
        Err(error) => {
            eprintln!("error: {error:#}");
            return ExitCode::from(1);
        }
    };
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("error: cannot serialize doctor report: {error}");
                return ExitCode::from(1);
            }
        }
    } else {
        print_human(&report);
    }
    if report.status == Status::Error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn print_human(report: &DoctorReport) {
    let color = io::stdout().is_terminal();
    println!("Agent Shield doctor");
    print_check("Binary", &report.binary, color);
    for hook in &report.hooks {
        print_status(
            &format!("{} hooks", hook.agent),
            hook.status,
            &format!("{} ({})", hook.message, hook.path),
            color,
        );
    }
    print_check("Policy", &report.policy, color);
    print_check("Audit log", &report.audit_log, color);
    print_check("Daemon", &report.daemon, color);
}

fn daemon_status(socket_path: &std::path::Path) -> Check {
    if !socket_path.exists() {
        return Check {
            status: Status::Warning,
            message: format!("daemon is not running ({})", socket_path.display()),
        };
    }
    match shield_ipc::ping(socket_path, Duration::from_secs(1)) {
        Ok(()) => Check {
            status: Status::Ok,
            message: format!("daemon is running at {}", socket_path.display()),
        },
        Err(error) => Check {
            status: Status::Error,
            message: error.to_string(),
        },
    }
}

fn print_check(name: &str, check: &Check, color: bool) {
    print_status(name, check.status, &check.message, color);
}

fn print_status(name: &str, status: Status, message: &str, color: bool) {
    let label = if color {
        let code = match status {
            Status::Ok => "32",
            Status::Warning => "33",
            Status::Error => "31",
        };
        format!("\u{1b}[{code}m{}\u{1b}[0m", status.label())
    } else {
        status.label().to_string()
    };
    println!("[{label:<5}] {name}: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_paths_report_missing_hooks_and_bad_binary() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".cursor")).unwrap();
        let doctor = Doctor::new(
            temp.path().to_path_buf(),
            temp.path().join("missing-binary"),
            temp.path().to_path_buf(),
            PlatformPaths::new(
                Some(temp.path().to_path_buf()),
                None,
                Some(temp.path().join("audit")),
            ),
            temp.path().join("agent-shield.sock"),
        );
        let report = doctor.examine();
        assert_eq!(report.status, Status::Error);
        assert_eq!(report.binary.status, Status::Error);
        let cursor = report
            .hooks
            .iter()
            .find(|hook| hook.agent == "cursor")
            .unwrap();
        assert_eq!(cursor.status, Status::Error);
        assert!(cursor.message.contains("hook config is missing"));
        assert_eq!(report.daemon.status, Status::Warning);
    }
}
