//! Supervised `sandbox-exec` launch for named CLI agents (Phase A).

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{anyhow, Context, Result};
use shield_core::sandbox::{fail_closed_message, is_sandboxed_cli, seatbelt_profile};

/// `sandbox-exec` path, overridable for tests.
pub fn sandbox_exec_bin() -> PathBuf {
    env::var_os("AGENT_SHIELD_SANDBOX_EXEC")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/sandbox-exec"))
}

pub fn sandbox_exec_available() -> bool {
    let bin = sandbox_exec_bin();
    bin.is_file() && is_executable(&bin)
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Write a 0600 Seatbelt profile for this session under a temp directory.
pub fn write_profile(home: &Path, session: &str) -> Result<PathBuf> {
    let dir = env::temp_dir().join("agent-shield-sandbox");
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join(format!("{session}.sb"));
    fs::write(&path, seatbelt_profile(home))
        .with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

pub fn named_cli(cmd: &[String]) -> Option<&str> {
    let name = cmd.first()?;
    if is_sandboxed_cli(name) {
        Path::new(name).file_name()?.to_str()
    } else {
        None
    }
}

/// Print the generated profile (dry-run / Linux CI).
pub fn print_profile(home: &Path) -> ExitCode {
    print!("{}", seatbelt_profile(home));
    ExitCode::SUCCESS
}

/// Build `sandbox-exec -f profile -- program args…` without spawning.
pub fn sandbox_command(
    profile: &Path,
    program: &Path,
    argv: &[impl AsRef<std::ffi::OsStr>],
    env_overrides: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Command {
    let mut command = Command::new(sandbox_exec_bin());
    command.arg("-f").arg(profile).arg("--").arg(program);
    if let Some((_, rest)) = argv.split_first() {
        command.args(rest);
    }
    for (key, value) in env_overrides {
        command.env(key, value);
    }
    command
}

/// Fail closed: do not start the named CLI unsandboxed.
pub fn refuse(cli: &str) -> ExitCode {
    eprintln!("error: {}", fail_closed_message(cli));
    ExitCode::from(1)
}

pub fn exec_sandboxed(
    home: &Path,
    session: &str,
    program: &Path,
    argv: &[std::ffi::OsString],
    env_overrides: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<ExitCode> {
    if !sandbox_exec_available() {
        let cli = program
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("agent");
        return Ok(refuse(cli));
    }
    let profile = write_profile(home, session)?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut command = sandbox_command(&profile, program, argv, env_overrides);
        let error = command.exec();
        Err(anyhow!(
            "sandbox-exec failed to apply the profile ({}). {}",
            error,
            fail_closed_message(
                program
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("agent")
            )
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = (home, session, program, argv, env_overrides, profile);
        Err(anyhow!("sandbox-exec is only available on macOS"))
    }
}

#[allow(dead_code)]
pub fn spawn_status(mut command: Command) -> io::Result<ExitCode> {
    let status = command.status()?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}
