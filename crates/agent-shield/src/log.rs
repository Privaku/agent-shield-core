use std::io::{self, Write};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use shield_audit::{
    read_entries, read_entries_since_now, verify_directory, AuditEntry, Paths, PlatformPaths,
};
use shield_core::model::{AgentKind, Outcome};

pub fn tail(
    n: usize,
    follow: bool,
    decision: Option<Outcome>,
    agent: Option<AgentKind>,
) -> ExitCode {
    match tail_inner(n, follow, decision, agent) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

pub fn verify() -> ExitCode {
    let result = PlatformPaths::from_env()
        .directory()
        .map_err(|error| error.to_string())
        .and_then(|directory| {
            verify_directory(&directory)
                .map(|report| {
                    println!(
                        "OK: {} entries across {} file(s); last hash {}",
                        report.entries, report.files, report.last_hash
                    );
                })
                .map_err(|error| error.to_string())
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

pub fn export(since: &str) -> ExitCode {
    match export_inner(since) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn matches_filters(
    entry: &AuditEntry,
    decision: Option<Outcome>,
    agent: Option<AgentKind>,
) -> bool {
    decision.is_none_or(|wanted| entry.decision == wanted)
        && agent.is_none_or(|wanted| entry.agent == wanted)
}

fn tail_inner(
    n: usize,
    follow: bool,
    decision: Option<Outcome>,
    agent: Option<AgentKind>,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = PlatformPaths::from_env().directory()?;
    verify_directory(&directory)?;
    let entries = read_entries(&directory)?;
    let matching = entries
        .iter()
        .filter(|entry| matches_filters(entry, decision, agent))
        .collect::<Vec<_>>();
    for entry in matching.into_iter().rev().take(n).rev() {
        print_entry(entry)?;
    }
    io::stdout().flush()?;

    if !follow {
        return Ok(());
    }

    let mut last_seen = entries.last().map(|entry| entry.hash.clone());
    loop {
        thread::sleep(Duration::from_millis(250));
        verify_directory(&directory)?;
        let current = read_entries(&directory)?;
        let start = match &last_seen {
            Some(hash) => current
                .iter()
                .position(|entry| &entry.hash == hash)
                .map(|index| index + 1)
                .ok_or("audit chain changed while following")?,
            None => 0,
        };
        for entry in &current[start..] {
            if matches_filters(entry, decision, agent) {
                print_entry(entry)?;
            }
        }
        if current.len() > start {
            io::stdout().flush()?;
        }
        last_seen = current.last().map(|entry| entry.hash.clone());
    }
}

fn export_inner(since: &str) -> Result<(), Box<dyn std::error::Error>> {
    let directory = PlatformPaths::from_env().directory()?;
    verify_directory(&directory)?;
    for entry in read_entries_since_now(&directory, since)? {
        print_entry(&entry)?;
    }
    io::stdout().flush()?;
    Ok(())
}

fn print_entry(entry: &AuditEntry) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string(entry)?);
    Ok(())
}
