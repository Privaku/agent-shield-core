use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const WARMUPS: usize = 5;
const SAMPLES: usize = 50;
const MEDIAN_BUDGET: Duration = Duration::from_millis(15);

#[test]
fn median_claude_hook_invocation_is_below_fifteen_milliseconds_in_release() {
    assert_hook_latency(
        "claude",
        include_bytes!("../../../tests/fixtures/claude/bash_git_status.json"),
    );
}

#[test]
fn median_cursor_hook_invocation_is_below_fifteen_milliseconds_in_release() {
    assert_hook_latency(
        "cursor",
        include_bytes!("../../../tests/fixtures/cursor/shell_npm_test.json"),
    );
}

fn assert_hook_latency(agent: &str, fixture: &[u8]) {
    if cfg!(debug_assertions) {
        eprintln!("hook latency gate runs only with cargo test --release");
        return;
    }

    let sandbox = tempfile::tempdir().unwrap();
    let home = sandbox.path().join("home");
    let state = sandbox.path().join("state");
    fs::create_dir_all(&home).unwrap();
    let binary = assert_cmd::cargo::cargo_bin!("agent-shield");
    let mut samples = Vec::with_capacity(SAMPLES);

    for index in 0..(WARMUPS + SAMPLES) {
        let started = Instant::now();
        let mut child = Command::new(binary)
            .args(["hook", agent])
            .env_clear()
            .env("HOME", &home)
            .env("AGENT_SHIELD_STATE_DIR", &state)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(fixture).unwrap();
        let output = child.wait_with_output().unwrap();
        let elapsed = started.elapsed();
        assert!(
            output.status.success(),
            "hook failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if index >= WARMUPS {
            samples.push(elapsed);
        }
    }

    samples.sort_unstable();
    let median = samples[SAMPLES / 2];
    println!(
        "median {agent} hook latency: {:.3} ms over {SAMPLES} invocations",
        median.as_secs_f64() * 1_000.0
    );
    assert!(
        median < MEDIAN_BUDGET,
        "median {agent} hook latency {:.3} ms exceeds 15 ms",
        median.as_secs_f64() * 1_000.0
    );
}
