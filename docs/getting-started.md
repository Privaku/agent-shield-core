# Getting started

© 2026 Privaku

Agent Shield core is the on-device decision engine for AI coding agents.
This page builds it and runs one check. Hook setup is in [hook-adapters.md](hook-adapters.md).

## Requirements

- Rust stable, the channel in `rust-toolchain.toml`
- A Unix shell

## Build

From a checkout of this repository:

```bash
cargo build --locked
```

The binary is `target/debug/agent-shield`. A release binary:

```bash
cargo build --release --locked
```

`Cargo.lock` is part of the repository. `--locked` refuses a different dependency set.

## Try a check

`check` evaluates one action and appends the decision to the local audit log. It does not run the command.

```bash
./target/debug/agent-shield check --shell 'rm -rf ~'
```

A matching critical rule prints a deny line and exits 20:

```text
DENY [destructive.rm_home_root]: Recursively deleting a home directory or filesystem root
```

![agent-shield check denies rm -rf ~ and cat ~/.ssh/id_rsa](assets/check-deny.png)

An everyday command that matches no rule exits 0:

```bash
./target/debug/agent-shield check --shell 'git status'
```

```text
ALLOW: No policy rule matched
```

Exit codes from `check`:

| Code | Outcome |
| --- | --- |
| 0 | Allow |
| 10 | Ask |
| 20 | Deny |
| 2 | Usage error (not exactly one of `--shell`, `--read`, or `--mcp`) |

## Tests

```bash
cargo test
```

`scripts/no-network-test.sh` runs the end-to-end suite under `strace` and fails if that suite opens an `AF_INET` or `AF_INET6` socket. It needs `strace`.

## Install the binary

This crate is not published to crates.io (`publish = false`). Install from the checkout:

```bash
cargo install --path crates/agent-shield --locked
```

That places `agent-shield` on `~/.cargo/bin`. Put that directory on `PATH`, then:

```bash
agent-shield --version
```

The version line is `agent-shield 0.1.0`.

## Next

- [hook-adapters.md](hook-adapters.md) to connect Claude Code, Codex, and Cursor
- [rules.md](rules.md) to read and write policy
- [privacy.md](privacy.md) for what stays on the machine
