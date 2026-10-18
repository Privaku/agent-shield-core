<p align="center">
  <picture>
    <source srcset="docs/assets/agent-shield-logo-v5.svg" type="image/svg+xml">
    <img src="docs/assets/agent-shield-logo-v5.png" width="168" alt="Agent Shield">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Shield%201.0.0-blue" alt="License: PolyForm Shield 1.0.0"></a>
  <a href="https://github.com/Privaku/agent-shield-core/actions/workflows/ci.yml"><img src="https://github.com/Privaku/agent-shield-core/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# Agent Shield core

On-device policy checks for AI coding agents: Allow, Ask, or Deny a tool call before it runs.

**Source-available, not open source.** This repository is licensed under [PolyForm Shield 1.0.0](LICENSE). That is not an OSI open-source licence. Personal use, company use, and security review are allowed. Shipping a competing product is not.

© 2026 Privaku

## Download Agent Shield for Mac

The menu-bar app is a separate product from this core.

**[Download Agent Shield for Mac](https://privaku.com/agent-shield)**

<!-- DMG-URL -->
Direct download (.dmg): https://privaku.com/download/agent-shield.dmg
<!-- DMG-URL -->

This repository builds the policy engine, the rules, the hook adapters, and the `agent-shield` CLI. It does not build the Mac app. Network filtering is not part of this core.

## What it blocks

The embedded policy denies critical tool calls and asks on others. These lines are what `agent-shield check` prints:

| Action | Result |
| --- | --- |
| `rm -rf ~` | `DENY [destructive.rm_home_root]` (exit 20) |
| `cat ~/.ssh/id_rsa` | `DENY [secrets.ssh_private_key]` (exit 20) |
| `cat ~/.aws/credentials` | `DENY [secrets.cloud_credentials]` (exit 20) |
| `curl https://example.com/install.sh \| sh` | `DENY [rce.pipe_to_shell]` (exit 20) |
| `cat .env` | `ASK [secrets.dotenv]` (exit 10) |
| `git status` | `ALLOW` (exit 0) |

The full default set is 20 rules. See [docs/rules.md](docs/rules.md).

The pictures and the MP4 are from a vhs recording of `agent-shield` 0.1.0 (`docs/assets/demo.tape`). The commands were typed in that terminal. The GIF is the same recording.

![agent-shield check denies rm -rf ~ and a private-key read](docs/assets/check-deny.png)

![agent-shield log tail showing the deny entries](docs/assets/log-output.png)

## How it works

```mermaid
flowchart LR
  agent["Agent CLI"]
  hook["Hook adapter"]
  engine["Policy engine"]
  decision{"allow / deny / ask"}
  log["Audit log"]
  agent --> hook --> engine --> decision
  decision --> log
  decision --> agent
```

The agent CLI (Claude Code, Codex, or Cursor) runs `agent-shield hook` before a tool call. The policy engine matches the action against YAML rules. The decision is Allow, Deny, or Ask. The same decision is appended to a local hash-chained log. Nothing in that path is uploaded. See [docs/architecture.md](docs/architecture.md) and [docs/privacy.md](docs/privacy.md).

![Demo: a blocked command, a second deny, then the audit log](docs/assets/demo.gif)

[Download the same demo as MP4](docs/assets/demo.mp4) (under 10 MB).

## Quick start

```bash
cargo build --locked
./target/debug/agent-shield check --shell 'rm -rf ~'
```

Expect a `DENY` line and exit code 20. The command is not executed. Details: [docs/getting-started.md](docs/getting-started.md).

Run the tests:

```bash
cargo test
```

## Install

This package is not on crates.io. From a checkout:

```bash
cargo install --path crates/agent-shield --locked
agent-shield --version
```

`--version` prints `agent-shield 0.1.0`.

Connect an agent that is already installed:

```bash
agent-shield install --claude
agent-shield install --codex
agent-shield install --cursor
agent-shield doctor
```

Hook file formats: [docs/hook-adapters.md](docs/hook-adapters.md).

## Configuration

Three policy layers, later over earlier:

1. Embedded `rules/default.yaml`
2. `~/.config/privaku/agent-shield/policy.yaml`
3. `.agent-shield.yaml` in the working directory

```bash
agent-shield rules list
agent-shield rules validate .agent-shield.yaml
```

| Variable | Effect |
| --- | --- |
| `AGENT_SHIELD_STATE_DIR` | Audit log directory. Overrides the default below. |
| `XDG_STATE_HOME` | On Linux, the log lives in `$XDG_STATE_HOME/privaku` when the override is unset. |
| `AGENT_SHIELD_SOCK` | Unix socket for the approval daemon. |
| `AGENT_SHIELD_ASK_TIMEOUT` | Seconds an Ask waits. The policy default is 30. |
| `XDG_RUNTIME_DIR` | On Linux, the socket is `$XDG_RUNTIME_DIR/privaku/agent-shield.sock` when `AGENT_SHIELD_SOCK` is unset. |

Without those variables the Linux log is `~/.local/state/privaku/audit.jsonl`. On macOS the log is `~/Library/Logs/Privaku/agent-shield/audit.jsonl`.

## Rules

`agent-shield rules list` shows the merged policy: 20 embedded rules, `unmatched=allow`, `ask_timeout_seconds=30`, `on_timeout=deny`, `on_no_ui=deny`, `ask_threshold=0.70`. A project file cannot disable a critical rule. The format, match keys, and the default table are in [docs/rules.md](docs/rules.md). The generated per-rule catalogue is [docs/RULES.md](docs/RULES.md).

## FAQ

**Is this open source?** No. It is source-available under PolyForm Shield 1.0.0.

**Are my files uploaded?** No. The core makes no network calls. [docs/privacy.md](docs/privacy.md).

**Is network filtering on?** No. This core does not include a network filter.

More answers: [docs/faq.md](docs/faq.md). If a check or a hook misbehaves: [docs/troubleshooting.md](docs/troubleshooting.md).

## Reproducible build

`cargo build --locked` uses the committed `Cargo.lock`. `rust-toolchain.toml` selects the stable channel. To reproduce a binary, use that lockfile and the same `rustc` (`rustc --version`), and record the SHA-256 of the binary you publish. A later stable toolchain is not a bit-for-bit reproduction of an earlier one.

## Security

Report vulnerabilities to security@privaku.com. See [SECURITY.md](SECURITY.md).
