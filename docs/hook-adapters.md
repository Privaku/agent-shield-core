# Hook adapters

© 2026 Privaku

`agent-shield hook` is the adapter an agent CLI runs before a tool call. The agent is `claude`, `codex`, or `cursor` (`agent-shield hook --help`).

```text
Usage: agent-shield hook [OPTIONS] <AGENT>

Arguments:
  <AGENT>  Agent type: claude, codex, cursor

Options:
      --event <EVENT>  Cursor event [possible values: beforeShellExecution, beforeMCPExecution, beforeReadFile]
      --autonomous     Mark the agent session as autonomous
```

`--event` is valid only for `cursor`. The payload arrives on stdin. The decision is printed on stdout. The process does not upload that payload.

## Install

`install` writes a hook only for an agent whose config directory is already present.

```bash
agent-shield install --claude
agent-shield install --cursor
agent-shield install --codex
agent-shield install --all
agent-shield uninstall --claude
```

`--all` installs every detected agent among those three. The command stored in the config is the absolute path of the `agent-shield` binary you ran, plus `hook claude`, `hook cursor`, or `hook codex`.

`agent-shield doctor` reports whether each hook still points at the current binary.

## Claude Code

Config: `~/.claude/settings.json`

`agent-shield install --claude` merges a `PreToolUse` command hook. The shape it writes:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/agent-shield hook claude"
          }
        ]
      }
    ]
  }
}
```

## Codex

Config: `~/.codex/hooks.json`

The installer uses the same `PreToolUse` command shape, with `hook codex`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/agent-shield hook codex"
          }
        ]
      }
    ]
  }
}
```

Codex MCP servers live in `~/.codex/config.toml` under `[mcp_servers]`. `agent-shield install --mcp` rewrites stdio servers through `mcp-proxy`. `--dry-run` prints the diff and writes nothing.

## Cursor

Config: `~/.cursor/hooks.json`

The installer sets `version` to `1` and adds three hooks, each with `failClosed: true`:

- `beforeShellExecution`
- `beforeMCPExecution`
- `beforeReadFile`

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "/absolute/path/to/agent-shield hook cursor --event beforeShellExecution",
        "failClosed": true
      }
    ],
    "beforeMCPExecution": [
      {
        "command": "/absolute/path/to/agent-shield hook cursor --event beforeMCPExecution",
        "failClosed": true
      }
    ],
    "beforeReadFile": [
      {
        "command": "/absolute/path/to/agent-shield hook cursor --event beforeReadFile",
        "failClosed": true
      }
    ]
  }
}
```

`failClosed: true` tells Cursor to block the tool call if the hook crashes. The installer always sets it. `doctor` checks it.

## MCP proxy

```bash
agent-shield install --mcp
agent-shield install --mcp --dry-run
agent-shield mcp-proxy --name fs -- npx -y some-server
```

`mcp-proxy` scans tool results and redacts detected secrets unless you pass `--no-redact-results`. `--redact-results` is the default.

## Other agents

Hook installers in this core exist for Claude Code, Codex, and Cursor only.

`agent-shield protect list` prints a catalog of additional agents the process matcher knows (GitHub Copilot, Gemini CLI, Windsurf, OpenCode, Cline, Zed, Kiro, Aider, Continue, Grok, Junie, Roo Code, Muse, and the Claude and Codex rows). `protect set <id> --on` or `--off` stores that preference. It does not install a hook.

`agent-shield run -- <command>` puts PATH shims ahead of the command. Named CLIs (`claude`, `codex`, `gemini`, `grok`, `muse`, `copilot`, `aider`, `opencode`, `cn`, `junie`, `cline`, `kiro`, `kiro-cli`) are started under `sandbox-exec` when that binary exists. If it does not, `run` refuses to start that named CLI. `agent-shield run --print-sandbox-profile` prints the Seatbelt profile and does not launch anything.

`agent-shield connect --status` prints consent and detection state. `connect --consent` records consent and connects detected supported agents on this machine. It does not contact a server.
