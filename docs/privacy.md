# Privacy

© 2026 Privaku

Your code, files, and prompts are not uploaded.

## What stays local

A hook adapter reads the tool-call payload the agent already handed it on standard input. The policy engine evaluates that payload in this process. The decision is printed on standard output and appended to a hash-chained log on disk.

Nothing in that path opens a TCP or UDP connection. `scripts/no-network-test.sh` traces the end-to-end suite and fails if it calls `connect()` on `AF_INET` or `AF_INET6`.

The log, the policy files, and the approval socket are local:

| Data | Where |
| --- | --- |
| Audit log | `$AGENT_SHIELD_STATE_DIR`, or `$XDG_STATE_HOME/privaku`, or `~/.local/state/privaku` on Linux. On macOS, `~/Library/Logs/Privaku/agent-shield`. The active file is `audit.jsonl`. |
| User policy | `~/.config/privaku/agent-shield/policy.yaml` |
| Project policy | `.agent-shield.yaml` in the working directory |
| Approval socket | `$AGENT_SHIELD_SOCK`, or `$XDG_RUNTIME_DIR/privaku/agent-shield.sock`, or `/tmp/privaku-<uid>/agent-shield.sock` on Linux. On macOS, `~/Library/Application Support/Privaku/agent-shield.sock`. |

The socket is a Unix domain socket. The approval daemon and `agent-shield approve` talk only over that socket.

## What this core does on the network

Nothing. There is no telemetry, no licence client, no update check, and no model download in this repository.

`agent-shield check`, `hook`, `rules`, `log`, `install`, `doctor`, `mcp-proxy`, and `daemon` do not contact a server. `mcp-proxy` relays stdio between the agent and a local MCP server process. It does not add a network hop of its own.

## What the log stores

Each `check` or hook decision appends one JSON line: timestamp, agent, session, the action (command or path the agent submitted), the decision, the rule id, a risk score, and the hash chain. Secret-looking values in recorded actions are redacted by the audit writer when the redaction path runs; still treat the log as sensitive, because it records which commands were attempted.

`agent-shield log verify` checks the hash chain. `agent-shield log tail` prints recent JSON lines on your terminal. Neither command sends them anywhere.
