**YAML schema excerpt (`rules/default.yaml`):**

```yaml
version: 1
defaults:
  unmatched: allow          # risk scorer may escalate to ask
  ask_timeout_seconds: 30
  on_timeout: deny
  on_no_ui: deny            # autonomous mode
  ask_threshold: 0.7
rules:
  - id: secrets.ssh_private_key
    description: Reading or copying SSH private keys
    severity: critical
    decision: deny
    match:
      access: [read, copy, send]
      paths: ["~/.ssh/id_*", "~/.ssh/*.pem", "~/.ssh/*_key"]
      except_paths: ["~/.ssh/*.pub", "~/.ssh/known_hosts", "~/.ssh/config"]
    agent_message: >
      Blocked by Privaku Agent Shield: SSH private keys are never readable by agents.
      Do not retry; ask the user to perform this step manually if truly required.
  - id: rce.pipe_to_shell
    severity: critical
    decision: deny
    match:
      pipeline:
        - { program: [curl, wget, fetch] }
        - { program: [sh, bash, zsh, dash, python, python3, perl, ruby, node] }
```
