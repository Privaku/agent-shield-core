# Agent Shield Default Rules

This reference is generated from `rules/default.yaml`. Run `agent-shield rules docs` after changing the default policy.

## Defaults

| Setting | Value |
|---|---|
| Unmatched action | `allow` |
| Ask timeout | `30` seconds |
| On timeout | `deny` |
| No UI | `deny` |
| Ask threshold | `0.70` |

## Rule summary

| Rule | Severity | Decision | Description |
|---|---|---|---|
| `secrets.ssh_private_key` | `critical` | `deny` | Reading or copying SSH private keys |
| `secrets.dotenv` | `high` | `ask` | Reading or sending dotenv files requires approval |
| `secrets.cloud_credentials` | `critical` | `deny` | Accessing cloud and container credentials |
| `secrets.package_tokens` | `critical` | `deny` | Accessing package manager and source control tokens |
| `secrets.keychain` | `critical` | `deny` | Extracting secrets from the macOS keychain |
| `secrets.browser_data` | `critical` | `deny` | Accessing browser cookies or saved credentials |
| `secrets.content_in_args` | `critical` | `ask` | Secret-looking content appears in action arguments |
| `exfil.secret_to_network` | `critical` | `deny` | Sending a secret source to a network destination |
| `exfil.upload_file` | `high` | `ask` | Uploading a local file to a remote destination |
| `rce.pipe_to_shell` | `critical` | `deny` | Piping a download straight into an interpreter |
| `rce.decode_and_exec` | `critical` | `deny` | Decoding or constructing content and executing it |
| `destructive.rm_home_root` | `critical` | `deny` | Recursively deleting a home directory or filesystem root |
| `destructive.rm_recursive_outside_ws` | `high` | `ask` | Recursively deleting files outside the current workspace |
| `destructive.disk` | `critical` | `deny` | Erasing or overwriting a disk device |
| `destructive.git_history` | `medium` | `ask` | Rewriting shared or local Git history |
| `priv.sudo` | `high` | `ask` | Running with elevated privileges or changing privileged ownership |
| `persist.autostart` | `high` | `ask` | Modifying login, startup, or scheduled execution settings |
| `self.tamper` | `critical` | `deny` | Disabling or modifying Agent Shield protections |
| `net.raw_socket` | `critical` | `deny` | Opening a listener or raw reverse-shell connection |
| `mcp.fs_secret_paths` | `critical` | `deny` | MCP filesystem tool access to secret paths |

## `secrets.ssh_private_key`

Reading or copying SSH private keys

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "access": [
    "read",
    "copy",
    "send"
  ],
  "paths": [
    "~/.ssh/id_*",
    "~/.ssh/*.pem",
    "~/.ssh/*_key"
  ],
  "except_paths": [
    "~/.ssh/*.pub",
    "~/.ssh/known_hosts",
    "~/.ssh/config"
  ]
}
```

Agent guidance:

> Blocked by Privaku Agent Shield: SSH private keys are never readable by agents. Do not retry; ask the user to perform this step manually if truly required.

## `secrets.dotenv`

Reading or sending dotenv files requires approval

- Severity: `high`
- Decision: `ask`

Match:

```json
{
  "access": [
    "read",
    "send"
  ],
  "paths": [
    "**/.env",
    "**/.env.*"
  ],
  "except_paths": [
    "**/.env.example",
    "**/.env.sample",
    "**/.env.template"
  ]
}
```

Agent guidance:

> Approval is required because dotenv files often contain secrets. Do not retry; ask the user whether this specific access is intended.

## `secrets.cloud_credentials`

Accessing cloud and container credentials

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "access": [
    "read",
    "copy",
    "send"
  ],
  "paths": [
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.config/gcloud/**",
    "~/.azure/**",
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.oci/**"
  ]
}
```

Agent guidance:

> Blocked because cloud credentials are never readable by agents. Do not retry; ask the user to perform this credential operation manually.

## `secrets.package_tokens`

Accessing package manager and source control tokens

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "access": [
    "read",
    "copy",
    "send"
  ],
  "paths": [
    "~/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "~/.git-credentials",
    "~/.config/gh/hosts.yml",
    "~/.cargo/credentials*"
  ]
}
```

Agent guidance:

> Blocked because package and source-control tokens are never readable by agents. Do not retry; ask the user to perform the authenticated step manually.

## `secrets.keychain`

Extracting secrets from the macOS keychain

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "program": [
    "security"
  ],
  "args_any": [
    "find-generic-password",
    "find-internet-password",
    "dump-keychain",
    "export"
  ]
}
```

Agent guidance:

> Blocked because agents may not extract keychain secrets. Do not retry; ask the user to perform the keychain operation manually.

## `secrets.browser_data`

Accessing browser cookies or saved credentials

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "access": [
    "read",
    "copy",
    "send"
  ],
  "paths": [
    "~/Library/Application Support/Google/Chrome/**/Cookies",
    "~/Library/Application Support/Google/Chrome/**/Login Data",
    "~/Library/Application Support/Firefox/**/Cookies",
    "~/Library/Application Support/Firefox/**/logins.json",
    "~/Library/Application Support/BraveSoftware/**/Cookies",
    "~/Library/Application Support/BraveSoftware/**/Login Data",
    "~/Library/Cookies/**"
  ]
}
```

Agent guidance:

> Blocked because browser cookies and saved logins are private credentials. Do not retry; ask the user to perform this browser-data operation manually.

## `secrets.content_in_args`

Secret-looking content appears in action arguments

- Severity: `critical`
- Decision: `ask`

Match:

```json
{
  "secret_content": true
}
```

Agent guidance:

> Approval is required because the action contains secret-looking content. Do not retry or expose the value; ask the user how to proceed.

## `exfil.secret_to_network`

Sending a secret source to a network destination

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "any": [
    {
      "dataflow": {
        "source": "secret_file",
        "sink": "network"
      }
    },
    {
      "network_sink": true,
      "secret_content": true
    }
  ]
}
```

Agent guidance:

> Blocked because the action would send secret material over the network. Do not retry; ask the user to handle any intended transfer manually.

## `exfil.upload_file`

Uploading a local file to a remote destination

- Severity: `high`
- Decision: `ask`

Match:

```json
{
  "any": [
    {
      "program": [
        "curl"
      ],
      "args_any": [
        "-T",
        "-T*",
        "--upload-file",
        "--upload-file=*",
        "-F",
        "-F*",
        "--form",
        "--form=*",
        "-d",
        "--data",
        "--data-binary"
      ]
    },
    {
      "program": [
        "wget"
      ],
      "args_any": [
        "--post-file",
        "--post-file=*"
      ]
    },
    {
      "access": [
        "send"
      ],
      "program": [
        "scp",
        "rsync"
      ]
    }
  ]
}
```

Agent guidance:

> Approval is required before an agent uploads a local file. Do not retry; ask the user to confirm the file and destination.

## `rce.pipe_to_shell`

Piping a download straight into an interpreter

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "any": [
    {
      "pipeline": [
        {
          "program": [
            "curl",
            "wget",
            "fetch"
          ]
        },
        {
          "program": [
            "sh",
            "bash",
            "zsh",
            "dash",
            "python",
            "python3",
            "perl",
            "ruby",
            "node"
          ]
        }
      ]
    },
    {
      "raw_any": [
        "*<(curl *)*",
        "*<(wget *)*",
        "*$(curl *)*",
        "*$(wget *)*"
      ]
    }
  ]
}
```

Agent guidance:

> Blocked by Privaku Agent Shield: downloaded scripts must not be piped into a shell. Do not retry; download the script to a file and ask the user to review it.

## `rce.decode_and_exec`

Decoding or constructing content and executing it

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "any": [
    {
      "pipeline": [
        {
          "program": [
            "base64",
            "openssl"
          ]
        },
        {
          "program": [
            "sh",
            "bash",
            "zsh",
            "dash",
            "python",
            "python3",
            "perl",
            "ruby",
            "node"
          ]
        }
      ]
    },
    {
      "raw_any": [
        "*eval*base64*",
        "*exec(*decode(*",
        "*exec(*b64decode(*"
      ]
    }
  ]
}
```

Agent guidance:

> Blocked because decoded or dynamically constructed content would be executed. Do not retry; ask the user to review and run the decoded content manually.

## `destructive.rm_home_root`

Recursively deleting a home directory or filesystem root

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "access": [
    "delete"
  ],
  "paths": [
    "/",
    "~",
    "$HOME",
    "/Users/*"
  ],
  "program": [
    "rm"
  ],
  "args_any": [
    "-*r*",
    "--recursive",
    "--no-preserve-root"
  ]
}
```

Agent guidance:

> Blocked because this recursive deletion targets a home directory or filesystem root. Do not retry; ask the user to perform any intended cleanup manually.

## `destructive.rm_recursive_outside_ws`

Recursively deleting files outside the current workspace

- Severity: `high`
- Decision: `ask`

Match:

```json
{
  "access": [
    "delete"
  ],
  "program": [
    "rm"
  ],
  "args_any": [
    "-*r*",
    "--recursive"
  ],
  "outside_workspace": true
}
```

Agent guidance:

> Approval is required for recursive deletion outside the workspace. Do not retry; ask the user to confirm the exact target.

## `destructive.disk`

Erasing or overwriting a disk device

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "any": [
    {
      "program": [
        "dd"
      ],
      "args_any": [
        "of=/dev/*"
      ]
    },
    {
      "program": [
        "mkfs*"
      ]
    },
    {
      "program": [
        "diskutil"
      ],
      "args_any": [
        "eraseDisk",
        "eraseVolume",
        "partitionDisk"
      ]
    }
  ]
}
```

Agent guidance:

> Blocked because the action could erase or overwrite a disk. Do not retry; ask the user to perform this destructive operation manually.

## `destructive.git_history`

Rewriting shared or local Git history

- Severity: `medium`
- Decision: `ask`

Match:

```json
{
  "any": [
    {
      "program": [
        "git"
      ],
      "args_all": [
        "push",
        "--force",
        "main"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "push",
        "--force",
        "master"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "push",
        "--force-with-lease",
        "main"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "push",
        "--force-with-lease",
        "master"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "push",
        "-f",
        "main"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "push",
        "-f",
        "master"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "reset",
        "--hard"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "clean",
        "-fdx"
      ]
    },
    {
      "program": [
        "git"
      ],
      "args_all": [
        "clean",
        "-xfd"
      ]
    }
  ]
}
```

Agent guidance:

> Approval is required because this Git operation can discard or rewrite history. Do not retry; ask the user to confirm the repository and branch.

## `priv.sudo`

Running with elevated privileges or changing privileged ownership

- Severity: `high`
- Decision: `ask`

Match:

```json
{
  "any": [
    {
      "program": [
        "sudo",
        "su",
        "doas"
      ]
    },
    {
      "program": [
        "chmod"
      ],
      "args_any": [
        "+s",
        "u+s",
        "g+s",
        "4???",
        "2???",
        "6???"
      ]
    },
    {
      "program": [
        "chown"
      ],
      "args_any": [
        "root",
        "root:*"
      ]
    }
  ]
}
```

Agent guidance:

> Approval is required because this action changes privileges. Do not retry; ask the user to perform or approve the exact privileged step.

## `persist.autostart`

Modifying login, startup, or scheduled execution settings

- Severity: `high`
- Decision: `ask`

Match:

```json
{
  "any": [
    {
      "access": [
        "write",
        "delete"
      ],
      "paths": [
        "~/Library/LaunchAgents/**",
        "/Library/LaunchAgents/**",
        "/Library/LaunchDaemons/**",
        "/Library/StartupItems/**",
        "~/.zshrc",
        "~/.bashrc",
        "~/.profile"
      ]
    },
    {
      "program": [
        "crontab"
      ],
      "args_any": [
        "-e",
        "-"
      ]
    },
    {
      "program": [
        "launchctl"
      ],
      "args_any": [
        "load",
        "bootstrap"
      ]
    }
  ]
}
```

Agent guidance:

> Approval is required because this action changes automatic startup behavior. Do not retry; ask the user to confirm the persistence change.

## `self.tamper`

Disabling or modifying Agent Shield protections

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "any": [
    {
      "access": [
        "write",
        "delete"
      ],
      "paths": [
        "~/.config/privaku/agent-shield/**",
        "**/.agent-shield.yaml",
        "~/.privaku/**",
        "~/Library/Logs/Privaku/**",
        "~/.local/state/privaku/**",
        "~/.claude/settings.json",
        "~/.codex/hooks.json",
        "~/.cursor/hooks.json"
      ]
    },
    {
      "program": [
        "pkill",
        "killall"
      ],
      "args_any": [
        "*agent-shield*"
      ]
    }
  ]
}
```

Agent guidance:

> Blocked because agents may not disable or modify Agent Shield protections. Do not retry; ask the user to make any intended configuration change manually.

## `net.raw_socket`

Opening a listener or raw reverse-shell connection

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "any": [
    {
      "program": [
        "nc",
        "ncat",
        "netcat"
      ],
      "args_any": [
        "-l",
        "-l*",
        "--listen"
      ]
    },
    {
      "raw_any": [
        "*/dev/tcp/*",
        "*bash -i*>*"
      ]
    }
  ]
}
```

Agent guidance:

> Blocked because raw listeners and reverse shells are unsafe for agents. Do not retry; ask the user to establish any required connection manually.

## `mcp.fs_secret_paths`

MCP filesystem tool access to secret paths

- Severity: `critical`
- Decision: `deny`

Match:

```json
{
  "any": [
    {
      "paths": [
        "~/.ssh/**",
        "~/.aws/**",
        "~/.config/gcloud/**",
        "~/.azure/**",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.oci/**",
        "~/.npmrc",
        "~/.pypirc",
        "~/.netrc",
        "~/.git-credentials",
        "~/.config/gh/hosts.yml",
        "~/.cargo/credentials*",
        "**/.env",
        "**/.env.*",
        "~/Library/**/Cookies",
        "~/Library/**/Login Data",
        "~/Library/**/logins.json",
        "~/Library/Cookies/**"
      ],
      "except_paths": [
        "~/.ssh/*.pub",
        "~/.ssh/known_hosts",
        "~/.ssh/config",
        "**/.env.example",
        "**/.env.sample",
        "**/.env.template"
      ],
      "mcp": {
        "tool": "*read_file*",
        "arg": "/path"
      }
    },
    {
      "paths": [
        "~/.ssh/**",
        "~/.aws/**",
        "~/.config/gcloud/**",
        "~/.azure/**",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.oci/**",
        "~/.npmrc",
        "~/.pypirc",
        "~/.netrc",
        "~/.git-credentials",
        "~/.config/gh/hosts.yml",
        "~/.cargo/credentials*",
        "**/.env",
        "**/.env.*",
        "~/Library/**/Cookies",
        "~/Library/**/Login Data",
        "~/Library/**/logins.json",
        "~/Library/Cookies/**"
      ],
      "except_paths": [
        "~/.ssh/*.pub",
        "~/.ssh/known_hosts",
        "~/.ssh/config",
        "**/.env.example",
        "**/.env.sample",
        "**/.env.template"
      ],
      "mcp": {
        "tool": "*get_file_contents*",
        "arg": "/path"
      }
    },
    {
      "paths": [
        "~/.ssh/**",
        "~/.aws/**",
        "~/.config/gcloud/**",
        "~/.azure/**",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.oci/**",
        "~/.npmrc",
        "~/.pypirc",
        "~/.netrc",
        "~/.git-credentials",
        "~/.config/gh/hosts.yml",
        "~/.cargo/credentials*",
        "**/.env",
        "**/.env.*",
        "~/Library/**/Cookies",
        "~/Library/**/Login Data",
        "~/Library/**/logins.json",
        "~/Library/Cookies/**"
      ],
      "except_paths": [
        "~/.ssh/*.pub",
        "~/.ssh/known_hosts",
        "~/.ssh/config",
        "**/.env.example",
        "**/.env.sample",
        "**/.env.template"
      ],
      "mcp": {
        "tool": "*read_text_file*",
        "arg": "/file_path"
      }
    }
  ]
}
```

Agent guidance:

> Blocked because MCP filesystem tools may not read secret paths. Do not retry with another tool; ask the user to perform this access manually.
