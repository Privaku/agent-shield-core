# FAQ

© 2026 Privaku

## Is this open source?

No. Agent Shield core is **source-available, not open source**. The licence is [PolyForm Shield 1.0.0](../LICENSE). It is not an OSI open-source licence. Personal use, company use, and security review are allowed. Shipping a competing product is not. Read the licence before you use or ship a build.

## Does it upload my code, files, or prompts?

No. The decision loop does not open a network connection. Details are in [privacy.md](privacy.md).

## Does it filter network traffic?

No. This core does not include a network filter, and these docs do not describe one as turned on. It decides on tool calls the agent submits to a hook, to `check`, or to the MCP proxy.

## Where is the Mac app?

The menu-bar app is a separate product: <https://privaku.com/agent-shield>. This repository builds the engine and the CLI.

<!-- DMG-URL -->
Direct download (.dmg): <https://privaku.com/download/agent-shield.dmg>
<!-- DMG-URL -->

## Which agents have a hook?

Claude Code, Codex, and Cursor. `agent-shield hook --help` lists those three agent names. Other names in `agent-shield protect list` are catalog rows, not hook installers. See [hook-adapters.md](hook-adapters.md).

## What does a deny look like?

```text
DENY [destructive.rm_home_root]: Recursively deleting a home directory or filesystem root
```

`check` exits 20. An Ask exits 10. An Allow exits 0.

## Can a project turn off a critical rule?

No. A project `.agent-shield.yaml` cannot weaken or disable a `critical` rule. The user policy can only when it sets `allow_override_critical: true`. See [rules.md](rules.md).

## Where do I report a vulnerability?

Email security@privaku.com. Do not open a public issue for a vulnerability. See [SECURITY.md](../SECURITY.md).
