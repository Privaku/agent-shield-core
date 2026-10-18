# Security Policy

© 2026 Privaku

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## Reporting a vulnerability

Report vulnerabilities in this core to **security@privaku.com**.

That is the security contact used by the Agent Shield project. Do not
open a public issue for a vulnerability.

Include what you found and how to reproduce it. The project aims to
acknowledge receipt within 48 hours.

## Design of this core

1. The security loop makes no network connections.
2. A policy or parser error denies the action. It does not allow it.
3. The audit log is a hash chain.
4. The process runs as the user. It does not need a privileged helper.

This policy covers the crates, rules, and CLI in this repository.
The macOS application is a separate product.
