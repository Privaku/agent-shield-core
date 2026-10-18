# Contributing

© 2026 Privaku

Agent Shield core is source-available under [PolyForm Shield 1.0.0](LICENSE).
It is not an OSI open-source project. Read the licence before you use or
change the code. Contributions are accepted under the same licence.

## Build and test

```bash
cargo build --locked
cargo test
```

Use the stable toolchain in `rust-toolchain.toml`. Format with `rustfmt`.
A change to the engine, the rules format, or a hook adapter needs a test
that fails without the change.

`scripts/no-network-test.sh` checks that the end-to-end suite does not
open an IP socket. Run it when you touch the hook path, the proxy, or
the daemon.

## What belongs here

- The policy engine, the rules format, and the default rules
- Hook adapters for agent CLIs
- The `agent-shield` CLI that hosts those adapters
- No-network tests, corpora, and fixtures

Do not add the macOS app, a system extension, licensing or update
clients, signing material, or release workflows for those closed parts.

## Security reports

Email security@privaku.com. Do not file a public issue for a vulnerability.
See [SECURITY.md](SECURITY.md).

## Notices

Keep copyright lines as `© 2026 Privaku`. Do not add personal names,
private URLs, certificates, or keys.
