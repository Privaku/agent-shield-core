#!/usr/bin/env bash
# Run the E2E suite under strace and assert the security loop never
# connect()s over AF_INET/AF_INET6.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v strace >/dev/null 2>&1; then
    echo "strace is required for the no-network gate."
    if command -v apt-get >/dev/null 2>&1; then
        echo "Installing strace..."
        sudo apt-get update -qq
        sudo apt-get install -y strace
    else
        echo "Install strace and re-run."
        exit 1
    fi
fi

echo "Building E2E test binary (compile step is not traced)..."
cargo test -p agent-shield --test e2e --offline --no-run

mapfile -t BINS < <(find target/debug/deps -maxdepth 1 -type f -name 'e2e-*' -perm -111 | sort)
if [[ ${#BINS[@]} -eq 0 ]]; then
    echo "error: no e2e test binary under target/debug/deps" >&2
    exit 1
fi
BIN="${BINS[-1]}"
echo "Tracing $BIN"

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

# Follow forks (daemon, mock UI, hook children, mcp-proxy, python canary).
# Only connect() is traced. bind/listen/accept on the exfil canary is allowed.
set +e
strace -f -e trace=connect -o "$LOG" "$BIN" --nocapture
STATUS=$?
set -e

if [[ $STATUS -ne 0 ]]; then
    echo "error: E2E suite exited $STATUS under strace" >&2
    tail -n 40 "$LOG" >&2 || true
    exit "$STATUS"
fi

INET="$(grep -E 'AF_INET6?,' "$LOG" || true)"
if [[ -n "$INET" ]]; then
    echo "FAIL: security loop opened a TCP/UDP connect (AF_INET/AF_INET6):" >&2
    echo "$INET" | head -n 40 >&2
    exit 1
fi

UNIX_HITS="$(grep -c 'AF_UNIX' "$LOG" || true)"
echo "OK: only AF_UNIX connect() calls (count=$UNIX_HITS). No AF_INET/AF_INET6."
exit 0
