#!/usr/bin/env python3
"""Localhost-only CANARY receiver for the Agent Shield launch demo.

Binds 127.0.0.1 only. Shows NOTHING RECEIVED (green) until any body arrives,
then LEAKED (red). Used by docs/DEMO.md and tests/e2e; never a real sink.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"
BOLD = "\033[1m"


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.received_bytes = 0
        self.requests = 0

    def record(self, n: int) -> None:
        with self.lock:
            self.received_bytes += n
            self.requests += 1

    def snapshot(self) -> tuple[int, int]:
        with self.lock:
            return self.received_bytes, self.requests


def banner(received_bytes: int, requests: int) -> str:
    if received_bytes == 0:
        status = f"{GREEN}{BOLD}NOTHING RECEIVED{RESET}{GREEN}  (0 bytes, {requests} requests){RESET}"
    else:
        status = (
            f"{RED}{BOLD}LEAKED{RESET}{RED}  "
            f"({received_bytes} bytes across {requests} requests){RESET}"
        )
    return (
        "\n=== Privaku Agent Shield exfil canary (localhost only) ===\n"
        f"{status}\n"
        "Waiting on 127.0.0.1. Ctrl-C to stop.\n"
    )


def write_status(path: Path | None, received_bytes: int, requests: int) -> None:
    if path is None:
        return
    payload = {
        "received_bytes": received_bytes,
        "requests": requests,
        "leaked": received_bytes > 0,
    }
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def make_handler(state: State, status_file: Path | None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: N802
            sys.stderr.write("[exfil] " + (fmt % args) + "\n")

        def _client_is_loopback(self) -> bool:
            host = self.client_address[0]
            return host in {"127.0.0.1", "::1"}

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _reply(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if not self._client_is_loopback():
                self._reply(403, b"localhost only\n")
                return
            received_bytes, requests = state.snapshot()
            if self.path.startswith("/status"):
                body = json.dumps(
                    {
                        "received_bytes": received_bytes,
                        "requests": requests,
                        "leaked": received_bytes > 0,
                    }
                ).encode()
                self._reply(200, body)
                return
            if self.path.startswith("/setup.sh"):
                # Harmless canary payload. The shield must block `curl | sh`
                # before this body is ever fetched.
                self._reply(200, b"#!/bin/sh\necho CANARY setup.sh\n")
                return
            self._reply(200, banner(received_bytes, requests).encode())

        def do_PUT(self) -> None:  # noqa: N802
            self.do_POST()

        def do_POST(self) -> None:  # noqa: N802
            if not self._client_is_loopback():
                self._reply(403, b"localhost only\n")
                return
            body = self._read_body()
            state.record(len(body))
            received_bytes, requests = state.snapshot()
            write_status(status_file, received_bytes, requests)
            sys.stdout.write(banner(received_bytes, requests))
            sys.stdout.flush()
            self._reply(200, b"recorded\n")

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (loopback only)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--status-file",
        type=Path,
        help="JSON file with received_bytes; used by tests/e2e so the suite never opens a TCP client",
    )
    parser.add_argument(
        "--ready-file",
        type=Path,
        help="Touched once the server is listening",
    )
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("error: exfil-server binds loopback only", file=sys.stderr)
        return 2

    state = State()
    write_status(args.status_file, 0, 0)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state, args.status_file))
    server.daemon_threads = True
    bound_host, bound_port = server.server_address[:2]
    if args.ready_file is not None:
        args.ready_file.write_text(f"{bound_host}:{bound_port}\n", encoding="utf-8")

    sys.stdout.write(f"Listening on http://{bound_host}:{bound_port}\n")
    sys.stdout.write(banner(0, 0))
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
