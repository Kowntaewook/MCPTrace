"""Small real stdio exchange with retained synthetic MCP-shaped JSON-RPC bytes.

The peer is purpose-built, not an official MCP SDK implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def encode(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def serve() -> None:
    retained: list[bytes] = []
    for raw in sys.stdin.buffer:
        retained.append(raw)
        request = json.loads(raw)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcptrace-control", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": [{"name": "echo_marker", "inputSchema": {"type": "object"}}]}
        else:
            result = {"content": [{"type": "text", "text": request["params"]["arguments"]["text"]}]}
        reply = encode({"jsonrpc": "2.0", "id": request["id"], "result": result})
        retained.append(reply)
        sys.stdout.buffer.write(reply)
        sys.stdout.buffer.flush()


def client(ready: Path) -> None:
    peer = subprocess.Popen(
        [sys.executable, __file__, "--server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert peer.stdin is not None and peer.stdout is not None
    retained: list[bytes] = []
    truth = []

    def exchange(message: dict) -> None:
        outbound = encode(message)
        retained.append(outbound)
        peer.stdin.write(outbound)
        peer.stdin.flush()
        truth.append(
            {
                "direction": "sent",
                "sha256": hashlib.sha256(outbound.strip()).hexdigest(),
                "message": message,
            }
        )
        if "id" in message:
            inbound = peer.stdout.readline()
            if not inbound:
                raise RuntimeError("stdio peer closed without a response")
            retained.append(inbound)
            truth.append(
                {
                    "direction": "received",
                    "sha256": hashlib.sha256(inbound.strip()).hexdigest(),
                    "message": json.loads(inbound),
                }
            )

    try:
        exchange(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "mcptrace-control", "version": "1"},
                },
            }
        )
        exchange({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        for index in range(3):
            exchange(
                {
                    "jsonrpc": "2.0",
                    "id": 10 + index,
                    "method": "tools/call",
                    "params": {
                        "name": "echo_marker",
                        "arguments": {"text": f"RAM_CONTROL_{index}"},
                    },
                }
            )
        unsent = encode(
            {
                "jsonrpc": "2.0",
                "id": "unsent",
                "method": "tools/call",
                "params": {"name": "echo_marker", "arguments": {"text": "RAM_UNSENT_CONTROL"}},
            }
        )
        retained.append(unsent)
        truth.append(
            {
                "direction": "unsent",
                "sha256": hashlib.sha256(unsent.strip()).hexdigest(),
                "message": json.loads(unsent),
            }
        )
        ready.write_text(
            json.dumps(
                {
                    "client_pid": os.getpid(),
                    "server_pid": peer.pid,
                    "messages": truth,
                    "retained_buffer_count": len(retained),
                },
                indent=2,
            )
            + "\n"
        )
        while True:
            time.sleep(1)
    finally:
        peer.terminate()
        peer.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--ready", type=Path)
    args = parser.parse_args()
    if args.server:
        serve()
    else:
        if args.ready is None:
            parser.error("--ready is required for the client")
        client(args.ready)


if __name__ == "__main__":
    main()
