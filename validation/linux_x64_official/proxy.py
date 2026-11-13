"""Forward real stdio bytes and log them outside the SDK client process."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--server", required=True, type=Path)
    args = parser.parse_args()
    server = subprocess.Popen(
        [sys.executable, str(args.server), "--run-id", args.run_id],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
    )
    assert server.stdin is not None and server.stdout is not None
    lock = threading.Lock()
    errors: list[Exception] = []
    with args.log.open("x", encoding="utf-8") as journal:
        (args.log.parent / "proxy-pid").write_text(str(os.getpid()), encoding="ascii")

        def forward(source, destination, direction: str) -> None:
            try:
                for raw in source:
                    message = json.loads(raw)
                    row = {
                        "direction": direction,
                        "observed_ns": time.time_ns(),
                        "raw_base64": base64.b64encode(raw.rstrip(b"\r\n")).decode("ascii"),
                        "raw_sha256": hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest(),
                        "message": message,
                    }
                    with lock:
                        journal.write(json.dumps(row, separators=(",", ":")) + "\n")
                        journal.flush()
                    destination.write(raw)
                    destination.flush()
            except Exception as exc:
                errors.append(exc)
            finally:
                if direction == "client-to-server":
                    destination.close()

        outgoing = threading.Thread(
            target=forward, args=(sys.stdin.buffer, server.stdin, "client-to-server")
        )
        incoming = threading.Thread(
            target=forward, args=(server.stdout, sys.stdout.buffer, "server-to-client")
        )
        outgoing.start()
        incoming.start()
        outgoing.join()
        incoming.join()
        status = server.wait(timeout=10)
        if errors or status:
            raise RuntimeError(f"stdio proxy failed: status={status}, errors={errors}")


if __name__ == "__main__":
    main()
