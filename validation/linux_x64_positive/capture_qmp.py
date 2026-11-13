"""Pause a local QEMU guest, save an ELF physical-memory dump, then resume it."""

from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path


class QMP:
    def __init__(self, path: Path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(600)
        self.socket.connect(str(path))
        self.input = self.socket.makefile("r", encoding="utf-8")
        greeting = json.loads(self.input.readline())
        if "QMP" not in greeting:
            raise RuntimeError("invalid QMP greeting")
        self.command("qmp_capabilities")

    def command(self, name: str, arguments: dict | None = None) -> dict:
        request = {"execute": name}
        if arguments is not None:
            request["arguments"] = arguments
        self.socket.sendall((json.dumps(request) + "\n").encode())
        while True:
            line = self.input.readline()
            if not line:
                raise RuntimeError(f"QMP disconnected during {name}")
            response = json.loads(line)
            if "error" in response:
                raise RuntimeError(f"QMP {name}: {response['error']}")
            if "return" in response:
                return response["return"]

    def close(self) -> None:
        self.input.close()
        self.socket.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    qmp = QMP(args.socket)
    try:
        qmp.command("stop")
        try:
            qmp.command(
                "dump-guest-memory",
                {"paging": False, "protocol": f"file:{args.output.resolve()}"},
            )
        finally:
            qmp.command("cont")
    finally:
        qmp.close()
    print(args.output)


if __name__ == "__main__":
    main()
