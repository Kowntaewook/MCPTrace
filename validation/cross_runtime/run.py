"""Local Linux process-memory check for real cross-runtime MCP SDK traffic.

This checks carving in live process virtual memory. It is not a physical RAM or
Volatility end-to-end validation and must not be reported as one.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

from mcptrace.core import ScanStats, scan_chunks

BLOCK = 64 * 1024
MAX_SCAN_BYTES = 256 * 1024 * 1024


def wait_for(path: Path, proc: subprocess.Popen, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if proc.poll() is not None:
            raise RuntimeError(f"process {proc.pid} exited with code {proc.returncode}")
        if time.monotonic() > deadline:
            raise TimeoutError(f"process {proc.pid} did not write {path}")
        time.sleep(0.1)


def canonical(message: dict) -> str:
    return json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def readable_private_maps(pid: int):
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        parts = line.split(maxsplit=5)
        start, end = (int(value, 16) for value in parts[0].split("-"))
        permissions = parts[1]
        name = parts[5] if len(parts) > 5 else ""
        if permissions.startswith("rw-p") and (not name or name.startswith("[")):
            yield start, end


def scan_process(pid: int, traffic_rows: list[dict]) -> tuple[list, dict, list[list[str]]]:
    maps = list(readable_private_maps(pid))
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    stats = ScanStats()
    read_bytes = read_errors = 0
    wire_encodings: list[set[str]] = [set() for _ in traffic_rows]
    needles: list[tuple[int, str, bytes]] = []
    for index, row in enumerate(traffic_rows):
        if "wire_base64" not in row:
            continue
        wire = base64.b64decode(row["wire_base64"], validate=True)
        if wire:
            needles.append((index, "utf-8", wire))
            needles.append((index, "utf-16-le", wire.decode("utf-8").encode("utf-16-le")))
    overlap = max((len(needle) for _, _, needle in needles), default=1) - 1

    def chunks():
        nonlocal read_bytes, read_errors
        for start, end in maps:
            tail = b""
            for address in range(start, end, BLOCK):
                if read_bytes >= MAX_SCAN_BYTES:
                    return
                try:
                    data = os.pread(fd, min(BLOCK, end - address), address)
                except OSError:
                    read_errors += 1
                    tail = b""
                    continue
                read_bytes += len(data)
                window = tail + data
                for index, encoding, needle in needles:
                    if encoding not in wire_encodings[index] and needle in window:
                        wire_encodings[index].add(encoding)
                tail = window[-overlap:] if overlap else b""
                yield address, data

    try:
        artifacts = list(scan_chunks(chunks(), stats=stats))
        verified = sum(
            hashlib.sha256(os.pread(fd, len(item.raw), item.address)).digest()
            == hashlib.sha256(item.raw).digest()
            for item in artifacts
        )
        prefixes = [
            os.pread(fd, min(128, item.address), max(0, item.address - 128)) for item in artifacts
        ]
    finally:
        os.close(fd)
    return (
        artifacts,
        {
            "scanned_bytes": read_bytes,
            "private_writable_maps": len(maps),
            "read_errors": read_errors,
            "truncated_at_256_mib": read_bytes >= MAX_SCAN_BYTES,
            "artifacts_reverified_at_virtual_address": verified,
            "sse_prefixed_artifact_records": sum(prefix.endswith(b"data: ") for prefix in prefixes),
            "content_length_framed_artifact_records": sum(
                re.search(rb"Content-Length: \d+\r\n\r\n$", prefix) is not None
                for prefix in prefixes
            ),
            "anchor_limit_hits": stats.anchor_limit_hits,
            "candidate_limit_hits": stats.candidate_limit_hits,
        },
        [sorted(encodings) for encodings in wire_encodings],
    )


def traffic_since(path: Path, offset: int) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        stream.seek(offset)
        return [json.loads(line) for line in stream if line.strip()]


def run_client(
    label: str, command: list[str], work: Path, traffic_name: str = "traffic.jsonl"
) -> dict:
    for name in ("client-ready.json", "client-stop"):
        (work / name).unlink(missing_ok=True)
    traffic = work / traffic_name
    offset = traffic.stat().st_size if traffic.exists() else 0
    with (work / f"{label}.stderr").open("wb") as stderr:
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
        try:
            wait_for(work / "client-ready.json", proc)
            time.sleep(0.3)
            truth_rows = traffic_since(traffic, offset)
            os.kill(proc.pid, signal.SIGSTOP)
            try:
                artifacts, scan, wire_encodings = scan_process(proc.pid, truth_rows)
            finally:
                os.kill(proc.pid, signal.SIGCONT)
            expected = {canonical(row["message"]) for row in truth_rows}
            found = {canonical(item.obj) for item in artifacts if item.obj}
            matched = found & expected
            per_message = [
                {
                    "direction": row["direction"],
                    "framing": row["framing"],
                    "method": row["message"].get("method", "response"),
                    "id": row["message"].get("id"),
                    "found": canonical(row["message"]) in matched,
                    "wire_exact_encodings": (
                        wire_encodings[index] if "wire_base64" in row else None
                    ),
                    "confirmed_scan_miss": (
                        bool(wire_encodings[index]) and canonical(row["message"]) not in matched
                    ),
                    "encodings": sorted(
                        {
                            item.encoding
                            for item in artifacts
                            if item.obj and canonical(item.obj) == canonical(row["message"])
                        }
                    ),
                }
                for index, row in enumerate(truth_rows)
            ]
            return {
                "runtime": label,
                "pid": proc.pid,
                "logged_messages": len(truth_rows),
                "distinct_logged_messages": len(expected),
                "distinct_logged_messages_found": len(matched),
                "logical_message_coverage": len(matched) / len(expected) if expected else None,
                "artifact_records": len(artifacts),
                "wire_probed_messages": sum("wire_base64" in row for row in truth_rows),
                "confirmed_scan_misses": sum(row["confirmed_scan_miss"] for row in per_message),
                "mcp_candidate_records": sum(item.mcp for item in artifacts),
                "unmatched_mcp_candidate_records": sum(
                    item.mcp and canonical(item.obj) not in expected
                    for item in artifacts
                    if item.obj
                ),
                "encodings": sorted({item.encoding for item in artifacts}),
                "sse_response_messages": sum(
                    row["direction"] == "server-to-client" and row["framing"] == "sse"
                    for row in truth_rows
                ),
                "per_message": per_message,
                **scan,
            }
        finally:
            (work / "client-stop").touch()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--dotnet-client", type=Path)
    parser.add_argument("--dotnet", type=Path)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    work = args.workdir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    node_fixture = Path(__file__).with_name("node_fixture.mjs").resolve()
    server_command = [str(args.node), str(node_fixture), "server", str(work), str(port)]
    with (work / "server.stderr").open("wb") as stderr:
        server = subprocess.Popen(server_command, stdout=subprocess.DEVNULL, stderr=stderr)
        try:
            wait_for(work / "server-ready.json", server)
            cases = [
                run_client(
                    "node",
                    [str(args.node), str(node_fixture), "client", str(work), str(port), "NODE-RAM"],
                    work,
                )
            ]
            if args.dotnet_client:
                if not args.dotnet:
                    parser.error("--dotnet is required with --dotnet-client")
                cases.append(
                    run_client(
                        "dotnet",
                        [
                            str(args.dotnet),
                            str(args.dotnet_client),
                            str(work),
                            str(port),
                            "DOTNET-RAM",
                        ],
                        work,
                    )
                )
                cases.append(
                    run_client(
                        "dotnet-modern",
                        [
                            str(args.dotnet),
                            str(args.dotnet_client),
                            str(work),
                            str(port),
                            "DOTNET-2026-RAM",
                            "modern",
                        ],
                        work,
                    )
                )
            cases.append(
                run_client(
                    "lsp-control",
                    [
                        str(args.node),
                        str(Path(__file__).with_name("lsp_control.mjs").resolve()),
                        str(work),
                    ],
                    work,
                    "lsp-traffic.jsonl",
                )
            )
            report = {
                "validation_scope": "live Linux process virtual memory; not full RAM or Volatility",
                "host": platform.platform(),
                "python": platform.python_version(),
                "node": subprocess.check_output([str(args.node), "--version"], text=True).strip(),
                "dotnet": (
                    subprocess.check_output([str(args.dotnet), "--version"], text=True).strip()
                    if args.dotnet
                    else None
                ),
                "cases": cases,
            }
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2))
        finally:
            (work / "server-stop").touch()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.terminate()
                server.wait(timeout=5)


if __name__ == "__main__":
    main()
