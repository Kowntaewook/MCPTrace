"""Score a paused Linux MCP host process against an independent wire journal.

This reads live process virtual memory, not a physical RAM image. Run as a user
permitted to read the target's /proc/<pid>/mem (often root under Yama policy).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import signal
from collections import Counter
from pathlib import Path

from validation.cross_runtime import run as memory_probe


def canonical(message: dict) -> str:
    return json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--traffic", type=Path, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--capture", type=Path, help="private binary process-memory capture")
    args = parser.parse_args()
    if args.pid <= 1:
        parser.error("--pid must identify a test process")
    rows = [json.loads(line) for line in args.traffic.read_text().splitlines() if line.strip()]
    for row in rows:
        raw = row.get("wire_base64", row.get("raw_base64"))
        if raw is not None:
            row["wire_base64"] = raw
            decoded = base64.b64decode(raw, validate=True)
            if hashlib.sha256(decoded).hexdigest() != row.get(
                "raw_sha256", hashlib.sha256(decoded).hexdigest()
            ):
                raise ValueError("traffic journal raw hash mismatch")
    os.kill(args.pid, signal.SIGSTOP)
    try:
        if args.capture:
            args.capture.parent.mkdir(parents=True, exist_ok=True)
        artifacts, scan, wire_encodings = memory_probe.scan_process(args.pid, rows, args.capture)
    finally:
        os.kill(args.pid, signal.SIGCONT)
    truth = {canonical(row["message"]) for row in rows if isinstance(row.get("message"), dict)}
    found = {canonical(item.obj) for item in artifacts if item.obj}
    messages = [
        {
            "direction": row["direction"],
            "method": row["message"].get("method", "response"),
            "id": row["message"].get("id"),
            "exact_wire_in_scanned_memory": bool(wire_encodings[index]),
            "wire_encodings": wire_encodings[index],
            "carved": canonical(row["message"]) in found,
        }
        for index, row in enumerate(rows)
        if isinstance(row.get("message"), dict)
    ]
    report = {
        "schema_version": 1,
        "case": args.case,
        "scope": "live Linux process virtual memory; not physical RAM or Volatility",
        "host": platform.platform(),
        "pid": args.pid,
        "process_command_sha256": hashlib.sha256(
            Path(f"/proc/{args.pid}/cmdline").read_bytes()
        ).hexdigest(),
        "traffic_sha256": hashlib.sha256(args.traffic.read_bytes()).hexdigest(),
        "snapshot_sha256": sha256_file(args.capture) if args.capture else None,
        "logged_messages": len(messages),
        "distinct_logged_messages": len(truth),
        "distinct_logged_messages_carved": len(truth & found),
        "exact_wire_present_messages": sum(row["exact_wire_in_scanned_memory"] for row in messages),
        "confirmed_scan_misses": sum(
            row["exact_wire_in_scanned_memory"] and not row["carved"] for row in messages
        ),
        "artifact_records": len(artifacts),
        "mcp_candidate_records": sum(item.mcp for item in artifacts),
        "classification_records": dict(Counter(item.protocol_hint for item in artifacts)),
        "unmatched_mcp_candidate_records": sum(
            item.mcp and canonical(item.obj) not in truth for item in artifacts if item.obj
        ),
        "messages": messages,
        **scan,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "case",
                    "logged_messages",
                    "distinct_logged_messages_carved",
                    "exact_wire_present_messages",
                    "confirmed_scan_misses",
                    "artifact_records",
                    "mcp_candidate_records",
                    "unmatched_mcp_candidate_records",
                    "scanned_bytes",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
