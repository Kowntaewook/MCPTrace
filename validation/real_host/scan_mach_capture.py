"""Score a private in-process macOS Mach snapshot against a wire journal.

The input binary consists of little-endian (address:uint64, length:uint32,
bytes) records from mac_self_snapshot.c. Never commit or publish that binary.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import platform
import struct
from collections import Counter
from pathlib import Path

from mcptrace.core import ScanStats, scan_chunks
from validation.real_host.scan_linux_pid import canonical, sha256_file


def chunks(path: Path):
    with path.open("rb") as stream:
        while header := stream.read(12):
            if len(header) != 12:
                raise ValueError("truncated Mach capture header")
            address, length = struct.unpack("<QI", header)
            if not 0 < length <= 65536:
                raise ValueError("invalid Mach capture record length")
            data = stream.read(length)
            if len(data) != length:
                raise ValueError("truncated Mach capture record data")
            yield address, data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--traffic", type=Path, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.traffic.read_text().splitlines() if line.strip()]
    needles = []
    for row in rows:
        encoded = row.get("wire_base64", row.get("raw_base64"))
        raw = base64.b64decode(encoded, validate=True) if encoded else b""
        if raw and row.get("raw_sha256") and hashlib.sha256(raw).hexdigest() != row["raw_sha256"]:
            raise ValueError("wire journal hash mismatch")
        needles.append(raw)
    overlap = max(map(len, needles), default=1) - 1
    present: list[set[str]] = [set() for _ in rows]

    def observed_chunks():
        tail, tail_end = b"", None
        for address, data in chunks(args.capture):
            window = (tail if tail_end == address else b"") + data
            for index, raw in enumerate(needles):
                if raw and raw in window:
                    present[index].add("utf-8")
                if raw:
                    utf16 = raw.decode("utf-8").encode("utf-16-le")
                    if utf16 in window:
                        present[index].add("utf-16-le")
            tail = window[-overlap:] if overlap else b""
            tail_end = address + len(data)
            yield address, data

    stats = ScanStats()
    artifacts = list(scan_chunks(observed_chunks(), stats=stats))
    truth = {canonical(row["message"]) for row in rows}
    found = {canonical(item.obj) for item in artifacts if item.obj}
    messages = [
        {
            "direction": row["direction"],
            "method": row["message"].get("method", "response"),
            "id": row["message"].get("id"),
            "wire_encodings": sorted(present[index]),
            "carved": canonical(row["message"]) in found,
        }
        for index, row in enumerate(rows)
    ]
    summary = json.loads(Path(str(args.capture) + ".json").read_text())
    report = {
        "schema_version": 1,
        "case": args.case,
        "scope": "in-process macOS host virtual memory; not physical RAM or Volatility",
        "host": platform.platform(),
        "snapshot_sha256": sha256_file(args.capture),
        "traffic_sha256": hashlib.sha256(args.traffic.read_bytes()).hexdigest(),
        "logged_messages": len(rows),
        "distinct_logged_messages": len(truth),
        "distinct_logged_messages_carved": len(truth & found),
        "exact_wire_present_messages": sum(bool(p) for p in present),
        "confirmed_scan_misses": sum(
            bool(present[i]) and not m["carved"] for i, m in enumerate(messages)
        ),
        "artifact_records": len(artifacts),
        "mcp_candidate_records": sum(item.mcp for item in artifacts),
        "classification_records": dict(Counter(item.protocol_hint for item in artifacts)),
        "unmatched_mcp_candidate_records": sum(
            item.mcp and canonical(item.obj) not in truth for item in artifacts if item.obj
        ),
        "messages": messages,
        "anchor_limit_hits": stats.anchor_limit_hits,
        "candidate_limit_hits": stats.candidate_limit_hits,
        **summary,
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
                    "scanned_bytes",
                    "truncated_at_256_mib",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
