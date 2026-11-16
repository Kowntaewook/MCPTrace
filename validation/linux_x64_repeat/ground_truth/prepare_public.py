"""Audit and copy the synthetic non-Codex wire journals from repeat captures.

Codex journals contain session metadata and remain private. This script never
copies RAM images or scanner exports.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from mcptrace.core import strict_loads
from validation.linux_x64_real_host_ram.ground_truth.prepare_public import (
    inspect_public_value,
)


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
RUNS = {
    "inspector-http-r1-delayed": ("http-fast-1", "RPT_HTTP_A_20261116"),
    "inspector-http-r2-fast": ("inspector-http-r2-fast", "RPT_HTTP_B_20261116"),
    "inspector-http-r3-delayed": ("inspector-http-r3-delayed", "RPT_HTTP_C_20261116"),
    "inspector-stdio-r1-fast": ("inspector-stdio-r1-fast", "RPT_STDIO_A_20261116"),
    "inspector-stdio-r2-delayed": ("inspector-stdio-r2-delayed", "RPT_STDIO_B_20261116"),
    "lsp-r1-fast": ("lsp-r1-fast", None),
    "lsp-r2-delayed": ("lsp-r2-delayed", None),
    "jsonrpc-r1-fast": ("jsonrpc-r1-fast", None),
    "jsonrpc-r2-delayed": ("jsonrpc-r2-delayed", None),
}
FIELDS = {
    "inspector-http": {"direction", "framing", "message", "wire_base64"},
    "inspector-stdio": {"direction", "observed_ns", "message", "raw_base64", "raw_sha256"},
    "lsp-control": {"direction", "framing", "message", "raw_base64", "raw_sha256"},
    "jsonrpc-control": {"direction", "message", "raw_base64", "raw_sha256"},
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit(data: bytes, report: dict, marker: str | None) -> int:
    lines = data.splitlines()
    if len(lines) != report["traffic_messages"]:
        raise ValueError("journal row count differs from public report")
    case = report["case"]
    observed_marker = []
    for index, line in enumerate(lines):
        row = json.loads(line)
        if set(row) != FIELDS[case]:
            raise ValueError("unexpected journal field")
        if row["direction"] not in {"client-to-server", "server-to-client"}:
            raise ValueError("unexpected direction")
        if case == "inspector-http" and row["framing"] not in {"json", "sse"}:
            raise ValueError("unexpected HTTP framing")
        if case == "lsp-control" and row["framing"] != "content-length":
            raise ValueError("unexpected LSP framing")
        if "observed_ns" in row and type(row["observed_ns"]) is not int:
            raise ValueError("unexpected stdio timestamp")
        wire = base64.b64decode(row.get("wire_base64", row.get("raw_base64")), validate=True)
        if not wire.startswith(b"{") or not wire.endswith(b"}"):
            raise ValueError("non-object wire body")
        message = strict_loads(wire.decode("utf-8"))
        if message != row["message"]:
            raise ValueError("wire bytes and parsed message differ")
        inspect_public_value(message, marker)
        if "raw_sha256" in row and sha256(wire) != row["raw_sha256"]:
            raise ValueError("journal wire digest differs")
        measured = report["messages"][index]
        if (sha256(wire) != measured["raw_sha256"]
                or row["direction"] != measured["direction"]
                or row.get("framing", "stdio") != measured["framing"]
                or message.get("method", "") != measured["method"]):
            raise ValueError("journal differs from measured per-message report")
        if message.get("method") == "tools/call":
            observed_marker.append(message["params"]["arguments"]["marker"])
    if marker is not None and observed_marker != [marker]:
        raise ValueError("synthetic call marker differs")
    if marker is None and observed_marker:
        raise ValueError("control unexpectedly called an MCP tool")
    return len(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=HERE)
    args = parser.parse_args()
    rows = []
    copies = {}
    for name, (guest_run_id, marker) in RUNS.items():
        report_path = ROOT / "validation/linux_x64_repeat/results" / f"2026-11-16-{name}.json"
        report_data = report_path.read_bytes()
        report = json.loads(report_data)
        capture = args.private_root / "captures" / report.get("capture_dir_name", name)
        data = (capture / "traffic.jsonl").read_bytes()
        count = audit(data, report, marker)
        if sha256(data) != report["traffic_log_sha256"]:
            raise ValueError(f"{name}: original journal hash differs")
        if report["run_id"] != guest_run_id:
            raise ValueError(f"{name}: wrong run ID")
        ready = json.loads((capture / "client-ready.json").read_text())
        if ready["pid"] != report["client_pid"]:
            raise ValueError(f"{name}: wrong client PID")
        rows.append({
            "report": str(report_path.relative_to(ROOT)), "case": report["case"],
            "run_id": guest_run_id, "client_pid": ready["pid"],
            "image_sha256": report["image_sha256"],
            "traffic_sha256": sha256(data), "traffic_messages": count,
            "traffic_path": f"traffic/{name}.jsonl",
            "report_sha256": sha256(report_data),
        })
        copies[name] = data
    if len(rows) != 9 or sum(row["traffic_messages"] for row in rows) != 53:
        raise ValueError("unexpected public repeat corpus size")
    out = args.output
    (out / "traffic").mkdir(parents=True, exist_ok=True)
    for name, data in copies.items():
        (out / "traffic" / f"{name}.jsonl").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "scope": "exact synthetic JSON bodies for nine non-Codex Linux repeat images",
        "public_journals": 9,
        "public_messages": 53,
        "codex_journals_private": 2,
        "ram_images_private": 11,
        "runs": rows,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Audited and copied nine synthetic journals containing 53 exact wire bodies.")


if __name__ == "__main__":
    main()
