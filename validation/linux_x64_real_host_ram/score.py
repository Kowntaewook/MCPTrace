"""Score a live host or protocol control from a Linux physical RAM image.

The independent traffic journal and all raw exports stay outside Git. This
module writes only numerical results, hashes, and protocol labels.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote, urlparse

from mcptrace.core import strict_loads
from validation.linux_x64_official.score import probe_wire
from validation.linux_x64_positive.score import canonical, sha256, verify_exports


CASES = {"inspector-http", "inspector-stdio", "lsp-control", "jsonrpc-control"}


def read_traffic(path: Path) -> list[dict]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        row = json.loads(line)
        encoded = row.get("raw_base64", row.get("wire_base64"))
        if not isinstance(encoded, str):
            raise ValueError(f"traffic row {line_number} has no raw JSON body")
        raw = base64.b64decode(encoded, validate=True)
        if (not raw or canonical(strict_loads(raw.decode("utf-8"))) != canonical(row["message"])
                or ("raw_sha256" in row and hashlib.sha256(raw).hexdigest() != row["raw_sha256"])):
            raise ValueError(f"traffic row {line_number} has inconsistent raw bytes")
        rows.append({"raw": raw, "message": row["message"],
                     "direction": row["direction"], "framing": row.get("framing", "stdio")})
    if not rows:
        raise ValueError("traffic journal is empty")
    return rows


def score(*, case: str, image: Path, symbols: Path, cache: Path, config: Path,
          ready: Path, traffic: Path, export: Path) -> dict:
    if case not in CASES:
        raise ValueError(f"unknown case: {case}")
    configuration = json.loads(config.read_text(encoding="utf-8"))
    locations = [value for key, value in configuration.items()
                 if key.endswith(".memory_layer.base_layer.location")]
    configured = Path(unquote(urlparse(locations[0]).path)).resolve() if locations else None
    if len(locations) != 1 or configured != image.resolve():
        raise ValueError("Volatility config refers to a different RAM image")
    pid = int(json.loads(ready.read_text(encoding="utf-8"))["pid"])
    rows = read_traffic(traffic)
    artifacts, scans = verify_exports([export], symbols, cache, config)
    if len(scans) != 1 or scans[0]["pid"] != pid:
        raise ValueError("traffic client PID and exported process differ")
    found = {canonical(row["message"]) for row in artifacts}
    mcp_found = {canonical(row["message"]) for row in artifacts if row["mcp_candidate"]}
    presence, probe_stats = probe_wire(pid, rows, symbols, cache, config)
    truth = {canonical(row["message"]) for row in rows}
    per_message = []
    for row, flags in zip(rows, presence, strict=True):
        key = canonical(row["message"])
        exact_present = flags["utf8"] or flags["utf16le"]
        per_message.append({
            "direction": row["direction"],
            "framing": row["framing"],
            "method": row["message"].get("method", ""),
            "raw_sha256": hashlib.sha256(row["raw"]).hexdigest(),
            "wire_present_utf8": flags["utf8"],
            "wire_present_utf16le": flags["utf16le"],
            "carved": key in found,
            "mcp_labeled_copy": key in mcp_found,
            "confirmed_scan_miss": exact_present and key not in found,
        })
    summary = scans[0]["summary"]
    return {
        "schema_version": 1,
        "scope": "one current client PID in a Linux x86-64 QEMU physical RAM image",
        "case": case,
        "client_pid": pid,
        "image_sha256": sha256(image),
        "image_bytes": image.stat().st_size,
        "traffic_log_sha256": sha256(traffic),
        "export_sha256": scans[0]["export_sha256"],
        "traffic_messages": len(rows),
        "traffic_distinct_logical_messages": len(truth),
        "wire_present_utf8": sum(row["wire_present_utf8"] for row in per_message),
        "wire_present_utf16le": sum(row["wire_present_utf16le"] for row in per_message),
        "wire_present_any_encoding": sum(row["wire_present_utf8"] or row["wire_present_utf16le"] for row in per_message),
        "carved_logged_messages": sum(row["carved"] for row in per_message),
        "mcp_labeled_logged_messages": sum(row["mcp_labeled_copy"] for row in per_message),
        "confirmed_scan_misses": sum(row["confirmed_scan_miss"] for row in per_message),
        "artifact_records": len(artifacts),
        "artifacts_reread_at_virtual_address": len(artifacts),
        "mcp_candidate_records": sum(bool(row["mcp_candidate"]) for row in artifacts),
        "unmatched_artifact_records": sum(canonical(row["message"]) not in truth for row in artifacts),
        "scan_limits_hit": summary["limits_hit"],
        "scan_candidate_limit_hits": summary["candidate_limit_hits"],
        "scan_unreadable_bytes": summary["unreadable_bytes"],
        "probe_regions_scanned": probe_stats.regions_scanned,
        "probe_unreadable_bytes": probe_stats.unreadable_bytes,
        "messages": per_message,
        "limitations": [
            "Exact-wire presence and carving are scoped to this one readable client process at capture time.",
            "Canonical JSON equality does not identify which memory copy crossed the transport.",
            "The control server and control clients are purpose-built; a few captures do not estimate field rates.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    for name in ("image", "symbols", "cache", "config", "ready", "traffic", "export", "report"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    result = score(case=args.case, image=args.image, symbols=args.symbols,
                   cache=args.cache, config=args.config, ready=args.ready,
                   traffic=args.traffic, export=args.export)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
