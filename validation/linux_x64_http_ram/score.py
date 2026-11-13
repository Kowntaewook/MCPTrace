"""Score one HTTP/SSE SDK client in a QEMU physical RAM capture."""

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


def read_traffic(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        row = json.loads(line)
        raw = base64.b64decode(row["wire_base64"], validate=True)
        if not raw or canonical(strict_loads(raw.decode("utf-8"))) != canonical(row["message"]):
            raise ValueError(f"traffic row {number} has inconsistent wire bytes")
        if row["direction"] not in ("client-to-server", "server-to-client") or row[
            "framing"
        ] not in ("json", "sse"):
            raise ValueError(f"traffic row {number} has invalid direction or framing")
        rows.append({"raw": raw, **row})
    if not rows:
        raise ValueError("empty HTTP traffic log")
    return rows


def score(
    *,
    case: str,
    image: Path,
    symbols: Path,
    cache: Path,
    config: Path,
    ready: Path,
    traffic: Path,
    export: Path,
    requested_delay: int,
    observed_delay: float,
    detection_bound: float,
) -> dict:
    if case not in ("node", "dotnet-legacy", "dotnet-modern"):
        raise ValueError(f"unsupported case: {case}")
    configuration = json.loads(config.read_text(encoding="utf-8"))
    locations = [
        value
        for key, value in configuration.items()
        if key.endswith(".memory_layer.base_layer.location")
    ]
    configured = Path(unquote(urlparse(locations[0]).path)).resolve() if locations else None
    if len(locations) != 1 or configured != image.resolve():
        raise ValueError("saved Volatility config refers to another RAM image")
    metadata = json.loads(ready.read_text(encoding="utf-8"))
    rows = read_traffic(traffic)
    artifacts, scans = verify_exports([export], symbols, cache, config)
    if scans[0]["pid"] != metadata["pid"]:
        raise ValueError("client-ready PID differs from scanned PID")
    found = {canonical(record["message"]) for record in artifacts}
    presence, probe_stats = probe_wire(metadata["pid"], rows, symbols, cache, config)
    messages = []
    for row, present in zip(rows, presence, strict=True):
        carved = canonical(row["message"]) in found
        messages.append(
            {
                "direction": row["direction"],
                "framing": row["framing"],
                "wire_sha256": hashlib.sha256(row["raw"]).hexdigest(),
                "method": row["message"].get("method", ""),
                "wire_present_utf8": present["utf8"],
                "wire_present_utf16le": present["utf16le"],
                "carved_logical_message": carved,
                "confirmed_scan_miss": (present["utf8"] or present["utf16le"]) and not carved,
            }
        )
    expected = {canonical(row["message"]) for row in rows}
    unmatched = sum(canonical(record["message"]) not in expected for record in artifacts)
    summary = scans[0]["summary"]
    return {
        "schema_version": 1,
        "scope": "one Node or .NET HTTP/SSE client in Linux x86-64 physical RAM",
        "case": case,
        "client_marker": metadata["marker"],
        "requested_delay_seconds": requested_delay,
        "observed_ready_detection_to_pause_seconds": observed_delay,
        "client_launch_to_readiness_detection_upper_bound_seconds": detection_bound,
        "image_sha256": sha256(image),
        "image_bytes": image.stat().st_size,
        "traffic_log_sha256": sha256(traffic),
        "export_sha256": scans[0]["export_sha256"],
        "artifact_records": len(artifacts),
        "artifacts_reread_at_virtual_address": len(artifacts),
        "mcp_candidate_records": sum(record["mcp_candidate"] for record in artifacts),
        "unmatched_artifact_records": unmatched,
        "traffic_messages": len(rows),
        "sse_response_messages": sum(
            row["direction"] == "server-to-client" and row["framing"] == "sse" for row in rows
        ),
        "wire_present_utf8": sum(row["wire_present_utf8"] for row in messages),
        "wire_present_utf16le": sum(row["wire_present_utf16le"] for row in messages),
        "carved_logical_messages": sum(row["carved_logical_message"] for row in messages),
        "confirmed_scan_misses": sum(row["confirmed_scan_miss"] for row in messages),
        "scan_summary": summary,
        "wire_probe": vars(probe_stats),
        "messages": messages,
        "interpretation": (
            "The HTTP server logged payloads outside the SDK client process. "
            "Absent exact wire bytes do not rule out other serializations. "
            "A carved object is not proof of transmission or execution."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    for name in ("image", "symbols", "cache", "config", "ready", "traffic", "export", "report"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--requested-delay", type=int, required=True)
    parser.add_argument("--observed-delay", type=float, required=True)
    parser.add_argument("--detection-bound", type=float, required=True)
    args = parser.parse_args()
    result = score(
        case=args.case,
        image=args.image,
        symbols=args.symbols,
        cache=args.cache,
        config=args.config,
        ready=args.ready,
        traffic=args.traffic,
        export=args.export,
        requested_delay=args.requested_delay,
        observed_delay=args.observed_delay,
        detection_bound=args.detection_bound,
    )
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
