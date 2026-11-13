"""Score one SDK client RAM image against bytes logged by a separate stdio proxy."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from volatility3.framework import exceptions

from mcptrace.core import ScanStats, strict_loads
from mcptrace.memory import readable_chunks
from validation.linux_x64_positive.score import canonical, process_context, sha256, verify_exports


def read_wire(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        row = json.loads(line)
        raw = base64.b64decode(row["raw_base64"], validate=True)
        if hashlib.sha256(raw).hexdigest() != row["raw_sha256"] or canonical(
            strict_loads(raw.decode("utf-8"))
        ) != canonical(row["message"]):
            raise ValueError(f"wire log row {number} is inconsistent")
        rows.append({"direction": row["direction"], "raw": raw, "message": row["message"]})
    if not rows:
        raise ValueError("empty wire log")
    return rows


def probe_wire(
    pid: int, rows: list[dict], symbols: Path, cache: Path, config: Path
) -> tuple[list[dict], ScanStats]:
    patterns = []
    for index, row in enumerate(rows):
        patterns.append((index, "utf-8", row["raw"]))
        patterns.append((index, "utf-16-le", row["raw"].decode("utf-8").encode("utf-16-le")))
    longest = max(len(raw) for _, _, raw in patterns)
    hits: set[tuple[int, str]] = set()
    stats = ScanStats()
    with process_context(symbols, cache, config) as (context, processes, _):
        if pid not in processes:
            raise ValueError("SDK client PID absent from pslist")
        task = processes[pid]
        layer = context.layers[task.add_process_layer()]
        for vma in task.mm.get_vma_iter():
            start, end = int(vma.vm_start), int(vma.vm_end)
            if end <= start:
                stats.invalid_regions += 1
                continue
            stats.regions_scanned += 1
            tail = b""
            previous_end = None
            for address, data in readable_chunks(
                layer, start, end - start, stats, exceptions.InvalidAddressException
            ):
                if previous_end != address:
                    tail = b""
                window = tail + data
                for index, encoding, raw in patterns:
                    if (index, encoding) not in hits and raw in window:
                        hits.add((index, encoding))
                tail = window[-longest + 1 :] if longest > 1 else b""
                previous_end = address + len(data)
    presence = [
        {"utf8": (index, "utf-8") in hits, "utf16le": (index, "utf-16-le") in hits}
        for index in range(len(rows))
    ]
    return presence, stats


def score(
    *,
    image: Path,
    symbols: Path,
    cache: Path,
    config: Path,
    ready: Path,
    wire: Path,
    export: Path,
    requested_delay: int,
    observed_delay: float,
) -> dict:
    metadata = json.loads(ready.read_text(encoding="utf-8"))
    rows = read_wire(wire)
    artifacts, scans = verify_exports([export], symbols, cache, config)
    if scans[0]["pid"] != metadata["client_pid"]:
        raise ValueError("ready PID differs from scanned PID")
    found = {canonical(record["message"]) for record in artifacts}
    presence, probe_stats = probe_wire(metadata["client_pid"], rows, symbols, cache, config)
    messages = []
    for row, present in zip(rows, presence, strict=True):
        carved = canonical(row["message"]) in found
        messages.append(
            {
                "direction": row["direction"],
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
        "scope": "one official Python SDK client in Linux x86-64 physical RAM",
        "run_id": metadata["run_id"],
        "mcp_sdk": metadata["mcp_sdk"],
        "client_frame_journal": metadata["frame_journal_in_client"],
        "requested_delay_seconds": requested_delay,
        "observed_ready_detection_to_pause_seconds": observed_delay,
        "image_sha256": sha256(image),
        "image_bytes": image.stat().st_size,
        "wire_log_sha256": sha256(wire),
        "export_sha256": scans[0]["export_sha256"],
        "artifact_records": len(artifacts),
        "artifacts_reread_at_virtual_address": len(artifacts),
        "unmatched_artifact_records": unmatched,
        "wire_messages": len(rows),
        "wire_present_utf8": sum(row["wire_present_utf8"] for row in messages),
        "wire_present_utf16le": sum(row["wire_present_utf16le"] for row in messages),
        "carved_logical_messages": sum(row["carved_logical_message"] for row in messages),
        "confirmed_scan_misses": sum(row["confirmed_scan_miss"] for row in messages),
        "scan_summary": summary,
        "wire_probe": vars(probe_stats),
        "messages": messages,
        "interpretation": (
            "Wire payloads were logged by a separate proxy, not retained by the SDK client. "
            "An absent exact wire payload does not prove no differently serialized copy existed. "
            "A carved message is a memory candidate, not proof of execution. "
            "Repeated scans of one image are not independent observations."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "symbols", "cache", "config", "ready", "wire", "export", "report"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--requested-delay", type=int, required=True)
    parser.add_argument("--observed-delay", type=float, required=True)
    args = parser.parse_args()
    result = score(
        image=args.image,
        symbols=args.symbols,
        cache=args.cache,
        config=args.config,
        ready=args.ready,
        wire=args.wire,
        export=args.export,
        requested_delay=args.requested_delay,
        observed_delay=args.observed_delay,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
