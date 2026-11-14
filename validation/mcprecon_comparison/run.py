"""Compare MCPRecon's published CLI with saved MCPTrace results on archived RAM.

Raw images, traffic logs, and both tools' message output stay in the private
evidence directory. The report contains only counts and hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from validation.linux_x64_http_ram.archive import verify_patch_archive


MCPRECON_GIT_BLOB = "5f03a84bc855a69173eedf5a8963c32509a468b5"
MCPRECON_COMMIT = "4811d04e6c6a522759ade5e2f3fef37d33c6c27e"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def score_run(
    evidence: Path, capture: dict, image: Path, output: Path, source: Path,
    *, client_only: bool = False, symbols: Path | None = None, cache: Path | None = None,
) -> dict:
    run_id = capture["run_id"]
    run_dir = evidence / "rerun" / run_id
    prior = json.loads((run_dir / "score.json").read_text(encoding="utf-8"))
    traffic = run_dir / "traffic.jsonl"
    exports = list((run_dir / "exports").glob("mcptrace.pid-*.jsonl"))
    if len(exports) != 1:
        raise ValueError(f"{run_id}: expected one MCPTrace export")
    exported = exports[0]
    if (
        digest(image) != capture["image_sha256"]
        or prior["image_sha256"] != capture["image_sha256"]
        or digest(traffic) != capture["traffic_log_sha256"]
        or digest(exported) != capture["export_sha256"]
    ):
        raise ValueError(f"{run_id}: RAM, traffic, or export hash mismatch")

    truth = [row["message"] for row in lines(traffic)]
    truth_keys = [canonical(row) for row in truth]
    if len(truth_keys) != len(set(truth_keys)) or len(truth) != capture["traffic_messages"]:
        raise ValueError(f"{run_id}: duplicate or inconsistent traffic truth")
    presence = prior["messages"]
    if len(presence) != len(truth):
        raise ValueError(f"{run_id}: inconsistent independent memory probe")
    present = {key for key, row in zip(truth_keys, presence, strict=True)
               if row["wire_present_utf8"] or row["wire_present_utf16le"]}
    if len(present) != capture["wire_present_any_encoding"]:
        raise ValueError(f"{run_id}: memory presence count mismatch")

    trace = [row for row in lines(exported) if row["type"] == "artifact"]
    trace_keys = {canonical(row["message"]) for row in trace}
    if len(trace) != capture["artifact_records"] or len(trace_keys & set(truth_keys)) != capture["carved_logical_messages"]:
        raise ValueError(f"{run_id}: MCPTrace export and saved score disagree")

    scan_input = image
    packed = None
    if client_only:
        if symbols is None or cache is None:
            raise ValueError("client-only comparison needs symbols and cache")
        from validation.mcprecon_comparison.pack_client_memory import pack

        packed = output.with_suffix(".client.bin")
        pid = json.loads((run_dir / "client-ready.json").read_text(encoding="utf-8"))["pid"]
        pack_stats = pack(image, run_dir / "config.json", symbols, cache, pid, packed)
        for key in ("bytes_read", "unreadable_bytes", "regions_scanned"):
            if pack_stats[key] != prior["wire_probe"][key]:
                raise ValueError(f"{run_id}: packed client memory differs in {key}")
        scan_input = packed
    try:
        with output.open("w", encoding="utf-8") as result, (output.with_suffix(".stderr")).open("w", encoding="utf-8") as errors:
            started = time.monotonic()
            subprocess.run(
                [sys.executable, str(source), str(scan_input), "--quiet", "--emit-raw",
                 "--temp-dir", str(output.parent / "temp")],
                stdout=result, stderr=errors, check=True,
            )
            elapsed = time.monotonic() - started

        recon = lines(output)
        recon_keys = {canonical(row["json"]) for row in recon}
        matched = recon_keys & set(truth_keys)
        bytes_verified = 0
        with scan_input.open("rb") as stream:
            for row in recon:
                raw = row["raw"].encode("utf-8")
                stream.seek(row["offset"])
                bytes_verified += stream.read(len(raw)) == raw
    finally:
        if packed is not None:
            packed.unlink(missing_ok=True)
    return {
        "run_id": run_id,
        "case": capture["case"],
        "image_sha256": capture["image_sha256"],
        "traffic_messages": len(truth),
        "exact_wire_present_in_client_memory": len(present),
        "mcptrace_truth_messages": len(trace_keys & set(truth_keys)),
        "mcptrace_truth_present_in_client_memory": len(trace_keys & present),
        "mcprecon_truth_messages": len(matched),
        "mcprecon_truth_present_in_client_memory": len(matched & present),
        "mcprecon_record_count": len(recon),
        "mcprecon_distinct_messages": len(recon_keys),
        "mcprecon_unmatched_records": sum(canonical(row["json"]) not in truth_keys for row in recon),
        "mcprecon_file_offset_bytes_verified": bytes_verified,
        "mcprecon_flagged_mcp_records": sum(bool(row["mcp"]) for row in recon),
        "mcprecon_elapsed_seconds": round(elapsed, 3),
        "client_packed_bytes": pack_stats["packed_bytes"] if client_only else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--mcprecon", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runs", nargs="*")
    parser.add_argument("--client-only", action="store_true")
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    source = args.mcprecon.resolve()
    source_bytes = source.read_bytes()
    git_blob = hashlib.sha1(f"blob {len(source_bytes)}\0".encode() + source_bytes).hexdigest()
    if git_blob != MCPRECON_GIT_BLOB:
        raise ValueError("MCPRecon source differs from pinned public Git blob")
    manifest = json.loads((evidence.parent / "MCPTrace" / "validation" / "linux_x64_http_ram" / "results" / "2026-11-14-qemu-http-sdk-rerun.json").read_text(encoding="utf-8"))
    captures = [item for item in manifest["captures"] if not args.runs or item["run_id"] in args.runs]
    if args.runs and len(captures) != len(set(args.runs)):
        raise ValueError("unknown run or duplicate run id")
    base = evidence / "node-d0-r1-ram.elf"
    if digest(base) != manifest["captures"][0]["image_sha256"]:
        raise ValueError("base RAM hash mismatch")
    private_output = evidence / ("mcprecon-comparison-client" if args.client_only else "mcprecon-comparison")
    private_output.mkdir(exist_ok=True)
    results = []
    for capture in captures:
        run_id = capture["run_id"]
        print(f"comparing {run_id}", file=sys.stderr, flush=True)
        if run_id == "node-d0-r1":
            image = base
            results.append(score_run(evidence, capture, image, private_output / f"{run_id}.jsonl", source,
                                     client_only=args.client_only, symbols=args.symbols, cache=args.cache))
            continue
        archive = evidence / "assets" / capture["ram_archive"]["name"]
        if digest(archive) != capture["ram_archive"]["sha256"]:
            raise ValueError(f"{run_id}: archive hash mismatch")
        with tempfile.TemporaryDirectory(dir=evidence) as temp_dir:
            image = Path(temp_dir) / "ram.elf"
            with image.open("wb") as stream:
                verify_patch_archive(base, archive, capture["image_sha256"],
                                     manifest["captures"][0]["image_sha256"], stream)
            results.append(score_run(evidence, capture, image, private_output / f"{run_id}.jsonl", source,
                                     client_only=args.client_only, symbols=args.symbols, cache=args.cache))

    by_case = defaultdict(lambda: defaultdict(int))
    for row in results:
        for group in (row["case"], "total"):
            by_case[group]["captures"] += 1
            for key in ("traffic_messages", "exact_wire_present_in_client_memory",
                        "mcptrace_truth_messages", "mcptrace_truth_present_in_client_memory",
                        "mcprecon_truth_messages", "mcprecon_truth_present_in_client_memory",
                        "mcprecon_record_count", "mcprecon_distinct_messages",
                        "mcprecon_unmatched_records", "mcprecon_file_offset_bytes_verified",
                        "mcprecon_flagged_mcp_records"):
                by_case[group][key] += row[key]
    report = {
        "schema_version": 1,
        "scope": ("MCPRecon default CLI over a derived stream of the same client's readable VMAs versus saved MCPTrace client-PID exports"
                  if args.client_only else
                  "MCPRecon default CLI over whole ELF RAM versus saved MCPTrace client-PID exports on the same images"),
        "mcprecon_commit": MCPRECON_COMMIT,
        "mcprecon_source_git_blob": MCPRECON_GIT_BLOB,
        "mcptrace_commit": "ded4c00235f5c41222f72e8529f3dbd617bc3c9f",
        "captures": results,
        "by_case": by_case,
        "limitations": [
            ("MCPRecon scans a derived concatenation of the client's readable VMA chunks with 64 KiB NUL separators. This changes layout and file offsets; it is not MCPRecon's original whole-image workflow."
             if args.client_only else
             "MCPRecon scans the whole raw ELF file; MCPTrace scans one client PID's readable VMAs. Coverage and unmatched records are not a controlled precision comparison."),
            ("A truth-matching memory copy is not by itself proof of transmission; the separate server log establishes transmission in this fixture."
             if args.client_only else
             "A truth message found by MCPRecon anywhere in RAM is not automatically attributed to the client process or proven transmitted by that copy."),
            "MCPTrace outputs were generated earlier on the exact same images and were checked against saved hashes; they were not rerun during this comparison.",
            "Exact-wire memory presence is measured only in the client VMAs. The denominator is not all transmitted messages or all possible memory serializations.",
            "MCPRecon uses default CLI keywords and 16 KiB window with --emit-raw for byte checking; tuning has not been evaluated.",
        ],
    }
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
