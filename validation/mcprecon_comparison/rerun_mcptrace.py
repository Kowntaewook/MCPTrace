"""Re-execute the pinned MCPTrace plugin on archived Linux physical RAM.

Reconstruct one image at a time, verify its SHA-256, and reread every new
artifact at its process virtual address. Raw RAM and exports stay private.
The report contains only counts, hashes, and timing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from validation.linux_x64_http_ram.archive import CHUNK_BYTES, verify_patch_archive
from validation.linux_x64_positive.score import verify_exports
from validation.mcprecon_comparison.run import canonical, digest, lines


ROOT = Path(__file__).resolve().parents[2]
PINNED_COMMIT = "ded4c00235f5c41222f72e8529f3dbd617bc3c9f"
MANIFEST = ROOT / "validation/linux_x64_http_ram/results/2026-11-14-qemu-http-sdk-rerun.json"


def prepare_compressed_base(asset: Path, expected_sha256: str,
                            image_bytes: int, work: Path) -> Path:
    """Verify the base once and keep bounded compressed parts, not a 2 GiB file."""
    parts = work / "base-parts"
    parts.mkdir()
    whole = hashlib.sha256()
    count = 0
    with subprocess.Popen(["zstd", "-q", "-d", "-c", str(asset)],
                          stdout=subprocess.PIPE) as decoder:
        assert decoder.stdout is not None
        while True:
            chunk = bytearray()
            while len(chunk) < CHUNK_BYTES:
                data = decoder.stdout.read(min(4 * 1024 * 1024, CHUNK_BYTES - len(chunk)))
                if not data:
                    break
                chunk.extend(data)
            if not chunk:
                break
            whole.update(chunk)
            with (parts / f"part-{count:02d}.zst").open("wb") as encoded:
                subprocess.run(["zstd", "-q", "-3", "-c"], input=chunk,
                               stdout=encoded, check=True, timeout=600)
            count += 1
        if decoder.wait(timeout=600) != 0:
            raise ValueError("compressed base could not be decoded")
    if whole.hexdigest() != expected_sha256 or count != (image_bytes + CHUNK_BYTES - 1) // CHUNK_BYTES:
        raise ValueError("compressed base RAM SHA-256 or part count mismatch")
    (parts / "manifest.json").write_text(json.dumps({"chunk_bytes": CHUNK_BYTES,
                                                    "image_bytes": image_bytes}) + "\n", encoding="utf-8")
    return parts


def check_source() -> None:
    subprocess.run(
        ["git", "diff", "--quiet", PINNED_COMMIT, "--", "mcptrace", "plugins"],
        cwd=ROOT, check=True,
    )
    actual = subprocess.check_output(
        ["git", "rev-parse", PINNED_COMMIT], cwd=ROOT, text=True,
    ).strip()
    if actual != PINNED_COMMIT:
        raise ValueError("pinned MCPTrace commit is unavailable")


def execute_one(capture: dict, image: Path, evidence: Path, symbols: Path,
                cache: Path, vol: Path, work: Path) -> dict:
    run_id = capture["run_id"]
    original_dir = evidence / "rerun" / run_id
    original_score = json.loads((original_dir / "score.json").read_text(encoding="utf-8"))
    original_exports = list((original_dir / "exports").glob("mcptrace.pid-*.jsonl"))
    if len(original_exports) != 1:
        raise ValueError(f"{run_id}: expected one saved export")
    original_export = original_exports[0]
    traffic = original_dir / "traffic.jsonl"
    if (original_score["image_sha256"] != capture["image_sha256"]
            or digest(traffic) != capture["traffic_log_sha256"]
            or digest(original_export) != capture["export_sha256"]):
        raise ValueError(f"{run_id}: saved image, traffic, or export hash mismatch")
    pid = json.loads((original_dir / "client-ready.json").read_text(encoding="utf-8"))["pid"]

    exports_dir = work / "exports"
    exports_dir.mkdir()
    config = work / "config.json"
    stdout = work / "vol-stdout.txt"
    stderr = work / "vol-stderr.txt"
    command = [
        str(vol), "-q", "--cache-path", str(cache), "-s", str(symbols),
        "-p", str(ROOT / "plugins"), "-f", str(image), "-o", str(exports_dir),
        "--save-config", str(config), "linux.mcptrace.MCPTrace",
        "--pid", str(pid), "--include-rpc", "--dump",
    ]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT)
    started = time.monotonic()
    with stdout.open("w", encoding="utf-8") as out, stderr.open("w", encoding="utf-8") as err:
        subprocess.run(command, cwd=ROOT, env=environment, stdout=out, stderr=err,
                       check=True, timeout=600)
    elapsed = time.monotonic() - started

    output = exports_dir / f"mcptrace.pid-{pid}.jsonl"
    if not output.is_file():
        raise ValueError(f"{run_id}: expected new export is missing")
    artifacts, scans = verify_exports([output], symbols, cache, config)
    if scans[0]["pid"] != pid:
        raise ValueError(f"{run_id}: rerun scanned a different PID")
    expected_rows = lines(original_export)
    actual_rows = lines(output)
    exact_export = digest(output) == capture["export_sha256"]
    if not exact_export and actual_rows != expected_rows:
        raise ValueError(f"{run_id}: new export differs from the saved export")

    traffic_rows = lines(traffic)
    truth = {canonical(row["message"]) for row in traffic_rows}
    if len(traffic_rows) != capture["traffic_messages"] or len(truth) != len(traffic_rows):
        raise ValueError(f"{run_id}: inconsistent traffic truth")
    probe = original_score["messages"]
    if len(probe) != len(traffic_rows):
        raise ValueError(f"{run_id}: inconsistent original wire probe")
    present = {canonical(row["message"]) for row, flag in zip(traffic_rows, probe, strict=True)
               if flag["wire_present_utf8"] or flag["wire_present_utf16le"]}
    found = {canonical(row["message"]) for row in artifacts}
    if (len(artifacts) != capture["artifact_records"]
            or len(found & truth) != capture["carved_logical_messages"]
            or len(present) != capture["wire_present_any_encoding"]):
        raise ValueError(f"{run_id}: rerun counts differ from manifest")
    return {
        "run_id": run_id,
        "case": capture["case"],
        "requested_delay_seconds": capture["requested_delay_seconds"],
        "image_sha256": capture["image_sha256"],
        "saved_export_sha256": capture["export_sha256"],
        "rerun_export_sha256": digest(output),
        "exact_export_reproduced": exact_export,
        "traffic_messages": len(truth),
        "wire_present": len(present),
        "rerun_artifact_records": len(artifacts),
        "rerun_artifacts_reread_at_virtual_address": len(artifacts),
        "rerun_distinct_truth_messages": len(found & truth),
        "rerun_present_truth_messages": len(found & present),
        "rerun_truth_messages_outside_exact_wire_set": len((found & truth) - present),
        "rerun_unmatched_artifact_records": sum(canonical(row["message"]) not in truth for row in artifacts),
        "rerun_mcp_candidate_records": sum(bool(row["mcp_candidate"]) for row in artifacts),
        "scan_limits_hit": scans[0]["summary"]["limits_hit"],
        "elapsed_seconds": round(elapsed, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "symbols", "cache", "vol", "report"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--runs", nargs="*")
    parser.add_argument("--checkpoint", type=Path,
                        help="Private numeric progress file; verified completed runs are resumed")
    args = parser.parse_args()
    check_source()
    evidence = args.evidence.resolve()
    symbols = args.symbols.resolve()
    cache = args.cache.resolve()
    vol = args.vol.resolve()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    captures = [row for row in manifest["captures"]
                if not args.runs or row["run_id"] in args.runs]
    if args.runs and len(captures) != len(set(args.runs)):
        raise ValueError("unknown or duplicate run ID")
    base_capture = manifest["captures"][0]
    base_asset = evidence / "assets" / base_capture["ram_archive"]["name"]
    if digest(base_asset) != base_capture["ram_archive"]["sha256"]:
        raise ValueError("compressed base asset hash mismatch")

    completed = {}
    if args.checkpoint and args.checkpoint.is_file():
        prior_progress = json.loads(args.checkpoint.read_text(encoding="utf-8"))
        if prior_progress.get("mcptrace_commit") != PINNED_COMMIT:
            raise ValueError("checkpoint used a different MCPTrace commit")
        completed = {row["run_id"]: row for row in prior_progress["captures"]}
    known = {row["run_id"]: row for row in manifest["captures"]}
    for run_id, row in completed.items():
        if (run_id not in known or row["image_sha256"] != known[run_id]["image_sha256"]
                or not row["exact_export_reproduced"]
                or row["rerun_artifact_records"] != known[run_id]["artifact_records"]):
            raise ValueError(f"{run_id}: unusable checkpoint result")

    def save_checkpoint() -> None:
        if args.checkpoint is None:
            return
        args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        partial = args.checkpoint.with_suffix(".partial")
        partial.write_text(json.dumps({"mcptrace_commit": PINNED_COMMIT,
                                       "captures": list(completed.values())}, indent=2) + "\n", encoding="utf-8")
        partial.replace(args.checkpoint)

    with tempfile.TemporaryDirectory(dir=evidence, prefix="mcptrace-rerun-") as name:
        work = Path(name)
        base = prepare_compressed_base(base_asset, base_capture["image_sha256"],
                                       base_capture["image_bytes"], work)
        for capture in captures:
            run_id = capture["run_id"]
            if run_id in completed:
                print(f"already verified {run_id}", file=sys.stderr, flush=True)
                continue
            print(f"rerunning {run_id}", file=sys.stderr, flush=True)
            with tempfile.TemporaryDirectory(dir=work, prefix=f"{run_id}-") as run_name:
                run_work = Path(run_name)
                if run_id == base_capture["run_id"]:
                    image = run_work / "ram.elf"
                    with image.open("wb") as stream:
                        subprocess.run(["zstd", "-q", "-d", "-c", str(base_asset)],
                                       stdout=stream, check=True, timeout=600)
                    if digest(image) != capture["image_sha256"]:
                        raise ValueError("decompressed base RAM hash mismatch")
                else:
                    asset = evidence / "assets" / capture["ram_archive"]["name"]
                    if digest(asset) != capture["ram_archive"]["sha256"]:
                        raise ValueError(f"{run_id}: patch asset hash mismatch")
                    image = run_work / "ram.elf"
                    with image.open("wb") as stream:
                        verify_patch_archive(base, asset, capture["image_sha256"],
                                             base_capture["image_sha256"], stream)
                completed[run_id] = execute_one(capture, image, evidence, symbols, cache,
                                                vol, run_work)
                save_checkpoint()

    results = [completed[row["run_id"]] for row in captures]
    totals = defaultdict(int)
    for row in results:
        for key in ("traffic_messages", "wire_present", "rerun_artifact_records",
                    "rerun_artifacts_reread_at_virtual_address", "rerun_distinct_truth_messages",
                    "rerun_present_truth_messages", "rerun_truth_messages_outside_exact_wire_set",
                    "rerun_unmatched_artifact_records", "rerun_mcp_candidate_records"):
            totals[key] += row[key]
    report = {
        "schema_version": 1,
        "scope": "Pinned MCPTrace re-execution on hash-verified archived Linux x86-64 physical RAM; one client PID per image",
        "mcptrace_commit": PINNED_COMMIT,
        "captures": results,
        "totals": {"captures": len(results), "exact_exports_reproduced": sum(row["exact_export_reproduced"] for row in results),
                   "captures_with_scan_limits": sum(bool(row["scan_limits_hit"]) for row in results), **totals},
        "limitations": [
            "The original exact-wire probe and traffic logs are hash checked but not newly captured.",
            "A logical match uses canonical JSON equality; a carved copy is not proof that that copy crossed the transport.",
            "The 27 images are from a controlled Node/.NET SDK HTTP/SSE fixture, not a population sample.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
