"""Independently rescan the archived full RAM for the 20 planned repeats.

The two private capture roots need only contain each run's ram.elf.zst and,
for Codex, traffic.jsonl. Temporary ELF images and raw scanner exports are
removed after each serial replay. Only numeric/hash results may be written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from validation.linux_x64_real_host_ram.ground_truth.replay import hash_file, restore
from validation.linux_x64_real_host_ram.score import read_traffic, score
from validation.linux_x64_repeat.ground_truth.prepare_public import (
    RUNS as FIRST_PUBLIC_RUNS,
    audit as audit_public_journal,
)
from validation.linux_x64_repeat.ground_truth.prepare_public_same_cell import (
    RUNS as SECOND_PUBLIC_RUNS,
)


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SUMMARY = HERE.parent / "results/2026-11-16-same-cell-summary.json"
PINNED_SCANNER = "ded4c00235f5c41222f72e8529f3dbd617bc3c9f"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_wire_journal(path: Path, report: dict, run_id: str) -> None:
    data = path.read_bytes()
    if digest(data) != report["traffic_log_sha256"]:
        raise ValueError(f"{run_id}: journal SHA-256 differs")
    if run_id in FIRST_PUBLIC_RUNS or run_id in SECOND_PUBLIC_RUNS:
        if run_id in FIRST_PUBLIC_RUNS:
            marker = FIRST_PUBLIC_RUNS[run_id][1]
        else:
            marker = SECOND_PUBLIC_RUNS[run_id]
        audit_public_journal(data, report, marker)
        return
    if report["case"] != "codex-stdio":
        raise ValueError(f"{run_id}: no public journal or private Codex case")
    rows = read_traffic(path)
    if len(rows) != report["traffic_messages"]:
        raise ValueError(f"{run_id}: private Codex journal row count differs")
    for row, expected in zip(rows, report["messages"], strict=True):
        if (digest(row["raw"]) != expected["raw_sha256"]
                or row["direction"] != expected["direction"]
                or row["framing"] != expected["framing"]
                or row["message"].get("method", "") != expected["method"]):
            raise ValueError(f"{run_id}: private Codex journal message differs")


def rescan(run: dict, args: argparse.Namespace) -> dict:
    run_id = run["run_id"]
    report_path = ROOT / "validation/linux_x64_repeat" / run["report"]
    reference = json.loads(report_path.read_text())
    if (reference["run_id"] != run_id or reference["case"] != run["case"]
            or reference["image_sha256"] != run["image_sha256"]
            or reference["private_ram_archive_sha256"] != run["archive_sha256"]
            or reference["traffic_log_sha256"] != run["traffic_sha256"]
            or reference["client_pid"] != run["client_pid"]):
        raise ValueError(f"{run_id}: public summary and report differ")
    captures = (args.first_captures if run["phase"] == "initial"
                else args.second_captures)
    capture = captures / run_id
    archive = capture / "ram.elf.zst"
    if (archive.stat().st_size != reference["private_ram_archive_bytes"]
            or hash_file(archive) != reference["private_ram_archive_sha256"]):
        raise ValueError(f"{run_id}: original RAM archive differs")
    traffic = (capture / "traffic.jsonl" if run["case"] == "codex-stdio"
               else HERE / "traffic" / f"{run_id}.jsonl")
    check_wire_journal(traffic, reference, run_id)
    required = reference["image_bytes"] + 256 * 1024 * 1024
    free = shutil.disk_usage(args.scratch).free
    # APFS may reclaim the previous temporary ELF asynchronously after its
    # directory is removed. Give it a short chance before declaring low space.
    for _ in range(12):
        if free >= required:
            break
        time.sleep(5)
        free = shutil.disk_usage(args.scratch).free
    if free < required:
        raise OSError(f"{run_id}: scratch needs {required:,} free bytes; has {free:,}")
    with tempfile.TemporaryDirectory(prefix=f"mcptrace-repeat-{run_id}-",
                                     dir=args.scratch) as temporary:
        work = Path(temporary)
        image = work / "ram.elf"
        restore(archive, image, reference["image_sha256"], reference["image_bytes"])
        exports = work / "exports"
        exports.mkdir()
        config = work / "config.json"
        ready = work / "client-ready.json"
        ready.write_text(json.dumps({"pid": reference["client_pid"]}))
        command = [str(args.vol.resolve()), "-q", "--cache-path", str(args.cache.resolve()),
                   "-s", str(args.symbols.resolve()), "-p", str(ROOT / "plugins"),
                   "-f", str(image), "-o", str(exports), "--save-config", str(config),
                   "linux.mcptrace.MCPTrace", "--pid", str(reference["client_pid"]),
                   "--include-rpc", "--dump"]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT)
        with (work / "vol-stdout.txt").open("w") as stdout, \
                (work / "vol-stderr.txt").open("w") as stderr:
            for attempt in range(3):
                try:
                    subprocess.run(command, cwd=ROOT, env=environment, check=True,
                                   timeout=1800, stdout=stdout, stderr=stderr)
                    break
                except TimeoutError:
                    # A transient APFS executable-open timeout happens before
                    # Volatility starts; a scanner failure is never retried.
                    if attempt == 2:
                        raise
                    time.sleep(5)
                except subprocess.CalledProcessError as error:
                    stderr.flush()
                    stdout.flush()
                    failure_dir = args.scratch / "failed-replay-logs"
                    failure_dir.mkdir(exist_ok=True)
                    shutil.copyfile(work / "vol-stderr.txt",
                                    failure_dir / f"{run_id}.stderr.txt")
                    shutil.copyfile(work / "vol-stdout.txt",
                                    failure_dir / f"{run_id}.stdout.txt")
                    raise RuntimeError(
                        f"{run_id}: Volatility exited {error.returncode}; "
                        f"private diagnostics saved under {failure_dir}") from error
        export = exports / f"mcptrace.pid-{reference['client_pid']}.jsonl"
        measured = score(case=reference["case"], image=image,
                         symbols=args.symbols, cache=args.cache, config=config,
                         ready=ready, traffic=traffic, export=export)
        fields = set(measured) - {"limitations"}
        differences = {field for field in fields
                       if field not in reference or measured[field] != reference[field]}
        if differences:
            raise ValueError(f"{run_id}: replay differs in {', '.join(sorted(differences))}")
        return {
            "run_id": run_id,
            "phase": run["phase"],
            "case": reference["case"],
            "timing": run["timing"],
            "matches_published_score": True,
            "report_sha256": hash_file(report_path),
            "archive_sha256": reference["private_ram_archive_sha256"],
            "image_sha256": reference["image_sha256"],
            "traffic_sha256": reference["traffic_log_sha256"],
            "fresh_export_sha256": measured["export_sha256"],
            "client_pid": reference["client_pid"],
            "traffic_messages": measured["traffic_messages"],
            "wire_present_any_encoding": measured["wire_present_any_encoding"],
            "carved_logged_messages": measured["carved_logged_messages"],
            "mcp_labeled_logged_messages": measured["mcp_labeled_logged_messages"],
            "artifact_records": measured["artifact_records"],
            "confirmed_scan_misses": measured["confirmed_scan_misses"],
            "unmatched_artifact_records": measured["unmatched_artifact_records"],
            "scan_limits_hit": measured["scan_limits_hit"],
            "per_message_flags_checked": len(measured["messages"]),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first-captures", required=True, type=Path)
    parser.add_argument("--second-captures", required=True, type=Path)
    parser.add_argument("--symbols", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--vol", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--checkpoint", type=Path,
                        help="Private resumable progress file, written after each verified image")
    parser.add_argument("--run-id", help="Replay one named image for a spot check")
    args = parser.parse_args()
    source = subprocess.run(
        ["git", "diff", "--quiet", PINNED_SCANNER, "--", "mcptrace", "plugins"],
        cwd=ROOT, check=False)
    if source.returncode != 0:
        raise ValueError("scanner source differs from pinned capture commit")
    summary = json.loads(SUMMARY.read_text())
    runs = summary["runs"]
    if summary["primary_images"] != 20 or len(runs) != 20:
        raise ValueError("expected twenty planned images in public summary")
    if len({run["run_id"] for run in runs}) != 20:
        raise ValueError("duplicate public run ID")
    if args.run_id:
        runs = [run for run in runs if run["run_id"] == args.run_id]
        if not runs:
            parser.error("--run-id is absent from the 20-image primary summary")
    if args.run_id and args.checkpoint:
        parser.error("--checkpoint is only for a full 20-image replay")
    args.scratch.mkdir(parents=True, exist_ok=True)
    summary_hash = hash_file(SUMMARY)
    completed = {}
    if args.checkpoint and args.checkpoint.exists():
        checkpoint = json.loads(args.checkpoint.read_text())
        if (checkpoint.get("scanner_source_commit") != PINNED_SCANNER
                or checkpoint.get("summary_sha256") != summary_hash):
            raise ValueError("checkpoint belongs to a different scanner or summary")
        for row in checkpoint["completed"]:
            run = next((item for item in runs if item["run_id"] == row["run_id"]), None)
            if run is None or row["run_id"] in completed:
                raise ValueError("checkpoint has an unknown or duplicate run")
            reference_path = ROOT / "validation/linux_x64_repeat" / run["report"]
            reference = json.loads(reference_path.read_text())
            if (row["report_sha256"] != hash_file(reference_path)
                    or row["phase"] != run["phase"]
                    or row["case"] != run["case"]
                    or row["timing"] != run["timing"]
                    or row["archive_sha256"] != run["archive_sha256"]
                    or row["image_sha256"] != run["image_sha256"]
                    or row["traffic_sha256"] != run["traffic_sha256"]
                    or row["client_pid"] != run["client_pid"]
                    or row["matches_published_score"] is not True
                    or any(row[field] != reference[field] for field in (
                        "traffic_messages", "wire_present_any_encoding",
                        "carved_logged_messages", "mcp_labeled_logged_messages",
                        "artifact_records", "confirmed_scan_misses",
                        "unmatched_artifact_records", "scan_limits_hit"))):
                raise ValueError("checkpoint verification differs from published report")
            completed[row["run_id"]] = row
    results = []
    for index, run in enumerate(runs, 1):
        run_id = run["run_id"]
        if run_id in completed:
            print(f"Using verified checkpoint {index}/{len(runs)} {run_id}", flush=True)
            results.append(completed[run_id])
            continue
        print(f"Replaying {index}/{len(runs)} {run_id}...", flush=True)
        result = rescan(run, args)
        results.append(result)
        if args.checkpoint:
            args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
            checkpoint = {"schema_version": 1,
                          "scanner_source_commit": PINNED_SCANNER,
                          "summary_sha256": summary_hash,
                          "completed": results}
            temporary = args.checkpoint.with_name(args.checkpoint.name + ".tmp")
            temporary.write_text(json.dumps(checkpoint, indent=2) + "\n")
            temporary.replace(args.checkpoint)
    totals = {field: sum(row[field] for row in results)
              for field in ("traffic_messages", "wire_present_any_encoding",
                            "carved_logged_messages", "mcp_labeled_logged_messages",
                            "artifact_records", "confirmed_scan_misses",
                            "unmatched_artifact_records")}
    if not args.run_id:
        expected = summary["totals"]
        for field in ("traffic_messages", "wire_present_any_encoding",
                      "carved_logged_messages", "mcp_labeled_logged_messages",
                      "artifact_records"):
            if totals[field] != expected[field]:
                raise ValueError(f"aggregate {field} differs from public summary")
    output = {
        "schema_version": 1,
        "scanner_source_commit": PINNED_SCANNER,
        "author_or_reviewer_run": "operator-supplied; this file does not assert independence",
        "complete_primary_replay": args.run_id is None,
        "replayed_images": len(results),
        "all_scores_match": all(row["matches_published_score"] for row in results),
        "totals": totals,
        "runs": results,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"replayed_images": len(results),
                      "all_scores_match": output["all_scores_match"],
                      "totals": totals}), flush=True)


if __name__ == "__main__":
    main()
