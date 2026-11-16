"""Verify and summarize the independent-process Linux RAM repeat captures."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path


HERE = Path(__file__).resolve().parent
PRIMARY = {
    "inspector-http": ("inspector-http-r2-fast", "inspector-http-r3-delayed"),
    "inspector-stdio": ("inspector-stdio-r1-fast", "inspector-stdio-r2-delayed"),
    "lsp-control": ("lsp-r1-fast", "lsp-r2-delayed"),
    "jsonrpc-control": ("jsonrpc-r1-fast", "jsonrpc-r2-delayed"),
    "codex-stdio": ("codex-r1-fast", "codex-r2-delayed"),
}
PILOT = "inspector-http-r1-delayed"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def restored_digest(archive: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with subprocess.Popen(["zstd", "-d", "-c", str(archive)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        assert proc.stdout is not None
        for chunk in iter(lambda: proc.stdout.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
        if proc.wait() != 0:
            raise ValueError(f"archive decompression failed: {archive}")
    return digest.hexdigest(), size


def check(report: dict, capture: Path) -> None:
    case = report["case"]
    archive = capture / "ram.elf.zst"
    if (archive.stat().st_size != report["private_ram_archive_bytes"]
            or sha256(archive) != report["private_ram_archive_sha256"]):
        raise ValueError(f"{case}: compressed archive differs")
    image_hash, image_bytes = restored_digest(archive)
    if image_hash != report["image_sha256"] or image_bytes != report["image_bytes"]:
        raise ValueError(f"{case}: reconstructed image differs")
    traffic = capture / "traffic.jsonl"
    if (sha256(traffic) != report["traffic_log_sha256"]
            or sha256(capture / "traffic.before.jsonl") != report["traffic_log_sha256"]):
        raise ValueError(f"{case}: traffic changed during acquisition")
    ready = json.loads((capture / "client-ready.json").read_text())
    if ready["pid"] != report["client_pid"]:
        raise ValueError(f"{case}: client PID differs")
    export = capture / "exports" / f"mcptrace.pid-{report['client_pid']}.jsonl"
    if sha256(export) != report["export_sha256"]:
        raise ValueError(f"{case}: scanner export differs")
    messages = report["messages"]
    if (len(messages) != report["traffic_messages"]
            or sum(bool(m["wire_present_utf8"] or m["wire_present_utf16le"])
                   for m in messages) != report["wire_present_any_encoding"]
            or sum(bool(m["carved"]) for m in messages) != report["carved_logged_messages"]
            or sum(bool(m["mcp_labeled_copy"]) for m in messages)
                != report["mcp_labeled_logged_messages"]):
        raise ValueError(f"{case}: per-message flags differ from totals")
    if (report["confirmed_scan_misses"] != 0 or report["unmatched_artifact_records"] != 0
            or report["artifacts_reread_at_virtual_address"] != report["artifact_records"]
            or bool(report["scan_limits_hit"])):
        raise ValueError(f"{case}: scan verification failed")
    age = report["event_age_at_pre_capture_probe_seconds"]
    if age < 0 or report["qmp_pause_and_capture_seconds"] <= 0:
        raise ValueError(f"{case}: invalid timing")
    planned = report.get("planned_minimum_event_age_seconds")
    if planned == 0 and age >= 30:
        raise ValueError(f"{case}: early capture occurred too late")
    if planned == 90 and age < 90:
        raise ValueError(f"{case}: delayed capture occurred too early")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=HERE / "results/2026-11-16-repeat-summary.json")
    args = parser.parse_args()
    expected = [PILOT, *(run for pair in PRIMARY.values() for run in pair)]
    cases = defaultdict(list)
    pids = set()
    image_hashes = set()
    runs = []
    for name in expected:
        path = HERE / "results" / f"2026-11-16-{name}.json"
        report = json.loads(path.read_text())
        if report["run_id"] != ("http-fast-1" if name == PILOT else name):
            raise ValueError(f"unexpected run ID: {name}")
        capture = args.private_root / "captures" / report.get("capture_dir_name", report["run_id"])
        check(report, capture)
        if report["client_pid"] in pids or report["image_sha256"] in image_hashes:
            raise ValueError("reused PID or duplicate image in a claimed fresh-process run")
        pids.add(report["client_pid"])
        image_hashes.add(report["image_sha256"])
        pilot = name == PILOT
        if not pilot:
            cases[report["case"]].append(report)
        runs.append({
            "report": str(path.relative_to(HERE)),
            "case": report["case"], "run_id": report["run_id"],
            "pilot": pilot, "client_pid": report["client_pid"],
            "image_sha256": report["image_sha256"],
            "archive_sha256": report["private_ram_archive_sha256"],
            "traffic_sha256": report["traffic_log_sha256"],
            "event_age_at_pre_capture_probe_seconds":
                report["event_age_at_pre_capture_probe_seconds"],
            "traffic_messages": report["traffic_messages"],
            "wire_present_any_encoding": report["wire_present_any_encoding"],
            "carved_logged_messages": report["carved_logged_messages"],
            "mcp_labeled_logged_messages": report["mcp_labeled_logged_messages"],
            "artifact_records": report["artifact_records"],
            "mcp_candidate_records": report["mcp_candidate_records"],
            "confirmed_scan_misses": report["confirmed_scan_misses"],
            "unmatched_artifact_records": report["unmatched_artifact_records"],
        })
    if set(cases) != set(PRIMARY) or any(len(v) != 2 for v in cases.values()):
        raise ValueError("expected two primary independent captures per condition")
    totals = {}
    for case, reports in cases.items():
        totals[case] = {
            "independent_processes": 2,
            "traffic_messages": sum(r["traffic_messages"] for r in reports),
            "wire_present_any_encoding": sum(r["wire_present_any_encoding"] for r in reports),
            "carved_logged_messages": sum(r["carved_logged_messages"] for r in reports),
            "mcp_labeled_logged_messages": sum(r["mcp_labeled_logged_messages"] for r in reports),
            "artifact_records": sum(r["artifact_records"] for r in reports),
        }
    output = {
        "schema_version": 1,
        "date": "2026-11-16",
        "scope": "Linux x86-64 QEMU physical RAM, one selected live-client PID per image",
        "primary_new_images": 10,
        "separate_pilot_images": 1,
        "fresh_client_pids": True,
        "original_ram_archives_private": True,
        "cases": totals,
        "runs": runs,
        "interpretation": [
            "Each primary condition has one new early and one new >=90-second capture from separate processes and exchanges.",
            "The HTTP pilot is retained but excluded from primary totals because its timing was not planned in advance.",
            "Exact-wire presence is probed in readable client VMAs; absent wire bytes are not confirmed scanner misses.",
            "These small controlled samples do not estimate population detection or false-positive rates.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print("Verified 10 primary fresh-process captures and one separately flagged pilot.")


if __name__ == "__main__":
    main()
