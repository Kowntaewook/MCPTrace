"""Verify two fresh-process RAM images at each case/timing cell.

The original timing pilot is excluded. Run with both private evidence roots;
the public JSON reports alone cannot verify image-level results.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from validation.linux_x64_repeat.summarize import check


HERE = Path(__file__).resolve().parent
CELLS = {
    "inspector-http": {
        "early": ("inspector-http-r2-fast", "inspector-http-r4-fast"),
        "delayed": ("inspector-http-r3-delayed", "inspector-http-r5-delayed"),
    },
    "inspector-stdio": {
        "early": ("inspector-stdio-r1-fast", "inspector-stdio-r5-fast"),
        "delayed": ("inspector-stdio-r2-delayed", "inspector-stdio-r4-delayed"),
    },
    "lsp-control": {
        "early": ("lsp-r1-fast", "lsp-r3-fast"),
        "delayed": ("lsp-r2-delayed", "lsp-r4-delayed"),
    },
    "jsonrpc-control": {
        "early": ("jsonrpc-r1-fast", "jsonrpc-r3-fast"),
        "delayed": ("jsonrpc-r2-delayed", "jsonrpc-r4-delayed"),
    },
    "codex-stdio": {
        "early": ("codex-r1-fast", "codex-r3-fast"),
        "delayed": ("codex-r2-delayed", "codex-r4-delayed"),
    },
}
FIELDS = (
    "traffic_messages", "wire_present_any_encoding", "carved_logged_messages",
    "mcp_labeled_logged_messages", "artifact_records",
)
MESSAGE_SIGNATURE_FIELDS = (
    "direction", "framing", "method", "wire_present_utf8",
    "wire_present_utf16le", "carved", "mcp_labeled_copy",
    "confirmed_scan_miss",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first-private-root", required=True, type=Path)
    parser.add_argument("--second-private-root", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=HERE / "results/2026-11-16-same-cell-summary.json")
    args = parser.parse_args()
    cells = {}
    image_hashes = set()
    pids_by_phase: dict[str, set[int]] = defaultdict(set)
    rows = []
    for case, timing_map in CELLS.items():
        cells[case] = {}
        for timing, names in timing_map.items():
            reports = []
            for index, name in enumerate(names):
                phase = "initial" if index == 0 else "second"
                private = (args.first_private_root if index == 0
                           else args.second_private_root)
                path = HERE / "results" / f"2026-11-16-{name}.json"
                report = json.loads(path.read_text())
                if report["case"] != case or report["run_id"] != name:
                    raise ValueError(f"wrong case/run ID: {name}")
                planned = 0 if timing == "early" else 90
                if report["planned_minimum_event_age_seconds"] != planned:
                    raise ValueError(f"wrong timing plan: {name}")
                check(report, private / "captures" / name)
                image_hash = report["image_sha256"]
                pid = report["client_pid"]
                if image_hash in image_hashes or pid in pids_by_phase[phase]:
                    raise ValueError(f"duplicate image or PID within a VM boot: {name}")
                image_hashes.add(image_hash)
                pids_by_phase[phase].add(pid)
                reports.append(report)
                rows.append({
                    "report": str(path.relative_to(HERE)), "phase": phase,
                    "case": case, "timing": timing, "run_id": name,
                    "client_pid": pid, "image_sha256": image_hash,
                    "archive_sha256": report["private_ram_archive_sha256"],
                    "traffic_sha256": report["traffic_log_sha256"],
                    "event_age_seconds": report["event_age_at_pre_capture_probe_seconds"],
                    **{key: report[key] for key in FIELDS},
                })
            signatures = [
                [tuple(message[key] for key in MESSAGE_SIGNATURE_FIELDS)
                 for message in report["messages"]]
                for report in reports
            ]
            if signatures[0] != signatures[1]:
                raise ValueError(f"per-message recovery/classification differs: {case}/{timing}")
            cells[case][timing] = {
                "independent_processes": len(reports),
                "per_message_flags_agree": True,
                "per_run": [{"run_id": report["run_id"],
                             "event_age_seconds": report["event_age_at_pre_capture_probe_seconds"],
                             **{key: report[key] for key in FIELDS}}
                            for report in reports],
                "totals": {key: sum(report[key] for report in reports)
                           for key in FIELDS},
            }
    totals = {key: sum(row[key] for row in rows) for key in FIELDS}
    output = {
        "schema_version": 1,
        "scope": "Linux x86-64 QEMU full RAM; two fresh-process images per case and timing cell",
        "primary_images": len(rows),
        "separate_initial_timing_pilot_excluded": 1,
        "original_ram_archives_private": True,
        "cells": cells,
        "totals": totals,
        "runs": rows,
        "interpretation": [
            "The two images in each cell contain separate client processes and exchanges; all use a reused VM and synthetic peer/tool.",
            "Early and delayed images are not paired observations of the same process.",
            "Sent, exact-wire-present, carved, and MCP-labeled counts are separate denominators.",
            "No population detection rate or false-positive frequency is inferred from these controlled captures.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(f"Verified {len(rows)} images across {len(CELLS) * 2} same-condition cells.")


if __name__ == "__main__":
    main()
