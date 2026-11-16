"""Build a byte-free handoff index for the 20 primary Linux RAM images."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SUMMARY = HERE.parent / "results/2026-11-16-same-cell-summary.json"
OUTPUT = HERE / "reviewer_manifest.json"


def main() -> None:
    summary = json.loads(SUMMARY.read_text())
    if summary["primary_images"] != 20 or len(summary["runs"]) != 20:
        raise ValueError("expected exactly 20 planned images")
    rows = []
    for run in summary["runs"]:
        run_id = run["run_id"]
        report_rel = Path("validation/linux_x64_repeat") / run["report"]
        report_bytes = (ROOT / report_rel).read_bytes()
        report = json.loads(report_bytes)
        if (report["run_id"] != run_id or report["case"] != run["case"]
                or report["image_sha256"] != run["image_sha256"]
                or report["private_ram_archive_sha256"] != run["archive_sha256"]
                or report["traffic_log_sha256"] != run["traffic_sha256"]):
            raise ValueError(f"summary/report disagreement for {run_id}")
        public_wire = None
        if run["case"] != "codex-stdio":
            wire_rel = (Path("validation/linux_x64_repeat/ground_truth/traffic")
                        / f"{run_id}.jsonl")
            wire_hash = hashlib.sha256((ROOT / wire_rel).read_bytes()).hexdigest()
            if wire_hash != report["traffic_log_sha256"]:
                raise ValueError(f"public wire journal differs for {run_id}")
            public_wire = str(wire_rel)
        rows.append({
            "run_id": run_id,
            "capture_root_slot": run["phase"],
            "case": run["case"],
            "timing": run["timing"],
            "client_pid": report["client_pid"],
            "archive_relative_path": f"{run_id}/ram.elf.zst",
            "archive_bytes": report["private_ram_archive_bytes"],
            "archive_sha256": report["private_ram_archive_sha256"],
            "restored_image_bytes": report["image_bytes"],
            "restored_image_sha256": report["image_sha256"],
            "public_wire_journal": public_wire,
            "private_wire_relative_path": (f"{run_id}/traffic.jsonl"
                                           if public_wire is None else None),
            "wire_sha256": report["traffic_log_sha256"],
            "public_report": str(report_rel),
            "public_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        })
    if len({row["run_id"] for row in rows}) != 20:
        raise ValueError("duplicate run IDs")
    output = {
        "schema_version": 1,
        "scope": "20 primary Linux full-RAM host/control captures; timing pilot excluded",
        "scanner_source_commit": "ded4c00235f5c41222f72e8529f3dbd617bc3c9f",
        "volatility_version": "2.28.2",
        "original_ram_public": False,
        "primary_images": 20,
        "private_ram_archives_needed": 20,
        "private_codex_wire_journals_needed": 4,
        "public_non_codex_wire_journals": 16,
        "captures": rows,
    }
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n")
    print(f"Indexed {len(rows)} primary RAM images without copying private bytes.")


if __name__ == "__main__":
    main()
