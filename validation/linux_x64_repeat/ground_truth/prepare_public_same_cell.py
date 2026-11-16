"""Audit and publish only the second-phase synthetic non-Codex journals."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from validation.linux_x64_repeat.ground_truth.prepare_public import audit, sha256


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
RUNS = {
    "inspector-http-r4-fast": "RPT_HTTP_B_20261116",
    "inspector-http-r5-delayed": "RPT_INSPECTOR_HTTP_R5_DELAYED_20261116",
    "inspector-stdio-r5-fast": "RPT_INSPECTOR_STDIO_R5_FAST_20261116",
    "inspector-stdio-r4-delayed": "RPT_INSPECTOR_STDIO_R4_DELAYED_20261116",
    "lsp-r3-fast": None,
    "lsp-r4-delayed": None,
    "jsonrpc-r3-fast": None,
    "jsonrpc-r4-delayed": None,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=HERE)
    args = parser.parse_args()
    rows = []
    copies = {}
    for name, marker in RUNS.items():
        report_path = ROOT / "validation/linux_x64_repeat/results" / f"2026-11-16-{name}.json"
        report_data = report_path.read_bytes()
        report = json.loads(report_data)
        capture = args.private_root / "captures" / name
        data = (capture / "traffic.jsonl").read_bytes()
        count = audit(data, report, marker)
        if sha256(data) != report["traffic_log_sha256"] or report["run_id"] != name:
            raise ValueError(f"{name}: journal digest or run ID differs")
        ready = json.loads((capture / "client-ready.json").read_text())
        if ready["pid"] != report["client_pid"]:
            raise ValueError(f"{name}: client PID differs")
        rows.append({
            "report": str(report_path.relative_to(ROOT)), "case": report["case"],
            "run_id": name, "client_pid": ready["pid"],
            "image_sha256": report["image_sha256"],
            "traffic_sha256": sha256(data), "traffic_messages": count,
            "traffic_path": f"traffic/{name}.jsonl",
            "report_sha256": sha256(report_data),
        })
        copies[name] = data
    if len(rows) != 8 or sum(row["traffic_messages"] for row in rows) != 44:
        raise ValueError("unexpected public same-cell journal count")
    out = args.output
    (out / "traffic").mkdir(parents=True, exist_ok=True)
    for name, data in copies.items():
        (out / "traffic" / f"{name}.jsonl").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "scope": "second-phase exact synthetic JSON bodies from eight non-Codex images",
        "public_journals": 8,
        "public_messages": 44,
        "codex_journals_private": 2,
        "ram_images_private": 10,
        "runs": rows,
    }
    (out / "manifest-same-cell.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Audited eight second-phase synthetic journals containing 44 exact wire bodies.")


if __name__ == "__main__":
    main()
