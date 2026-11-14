"""Cross-check four private RAM archives and publish a numeric summary."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from validation.linux_x64_positive.score import sha256


CASES = ("inspector-http", "inspector-stdio", "lsp-control", "jsonrpc-control")
CAPTURE_DIR = {"inspector-http": "http", "inspector-stdio": "stdio",
               "lsp-control": "lsp", "jsonrpc-control": "jsonrpc"}
FIELDS = ("traffic_messages", "wire_present_any_encoding", "carved_logged_messages",
          "mcp_labeled_logged_messages", "confirmed_scan_misses", "artifact_records",
          "artifacts_reread_at_virtual_address", "mcp_candidate_records",
          "unmatched_artifact_records")


def verify_archive(path: Path, expected_archive: str, expected_image: str,
                   expected_archive_bytes: int, expected_image_bytes: int) -> None:
    if path.stat().st_size != expected_archive_bytes or sha256(path) != expected_archive:
        raise ValueError(f"{path.name}: archive size or SHA-256 mismatch")
    digest = hashlib.sha256()
    size = 0
    with subprocess.Popen(["zstd", "-q", "-d", "-c", str(path)],
                          stdout=subprocess.PIPE) as decoder:
        assert decoder.stdout is not None
        for chunk in iter(lambda: decoder.stdout.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
        if decoder.wait(timeout=900) != 0:
            raise ValueError(f"{path.name}: decompression failed")
    if size != expected_image_bytes or digest.hexdigest() != expected_image:
        raise ValueError(f"{path.name}: reconstructed RAM size or SHA-256 mismatch")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--private-captures", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    rows = {}
    for case in CASES:
        path = args.results / f"2026-11-15-{case}.json"
        row = json.loads(path.read_text(encoding="utf-8"))
        if row["case"] != case or row["artifact_records"] != row[
                "artifacts_reread_at_virtual_address"] or row["scan_limits_hit"]:
            raise ValueError(f"{case}: case, address verification, or scan-limit mismatch")
        archive = args.private_captures / CAPTURE_DIR[case] / "ram.elf.zst"
        verify_archive(archive, row["private_ram_archive_sha256"], row["image_sha256"],
                       row["private_ram_archive_bytes"], row["image_bytes"])
        rows[case] = row
    if len({row["image_sha256"] for row in rows.values()}) != len(CASES):
        raise ValueError("duplicate physical RAM image")

    def aggregate(cases: tuple[str, ...]) -> dict:
        return {"captures": len(cases), **{field: sum(rows[c][field] for c in cases)
                                          for field in FIELDS}}

    report = {
        "schema_version": 1,
        "scope": "Four single-capture Linux x86-64 full-RAM observations in one reused QEMU VM",
        "cases": {case: {field: row[field] for field in FIELDS} | {
            "image_sha256": row["image_sha256"],
            "private_ram_archive_sha256": row["private_ram_archive_sha256"],
            "archive_reconstructed_to_image_hash": True,
        } for case, row in rows.items()},
        "real_mcp_host_total": aggregate(CASES[:2]),
        "non_mcp_controls_total": aggregate(CASES[2:]),
        "limitations": [
            "One capture per condition in a reused VM does not estimate field detection or false-positive rates.",
            "The positive cases use the same Inspector host family and one purpose-built official-SDK server.",
            "MCP labels and JSON-RPC carving are distinct outputs; exact-wire presence is conditional on readable client VMAs.",
            "Raw RAM and independent traffic journals are retained privately, not embedded in this numeric report.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
