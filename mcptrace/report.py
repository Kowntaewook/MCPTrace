"""Build a reviewable case summary from MCPTrace JSONL exports.

The report omits raw bytes and message arguments. It does not invent a timeline.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from collections import Counter
from pathlib import Path

from mcptrace.core import strict_loads


def _jsonl(path: Path) -> tuple[bytes, list[dict]]:
    data = path.read_bytes()
    rows = []
    for line_number, line in enumerate(data.splitlines(), 1):
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSONL") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_number}: expected a JSON object")
        rows.append(row)
    if len(rows) < 2 or rows[0].get("type") != "metadata":
        raise ValueError(f"{path}: missing first metadata record")
    if rows[-1].get("type") != "scan-summary":
        raise ValueError(f"{path}: missing final scan-summary record")
    if any(row.get("type") != "artifact" for row in rows[1:-1]):
        raise ValueError(f"{path}: unexpected record type or order")
    return data, rows


def _artifact(row: dict, metadata: dict, path: Path, line_number: int) -> dict:
    try:
        raw = base64.b64decode(row["raw_base64"], validate=True)
        digest = hashlib.sha256(raw).hexdigest()
        valid = digest == row["raw_sha256"] and len(raw) == row["byte_length"]
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError(f"{path}:{line_number}: invalid raw evidence fields") from exc
    if not valid:
        raise ValueError(f"{path}:{line_number}: raw evidence hash or length mismatch")
    if row.get("pid") != metadata.get("pid") or row.get("target_os") != metadata.get("target_os"):
        raise ValueError(f"{path}:{line_number}: artifact metadata mismatch")
    if type(row.get("virtual_address")) is not int or row["virtual_address"] < 0:
        raise ValueError(f"{path}:{line_number}: invalid virtual address")
    encoding = row.get("encoding")
    if encoding not in {"utf-8", "utf-16-le"}:
        raise ValueError(f"{path}:{line_number}: unsupported encoding")
    if row.get("state") == "complete":
        try:
            parsed = strict_loads(raw.decode(encoding))
        except (UnicodeError, ValueError) as exc:
            raise ValueError(f"{path}:{line_number}: raw message cannot be parsed") from exc
        exported = row.get("message")
        if json.dumps(parsed, sort_keys=True) != json.dumps(exported, sort_keys=True):
            raise ValueError(f"{path}:{line_number}: exported message differs from raw bytes")
    elif row.get("state") != "fragment":
        raise ValueError(f"{path}:{line_number}: invalid artifact state")
    return {
        "pid": row["pid"],
        "target_os": row["target_os"],
        "virtual_address": row["virtual_address"],
        "byte_length": row["byte_length"],
        "encoding": encoding,
        "raw_sha256": digest,
        "state": row.get("state"),
        "protocol_hint": row.get("protocol_hint", "unavailable"),
        "classification_reasons": row.get("classification_reasons", []),
        "kind": row.get("kind"),
        "method": row.get("method", ""),
        "tool": row.get("tool", ""),
        "relation": row.get("relation"),
        "candidate_address_count": row.get("candidate_address_count", 0),
    }


def build_report(paths: list[Path]) -> dict:
    if not paths:
        raise ValueError("at least one JSONL export is required")
    sources = []
    artifacts = []
    counts: Counter[str] = Counter()
    for path in paths:
        data, rows = _jsonl(path)
        metadata, summary = rows[0], rows[-1]
        required_summary = (
            "displayed_records",
            "limits_hit",
            "anchor_limit_hits",
            "candidate_limit_hits",
            "unreadable_bytes",
            "invalid_regions",
            "error",
            "skipped_reason",
        )
        if any(key not in summary for key in required_summary):
            raise ValueError(f"{path}: incomplete scan summary")
        if summary["displayed_records"] != len(rows) - 2:
            raise ValueError(f"{path}: exported artifact count differs from scan summary")
        source_artifacts = [
            _artifact(row, metadata, path, line_number)
            for line_number, row in enumerate(rows[1:-1], 2)
        ]
        for artifact in source_artifacts:
            counts[artifact["protocol_hint"]] += 1
        artifacts.extend(source_artifacts)
        limitations = {
            key: summary.get(key)
            for key in (
                "limits_hit",
                "anchor_limit_hits",
                "candidate_limit_hits",
                "unreadable_bytes",
                "invalid_regions",
                "error",
                "skipped_reason",
            )
        }
        limited = any(bool(value) for value in limitations.values())
        sources.append(
            {
                "path": str(path),
                "jsonl_sha256": hashlib.sha256(data).hexdigest(),
                "pid": metadata.get("pid"),
                "process": metadata.get("process"),
                "target_os": metadata.get("target_os"),
                "mcptrace_version": metadata.get("mcptrace_version"),
                "exported_artifacts": len(source_artifacts),
                "scan_status": "limited_or_incomplete" if limited else "no_reported_limits",
                "scan_limitations": limitations,
            }
        )
    return {
        "schema_version": 1,
        "scope": "Summary of supplied MCPTrace JSONL exports, with raw bytes verified by hash",
        "interpretation": (
            "Memory candidates do not prove transmission or execution. "
            "Virtual addresses and row order do not establish a timeline. "
            "Hash verification checks export consistency, not image acquisition."
        ),
        "sources": sources,
        "artifact_count": len(artifacts),
        "protocol_hint_counts": dict(sorted(counts.items())),
        "artifacts": artifacts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", nargs="+", type=Path, help="MCPTrace per-process JSONL exports")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = build_report(args.jsonl)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
