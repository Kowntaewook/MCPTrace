"""Case summaries must preserve evidence checks and visible scan limitations."""

import json

import pytest

from mcptrace.core import scan_chunks
from mcptrace.report import build_report


def export(tmp_path, *, limited=False):
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"x","arguments":{"secret":"DO_NOT_EXPORT"}}}'
    )
    (record,) = scan_chunks([(0x4000, raw)])
    record.pid = 123
    record.target_os = "linux"
    rows = [
        {"type": "metadata", "pid": 123, "target_os": "linux", "process": "client"},
        {"type": "artifact", **record.to_dict()},
        {
            "type": "scan-summary",
            "limits_hit": ["read-limit"] if limited else [],
            "displayed_records": 1,
            "anchor_limit_hits": 0,
            "candidate_limit_hits": 0,
            "unreadable_bytes": 0,
            "invalid_regions": 0,
            "error": None,
            "skipped_reason": None,
        },
    ]
    path = tmp_path / "mcptrace.pid-123.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    return path, rows


def test_report_checks_bytes_and_excludes_message_content(tmp_path):
    path, _ = export(tmp_path, limited=True)
    report = build_report([path])
    assert report["sources"][0]["scan_status"] == "limited_or_incomplete"
    assert report["protocol_hint_counts"] == {"mcp-candidate": 1}
    assert report["artifacts"][0]["virtual_address"] == 0x4000
    assert "DO_NOT_EXPORT" not in json.dumps(report)
    assert "timeline" in report["interpretation"]


def test_report_rejects_tampered_hash(tmp_path):
    path, rows = export(tmp_path)
    rows[1]["raw_sha256"] = "0" * 64
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="hash or length mismatch"):
        build_report([path])


def test_report_rejects_mismatched_pid(tmp_path):
    path, rows = export(tmp_path)
    rows[1]["pid"] = 456
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="metadata mismatch"):
        build_report([path])


def test_report_rejects_message_field_different_from_verified_raw(tmp_path):
    path, rows = export(tmp_path)
    rows[1]["message"]["params"]["arguments"]["secret"] = "CHANGED"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="differs from raw bytes"):
        build_report([path])
