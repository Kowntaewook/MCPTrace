"""Audit the archived comparison outputs without publishing message content.

Separates JSON-RPC carving from the scanners' MCP labels, and breaks down
encoding, capture delay, and transmitted messages outside exact-wire presence.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from validation.mcprecon_comparison.run import canonical, digest, lines


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "validation/linux_x64_http_ram/results/2026-11-14-qemu-http-sdk-rerun.json"
CLIENT_REPORT = ROOT / "validation/mcprecon_comparison/results/2026-11-14-http-ram-rerun-client.json"
WHOLE_REPORT = ROOT / "validation/mcprecon_comparison/results/2026-11-14-http-ram-rerun.json"
COUNT_FIELDS = (
    "traffic_messages", "present_utf8", "present_utf16le", "present_both",
    "present_utf8_only", "present_utf16le_only", "not_exact_wire_present",
    "mcptrace_artifact_records", "mcptrace_mcp_labeled_records",
    "mcptrace_truth_messages_any_label", "mcptrace_truth_messages_mcp_labeled",
    "mcptrace_truth_messages_outside_presence", "mcptrace_unmatched_artifact_records",
    "mcprecon_client_records", "mcprecon_client_mcp_labeled_records",
    "mcprecon_client_truth_messages_any_label", "mcprecon_client_truth_messages_mcp_labeled",
    "mcprecon_client_truth_messages_only_other_label",
    "mcprecon_client_truth_messages_outside_presence", "mcprecon_client_unmatched_records",
    "mcprecon_whole_truth_messages", "mcprecon_whole_truth_messages_in_presence",
    "mcprecon_whole_truth_messages_outside_presence",
)


def one(capture: dict, evidence: Path, client_expected: dict, whole_expected: dict) -> dict:
    run_id = capture["run_id"]
    folder = evidence / "rerun" / run_id
    prior = json.loads((folder / "score.json").read_text(encoding="utf-8"))
    traffic = folder / "traffic.jsonl"
    exports = list((folder / "exports").glob("mcptrace.pid-*.jsonl"))
    if len(exports) != 1 or digest(traffic) != capture["traffic_log_sha256"] or digest(exports[0]) != capture["export_sha256"]:
        raise ValueError(f"{run_id}: missing or hash-mismatched original evidence")
    traffic_rows = lines(traffic)
    probe_rows = prior["messages"]
    if len(traffic_rows) != len(probe_rows) or len(traffic_rows) != capture["traffic_messages"]:
        raise ValueError(f"{run_id}: traffic/probe count mismatch")
    keys = [canonical(row["message"]) for row in traffic_rows]
    truth = set(keys)
    if len(truth) != len(keys):
        raise ValueError(f"{run_id}: duplicated traffic message")
    encoding = {
        "present_utf8": sum(bool(row["wire_present_utf8"]) for row in probe_rows),
        "present_utf16le": sum(bool(row["wire_present_utf16le"]) for row in probe_rows),
        "present_both": sum(bool(row["wire_present_utf8"]) and bool(row["wire_present_utf16le"]) for row in probe_rows),
        "present_utf8_only": sum(bool(row["wire_present_utf8"]) and not row["wire_present_utf16le"] for row in probe_rows),
        "present_utf16le_only": sum(bool(row["wire_present_utf16le"]) and not row["wire_present_utf8"] for row in probe_rows),
        "not_exact_wire_present": sum(not row["wire_present_utf8"] and not row["wire_present_utf16le"] for row in probe_rows),
    }
    present = {key for key, probe in zip(keys, probe_rows, strict=True)
               if probe["wire_present_utf8"] or probe["wire_present_utf16le"]}
    if len(present) != capture["wire_present_any_encoding"]:
        raise ValueError(f"{run_id}: saved presence mismatch")

    trace = [row for row in lines(exports[0]) if row["type"] == "artifact"]
    trace_keys = {canonical(row["message"]) for row in trace}
    trace_mcp = {canonical(row["message"]) for row in trace if row["mcp_candidate"]}
    client_file = evidence / "mcprecon-comparison-client" / f"{run_id}.jsonl"
    client = lines(client_file)
    client_keys = {canonical(row["json"]) for row in client}
    client_mcp = {canonical(row["json"]) for row in client if row["mcp"]}
    whole_file = evidence / "mcprecon-comparison" / f"{run_id}.jsonl"
    whole = lines(whole_file)
    whole_keys = {canonical(row["json"]) for row in whole}
    if (len(trace) != capture["artifact_records"]
            or len(client) != client_expected["mcprecon_record_count"]
            or len(client_keys & truth) != client_expected["mcprecon_truth_messages"]
            or len(whole) != whole_expected["mcprecon_record_count"]
            or len(whole_keys & truth) != whole_expected["mcprecon_truth_messages"]
            or client_expected["packed_wire_probe_messages_verified"] != len(traffic_rows)
            or sum(bool(row["mcp"]) for row in client) != client_expected["mcprecon_flagged_mcp_records"]
            or sum(bool(row["mcp_candidate"]) for row in trace) != capture["mcp_candidate_records"]):
        raise ValueError(f"{run_id}: saved comparison count mismatch")
    if (len(trace_keys & truth) != capture["carved_logical_messages"]
            or len((client_keys & truth) & present) != client_expected["mcprecon_truth_present_in_client_memory"]):
        raise ValueError(f"{run_id}: conditional match count mismatch")

    client_truth = client_keys & truth
    whole_truth = whole_keys & truth
    values = {
        "run_id": run_id,
        "case": capture["case"],
        "requested_delay_seconds": capture["requested_delay_seconds"],
        "mcprecon_client_output_sha256": digest(client_file),
        "mcprecon_whole_output_sha256": digest(whole_file),
        "traffic_messages": len(truth),
        **encoding,
        "mcptrace_artifact_records": len(trace),
        "mcptrace_mcp_labeled_records": sum(bool(row["mcp_candidate"]) for row in trace),
        "mcptrace_truth_messages_any_label": len(trace_keys & truth),
        "mcptrace_truth_messages_mcp_labeled": len(trace_mcp & truth),
        "mcptrace_truth_messages_outside_presence": len((trace_keys & truth) - present),
        "mcptrace_unmatched_artifact_records": sum(canonical(row["message"]) not in truth for row in trace),
        "mcprecon_client_records": len(client),
        "mcprecon_client_mcp_labeled_records": sum(bool(row["mcp"]) for row in client),
        "mcprecon_client_truth_messages_any_label": len(client_truth),
        "mcprecon_client_truth_messages_mcp_labeled": len(client_mcp & truth),
        "mcprecon_client_truth_messages_only_other_label": len(client_truth - client_mcp),
        "mcprecon_client_truth_messages_outside_presence": len(client_truth - present),
        "mcprecon_client_unmatched_records": sum(canonical(row["json"]) not in truth for row in client),
        "mcprecon_whole_truth_messages": len(whole_truth),
        "mcprecon_whole_truth_messages_in_presence": len(whole_truth & present),
        "mcprecon_whole_truth_messages_outside_presence": len(whole_truth - present),
        "whole_and_client_matches_in_presence_identical": (whole_truth & present) == client_truth,
    }
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    client_report = json.loads(CLIENT_REPORT.read_text(encoding="utf-8"))
    whole_report = json.loads(WHOLE_REPORT.read_text(encoding="utf-8"))
    client_by_run = {row["run_id"]: row for row in client_report["captures"]}
    whole_by_run = {row["run_id"]: row for row in whole_report["captures"]}
    captures = [one(row, evidence, client_by_run[row["run_id"]], whole_by_run[row["run_id"]])
                for row in manifest["captures"]]
    groups = defaultdict(lambda: defaultdict(int))
    for row in captures:
        for name in ("total", row["case"], f"{row['case']}-d{row['requested_delay_seconds']}"):
            groups[name]["captures"] += 1
            for key in COUNT_FIELDS:
                groups[name][key] += row[key]
            groups[name]["whole_and_client_matches_in_presence_identical_captures"] += row[
                "whole_and_client_matches_in_presence_identical"
            ]
    report = {
        "schema_version": 1,
        "scope": "Audit of hash-checked traffic and MCPTrace exports plus count-checked, SHA-256-recorded MCPRecon outputs on the preserved 27-image HTTP/SSE fixture",
        "captures": captures,
        "groups": groups,
        "interpretation": [
            "Carved truth messages count canonical JSON matches regardless of either tool's MCP label; MCP-labeled counts are separate.",
            "Exact-wire presence is per transmitted logical message in the current client's readable VMAs; UTF-8 and UTF-16LE flags may overlap.",
            "Whole-image MCPRecon matches cannot be attributed to the client solely from the raw file offset.",
            "Counts from this controlled fixture are not population detection or false-positive rates.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
