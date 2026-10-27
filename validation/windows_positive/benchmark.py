"""Publish allowlisted measurements and aggregate three independent Windows captures."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path

CASE_FIELDS = (
    "expected_logical_messages",
    "distinct_expected_messages_found",
    "expected_tool_pairs",
    "complete_tool_pairs_any_endpoint",
    "artifact_records",
    "records_matching_logged_traffic",
    "distinct_unsent_controls_found",
    "records_matching_unsent_controls",
    "unmatched_artifact_records",
    "evaluated_candidate_links",
    "incorrect_candidate_links",
    "unverifiable_candidate_links",
)
ENVIRONMENT_FIELDS = ("platform", "python", "mcp_sdk", "volatility", "logical_cpus")
COMPLETED = {"passed", "completed_with_limits"}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def scan_diagnostics(scans):
    return {
        "processes": len(scans),
        "limited_processes": sum(
            bool(s["limits_hit"] or s["anchor_limit_hits"] or s["candidate_limit_hits"])
            for s in scans.values()
        ),
        "error_processes": sum(bool(s["error"]) for s in scans.values()),
        "skipped_processes": sum(bool(s["skipped_reason"]) for s in scans.values()),
        **{
            key: sum(s[key] for s in scans.values())
            for key in ("invalid_regions", "anchor_limit_hits", "candidate_limit_hits")
        },
        "record_budget_processes": sum("max-records" in s["limits_hit"] for s in scans.values()),
        "byte_budget_processes": sum("max-bytes" in s["limits_hit"] for s in scans.values()),
    }


def summarize_run(report, replica):
    """Exclude recovered content, ground truth, PIDs, paths, and arbitrary log text."""
    path = report / "manifest.json"
    manifest = read_json(path) if path.exists() else {}
    output = {
        "schema_version": 1,
        "replica": replica,
        "status": manifest["status"] if manifest.get("status") in COMPLETED else "failed",
        "commit": manifest.get("commit"),
        "environment": {key: manifest.get(key) for key in ENVIRONMENT_FIELDS},
        "tool_calls_per_case": manifest.get("tool_calls_per_case"),
        "scan_repeats": manifest.get("scan_repeats"),
        "report_scan_limits": manifest.get("report_scan_limits", False),
    }
    scan_path = report / "scan-summaries.json"
    scans = read_json(scan_path) if scan_path.exists() else {}
    if scans:
        output["scan_diagnostics"] = scan_diagnostics(scans)
    if output["status"] not in COMPLETED:
        return output
    for key in (
        "raw_memory_deleted",
        "image_hash_unchanged_after_analysis",
        "repeated_exports_identical",
    ):
        if manifest.get(key) is not True:
            raise ValueError(f"Completed capture is missing validation: {key}")
    comparison = read_json(report / "comparison.json")
    if len(scans) != 4 or any(
        s["error"] or s["skipped_reason"] or s["invalid_regions"] for s in scans.values()
    ):
        raise ValueError("Benchmark requires four complete endpoint scans")
    limited = output["scan_diagnostics"]["limited_processes"] > 0
    if limited and (
        output["status"] != "completed_with_limits" or not output["report_scan_limits"]
    ):
        raise ValueError("Limited scans must be explicitly marked completed_with_limits")
    if not limited and output["status"] != "passed":
        raise ValueError("Completed status does not agree with scan diagnostics")
    cases = {}
    for case in comparison["cases"]:
        counts = {key: case[key] for key in CASE_FIELDS}
        if any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("Case measurements must be nonnegative integer counts")
        if (
            counts["expected_tool_pairs"] != output["tool_calls_per_case"]
            or counts["expected_logical_messages"] != 5 + 2 * output["tool_calls_per_case"]
            or counts["distinct_expected_messages_found"] > counts["expected_logical_messages"]
            or counts["complete_tool_pairs_any_endpoint"] > counts["expected_tool_pairs"]
            or counts["incorrect_candidate_links"]
        ):
            raise ValueError("Inconsistent ground truth or incorrect candidate links")
        counts["best_single_pid_tool_pairs"] = max(
            p["complete_tool_pairs"] for p in case["per_pid"].values()
        )
        if case["mode"] in cases:
            raise ValueError("Duplicate benchmark mode")
        cases[case["mode"]] = counts
    if set(cases) != {"natural", "retained"}:
        raise ValueError("Both benchmark modes must be present")
    verified = comparison["artifact_records_byte_verified"]
    if verified != sum(c["artifact_records"] for c in cases.values()) or verified != sum(
        s["displayed_records"] for s in scans.values()
    ):
        raise ValueError("Verified and exported record counts differ")
    timings = manifest["timings_seconds"]
    durations = timings["plugin_cli_seconds"]
    if len(durations) != output["scan_repeats"] or any(
        not math.isfinite(s) or s <= 0 for s in durations
    ):
        raise ValueError("Missing or invalid CLI timing samples")
    output.update(
        cases=cases,
        capture_sha256=manifest["image_sha256"],
        physical_ram_bytes=manifest["physical_ram_bytes"],
        image_logical_bytes=manifest["image_bytes"],
        artifact_records_byte_verified=verified,
        artifact_bytes_verified=comparison["artifact_bytes_verified"],
        scan_totals={
            key: sum(s[key] for s in scans.values())
            for key in ("bytes_read", "unreadable_bytes", "regions_scanned", "candidate_records")
        },
        timings_seconds={
            **{
                key: timings[key]
                for key in (
                    "acquisition",
                    "symbols_and_info",
                    "native_byte_verification",
                    "pipeline_total",
                )
            },
            "plugin_cli": durations,
        },
        ready_to_capture_seconds={
            c["mode"]: (manifest["capture_started_ns"] - c["ready_ns"]) / 1e9
            for c in manifest["cases"]
        },
        checks={
            "full_endpoint_scans": not limited,
            "native_bytes_verified": True,
            "repeated_exports_identical": True,
            "image_hash_unchanged": True,
            "raw_memory_deleted": True,
        },
    )
    return output


def distribution(values):
    return {
        "n": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def aggregate_runs(runs):
    """Require the full predeclared sample; never silently discard a failed capture."""
    if len(runs) != 3 or {r["replica"] for r in runs} != {1, 2, 3}:
        raise ValueError("Require exactly replicas 1, 2, and 3")
    if any(r["status"] not in COMPLETED for r in runs):
        raise ValueError("Cannot aggregate a failed capture as a successful benchmark")
    if len({r["capture_sha256"] for r in runs}) != 3:
        raise ValueError("Require three independently acquired images")
    for key in (
        "schema_version",
        "commit",
        "environment",
        "tool_calls_per_case",
        "scan_repeats",
        "report_scan_limits",
    ):
        if any(r[key] != runs[0][key] for r in runs):
            raise ValueError(f"Incompatible benchmark conditions: {key}")
    modes = {}
    for mode in ("natural", "retained"):
        cases = [r["cases"][mode] for r in runs]
        totals = {key: sum(c[key] for c in cases) for key in CASE_FIELDS}
        modes[mode] = {
            "totals": totals,
            "logical_message_coverage": (
                totals["distinct_expected_messages_found"] / totals["expected_logical_messages"]
            ),
            "messages_found_per_capture": distribution(
                [c["distinct_expected_messages_found"] for c in cases]
            ),
            "tool_pairs_per_capture": distribution(
                [c["complete_tool_pairs_any_endpoint"] for c in cases]
            ),
        }
    return {
        "schema_version": 1,
        "independent_captures": 3,
        "captures_with_scan_limits": sum(r["status"] == "completed_with_limits" for r in runs),
        "commit": runs[0]["commit"],
        "environment": runs[0]["environment"],
        "tool_calls_per_case": runs[0]["tool_calls_per_case"],
        "scan_repeats_per_capture": runs[0]["scan_repeats"],
        "modes": modes,
        "plugin_cli_seconds": distribution(
            [s for r in runs for s in r["timings_seconds"]["plugin_cli"]]
        ),
        "per_capture_cli_median_seconds": distribution(
            [statistics.median(r["timings_seconds"]["plugin_cli"]) for r in runs]
        ),
        "artifact_records_byte_verified": sum(r["artifact_records_byte_verified"] for r in runs),
        "artifact_bytes_verified": sum(r["artifact_bytes_verified"] for r in runs),
        "runs": sorted(runs, key=lambda r: r["replica"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    summarize = subparsers.add_parser("summarize")
    summarize.add_argument("--reportdir", type=Path, required=True)
    summarize.add_argument("--replica", type=int, choices=[1, 2, 3], required=True)
    summarize.add_argument("--output", type=Path, required=True)
    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("inputs", nargs=3, type=Path)
    aggregate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = (
        summarize_run(args.reportdir, args.replica)
        if args.action == "summarize"
        else aggregate_runs([read_json(path) for path in args.inputs])
    )
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(f"Wrote {args.output.name}")


if __name__ == "__main__":
    main()
