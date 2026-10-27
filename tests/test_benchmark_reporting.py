"""Benchmark publication must keep denominators, failures, and content boundaries."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "benchmark", Path(__file__).resolve().parents[1] / "validation/windows_positive/benchmark.py"
)
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def report_files(tmp_path):
    manifest = {
        "status": "passed",
        "commit": "test-commit",
        "platform": "Windows-2022Server",
        "python": "3.12",
        "mcp_sdk": "1.26.0",
        "volatility": "2.28.2",
        "logical_cpus": 2,
        "tool_calls_per_case": 64,
        "scan_repeats": 3,
        "raw_memory_deleted": True,
        "image_hash_unchanged_after_analysis": True,
        "repeated_exports_identical": True,
        "image_sha256": "1" * 64,
        "physical_ram_bytes": 8 * 1024**3,
        "image_bytes": 11 * 1024**3,
        "capture_started_ns": 1_000_000_000,
        "cases": [
            {"mode": mode, "ready_ns": 900_000_000, "client_pid": 12345}
            for mode in ("natural", "retained")
        ],
        "timings_seconds": {
            "acquisition": 10.0,
            "symbols_and_info": 20.0,
            "native_byte_verification": 2.0,
            "pipeline_total": 50.0,
            "plugin_cli_seconds": [4.0, 3.0, 2.0],
        },
        "unrelated_secret": "DO_NOT_PUBLISH",
    }
    cases = []
    for mode in ("natural", "retained"):
        case = dict.fromkeys(benchmark.CASE_FIELDS, 0)
        case.update(
            mode=mode,
            expected_logical_messages=133,
            expected_tool_pairs=64,
            distinct_expected_messages_found=10,
            complete_tool_pairs_any_endpoint=2,
            artifact_records=10,
            records_matching_logged_traffic=10,
            per_pid={"12345": {"complete_tool_pairs": 2}},
            recovered_message="DO_NOT_PUBLISH",
        )
        cases.append(case)
    scans = {
        str(pid): {
            "error": None,
            "limits_hit": [],
            "skipped_reason": None,
            "anchor_limit_hits": 0,
            "candidate_limit_hits": 0,
            "invalid_regions": 0,
            "displayed_records": 5,
            "candidate_records": 5,
            "bytes_read": 1024,
            "unreadable_bytes": 2048,
            "regions_scanned": 2,
        }
        for pid in range(4)
    }
    for name, data in (
        ("manifest.json", manifest),
        ("scan-summaries.json", scans),
        (
            "comparison.json",
            {"cases": cases, "artifact_records_byte_verified": 20, "artifact_bytes_verified": 500},
        ),
    ):
        (tmp_path / name).write_text(json.dumps(data))
    return manifest


def test_summary_excludes_raw_content_and_identifiers(tmp_path):
    report_files(tmp_path)
    summary = benchmark.summarize_run(tmp_path, 1)
    encoded = json.dumps(summary)
    assert "DO_NOT_PUBLISH" not in encoded and "12345" not in encoded
    assert summary["scan_totals"]["bytes_read"] == 4096
    assert summary["cases"]["natural"]["expected_logical_messages"] == 133
    assert summary["checks"]["raw_memory_deleted"]


def test_aggregation_uses_capture_denominators_not_scan_repeats(tmp_path):
    report_files(tmp_path)
    runs = []
    for replica, found in enumerate([10, 12, 14], 1):
        run = benchmark.summarize_run(tmp_path, replica)
        run["capture_sha256"] = str(replica) * 64
        run["cases"]["natural"]["distinct_expected_messages_found"] = found
        runs.append(run)
    combined = benchmark.aggregate_runs(runs)
    natural = combined["modes"]["natural"]
    assert natural["totals"]["expected_logical_messages"] == 399
    assert natural["totals"]["distinct_expected_messages_found"] == 36
    assert natural["logical_message_coverage"] == 36 / 399
    assert natural["messages_found_per_capture"]["mean"] == 12
    assert combined["plugin_cli_seconds"]["n"] == 9
    with pytest.raises(ValueError, match="exactly replicas"):
        benchmark.aggregate_runs(runs[:2])
    bad = copy.deepcopy(runs)
    bad[2]["status"] = "failed"
    with pytest.raises(ValueError, match="failed capture"):
        benchmark.aggregate_runs(bad)
    bad = copy.deepcopy(runs)
    bad[2]["capture_sha256"] = bad[0]["capture_sha256"]
    with pytest.raises(ValueError, match="independently"):
        benchmark.aggregate_runs(bad)
    bad = copy.deepcopy(runs)
    bad[2]["tool_calls_per_case"] = 8
    with pytest.raises(ValueError, match="Incompatible"):
        benchmark.aggregate_runs(bad)


def test_failed_run_remains_a_failure_without_partial_metrics(tmp_path):
    manifest = report_files(tmp_path)
    manifest["status"] = "failed"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    summary = benchmark.summarize_run(tmp_path, 1)
    assert summary["status"] == "failed"
    assert "cases" not in summary
    assert summary["scan_diagnostics"]["processes"] == 4


def test_scan_limits_are_never_hidden_behind_a_passed_status(tmp_path):
    manifest = report_files(tmp_path)
    path = tmp_path / "scan-summaries.json"
    scans = json.loads(path.read_text())
    scans["0"]["candidate_limit_hits"] = 7
    path.write_text(json.dumps(scans))
    with pytest.raises(ValueError, match="explicitly marked"):
        benchmark.summarize_run(tmp_path, 1)
    manifest.update(status="completed_with_limits", report_scan_limits=True)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    summary = benchmark.summarize_run(tmp_path, 1)
    assert summary["status"] == "completed_with_limits"
    assert not summary["checks"]["full_endpoint_scans"]
    assert summary["scan_diagnostics"]["candidate_limit_hits"] == 7


@pytest.mark.parametrize("problem", ["cleanup", "record_count", "timings"])
def test_incomplete_validation_cannot_be_published_as_success(tmp_path, problem):
    manifest = report_files(tmp_path)
    if problem == "cleanup":
        manifest["raw_memory_deleted"] = False
    elif problem == "timings":
        manifest["timings_seconds"]["plugin_cli_seconds"] = [1.0]
    else:
        path = tmp_path / "comparison.json"
        data = json.loads(path.read_text())
        data["artifact_records_byte_verified"] = 999
        path.write_text(json.dumps(data))
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        benchmark.summarize_run(tmp_path, 1)
