"""Same-image Windows RAM comparison of two MCPTrace revisions.

This is called from the existing ephemeral positive-memory harness after capture.
Only allowlisted numeric results are published; all RAM and raw artifacts are
deleted by the parent harness, even if this comparison fails.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

from score import canonical, score_case, verify_exports


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _scan(root: Path, template: list[str], directory: Path, timeout=300):
    """Measure CLI elapsed time and Windows process peak working set."""
    import psutil

    directory.mkdir(parents=True)
    export_dir = directory / "exports"
    export_dir.mkdir()
    config_file = directory / "config.json"
    cmd = template.copy()
    cmd[cmd.index("-p") + 1] = str(root / "plugins")
    cmd[cmd.index("-o") + 1] = str(export_dir)
    cmd[cmd.index("--save-config") + 1] = str(config_file)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    started = time.perf_counter()
    peak = 0
    with (directory / "stdout.json").open("wb") as stdout:
        with (directory / "stderr.txt").open("wb") as stderr:
            with subprocess.Popen(
                cmd, cwd=root, env=env, stdout=stdout, stderr=stderr
            ) as proc:
                worker = psutil.Process(proc.pid)
                while proc.poll() is None:
                    if time.perf_counter() - started > timeout:
                        proc.kill()
                        proc.wait()
                        raise TimeoutError("Volatility comparison scan timed out")
                    try:
                        memory = worker.memory_info()
                        peak = max(peak, int(getattr(memory, "peak_wset", memory.rss)))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    time.sleep(0.05)
                status = proc.wait()
    elapsed = time.perf_counter() - started
    if status:
        raise RuntimeError(
            f"Comparison scanner failed with exit code {status}; "
            "review temporary runner logs"
        )
    if not peak:
        raise RuntimeError("No valid process peak working set measurement")
    return {
        "elapsed_seconds": elapsed,
        "peak_working_set_bytes": peak,
        "export_directory": export_dir,
        "config": config_file,
    }


def _score(cases, work, artifacts):
    by_mode = {}
    for case in cases:
        folder = work / case["mode"]
        truth = [_read_json_line for _read_json_line in (
            json.loads(line)
            for line in (folder / "ground-truth.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        )]
        decoys = []
        control = folder / "unsent-controls.json"
        if control.exists():
            decoys = [
                json.loads(base64.b64decode(item))
                for item in _read_json(control)
            ]
        result = score_case(case, truth, artifacts, decoys)
        by_mode[case["mode"]] = {
            "expected_messages": result["expected_logical_messages"],
            "recovered_messages": result["distinct_expected_messages_found"],
            "expected_tool_pairs": result["expected_tool_pairs"],
            "recovered_tool_pairs": result["complete_tool_pairs_any_endpoint"],
            "unsent_controls_found": result["distinct_unsent_controls_found"],
            "incorrect_candidate_links": result["incorrect_candidate_links"],
            "unmatched_artifact_records": result["unmatched_artifact_records"],
        }
    return by_mode


def compare_variants(
    *,
    baseline_root: Path,
    candidate_root: Path,
    template: list[str],
    work: Path,
    report: Path,
    image: Path,
    symbols: Path,
    cache: Path,
    cases: list[dict],
    pids: list[int],
    image_sha256: str,
    candidate_sha: str,
):
    if sys.platform != "win32":
        raise RuntimeError("Same-RAM benchmark requires a Windows acquisition runner")
    if not (baseline_root / "mcptrace/core.py").is_file():
        raise ValueError("Baseline checkout is missing core.py")
    if not (candidate_root / "mcptrace/core.py").is_file():
        raise ValueError("Candidate checkout is missing core.py")
    baseline_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=baseline_root, text=True
    ).strip()
    if baseline_sha == candidate_sha:
        raise RuntimeError("Baseline and candidate commits must be different")
    root = work / "paired-comparison"
    root.mkdir()
    roots = {"baseline": baseline_root, "candidate": candidate_root}
    measurements = {"baseline": [], "candidate": []}
    exports = {}
    # Balanced order ABBA, after symbol preparation: each revision first once.
    for index, variant in enumerate(("baseline", "candidate", "candidate", "baseline")):
        iteration = len(measurements[variant]) + 1
        directory = root / f"{index + 1:02d}-{variant}"
        run = _scan(roots[variant], template, directory)
        run["iteration"] = iteration
        measurements[variant].append(run)
        exports.setdefault(variant, run)

    for variant, runs in measurements.items():
        pids_and_hashes = None
        for run in runs:
            per_process = {
                pid: (run["export_directory"] / f"mcptrace.pid-{pid}.jsonl")
                for pid in pids
            }
            current = {
                pid: hashlib.sha256(file.read_bytes()).hexdigest()
                for pid, file in per_process.items()
            }
            if pids_and_hashes is not None and current != pids_and_hashes:
                raise RuntimeError(f"{variant} scans did not produce identical JSONL")
            pids_and_hashes = current

    results = {}
    fingerprints = {}
    for variant, run in exports.items():
        export_paths = [
            run["export_directory"] / f"mcptrace.pid-{pid}.jsonl"
            for pid in pids
        ]
        artifacts, summaries = verify_exports(
            image, symbols, cache, run["config"], export_paths
        )
        for summary in summaries.values():
            if summary["error"] or summary["skipped_reason"] or summary["invalid_regions"]:
                raise RuntimeError(f"{variant}: incomplete or erroneous process scan")
        fingerprints[variant] = {
            (record["pid"], record["virtual_address"], record["raw_sha256"])
            for record in artifacts
        }
        results[variant] = {
            "revision": baseline_sha if variant == "baseline" else candidate_sha,
            "modes": _score(cases, work, artifacts),
            "exported_records": len(artifacts),
            "exported_bytes": sum(row["byte_length"] for row in artifacts),
            "limited_processes": sum(
                bool(s["limits_hit"] or s["anchor_limit_hits"] or s["candidate_limit_hits"])
                for s in summaries.values()
            ),
            "runtime_seconds": [run["elapsed_seconds"] for run in measurements[variant]],
            "peak_working_set_bytes": [
                run["peak_working_set_bytes"] for run in measurements[variant]
            ],
        }
    # Never export underlying raw bytes, process identifiers, paths, or tool calls.
    matched = fingerprints["baseline"] == fingerprints["candidate"]
    result = {
        "schema_version": 1,
        "status": "passed",
        "same_image": True,
        "capture_sha256": image_sha256,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "scan_order": ["baseline", "candidate", "candidate", "baseline"],
        "repetitions_per_variant": 2,
        "memory_metric": "Windows process peak working set bytes (psutil peak_wset)",
        "variants": results,
        "identical_evidence_records": matched,
        "delta_candidate_minus_baseline": {
            "median_runtime_seconds": (
                statistics.median(results["candidate"]["runtime_seconds"])
                - statistics.median(results["baseline"]["runtime_seconds"])
            ),
            "median_peak_working_set_bytes": (
                statistics.median(results["candidate"]["peak_working_set_bytes"])
                - statistics.median(results["baseline"]["peak_working_set_bytes"])
            ),
            "per_mode": {
                mode: {
                    field: results["candidate"]["modes"][mode][field]
                    - results["baseline"]["modes"][mode][field]
                    for field in ("recovered_messages", "recovered_tool_pairs")
                }
                for mode in ("natural", "retained")
            },
        },
        "caveats": (
            "Two repeated scans per variant on one captured image are not "
            "independent recovery observations. Alternating order mitigates but "
            "does not eliminate runner-cache effects. The memory metric is "
            "process peak working set, not private heap or system-wide memory. "
            "This SDK/stdio fixture is not general MCP recall or precision."
        ),
    }
    (report / "variant-comparison.json").write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    if not matched:
        raise RuntimeError("Regression: baseline and candidate recovered different raw artifacts")
    return result
