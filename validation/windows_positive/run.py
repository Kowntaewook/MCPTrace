"""Acquire and analyze an ephemeral Windows VM running known real MCP traffic."""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

from mcp.client.stdio import get_default_environment
from score import canonical, score_case, verify_exports

WINPMEM_URL = (
    "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/"
    "go-winpmem_amd64_1.0-rc2_signed.exe"
)
WINPMEM_SHA256 = "86691bb4af2c17dd9ec4834c04a99ad51e04f780a07d1b05bc382a5d1892e0c4"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(16 * 1024**2):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def command(args, stdout, stderr, timeout=300):
    started = time.perf_counter()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        completed = subprocess.run(args, stdout=out, stderr=err, timeout=timeout, check=False)
    if completed.returncode:
        raise RuntimeError(
            f"Command failed ({completed.returncode}); see {stdout.name}/{stderr.name}"
        )
    return time.perf_counter() - started


def physical_ram():
    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_uint32),
            ("load", ctypes.c_uint32),
            *[
                (name, ctypes.c_uint64)
                for name in (
                    "total_physical",
                    "available_physical",
                    "total_page_file",
                    "available_page_file",
                    "total_virtual",
                    "available_virtual",
                    "available_extended_virtual",
                )
            ],
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise OSError("GlobalMemoryStatusEx failed")
    return status.total_physical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--reportdir", required=True, type=Path)
    parser.add_argument("--tool-calls", type=int, default=8)
    parser.add_argument("--scan-repeats", type=int, default=1)
    parser.add_argument("--report-scan-limits", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.tool_calls <= 512 or not 1 <= args.scan_repeats <= 5:
        parser.error("Require 1..512 tool calls and 1..5 scan repeats")
    if sys.platform != "win32":
        parser.error("Run this acquisition harness on Windows as administrator")
    work, report = args.workdir.resolve(), args.reportdir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    report.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[2]
    pipeline_started = time.perf_counter()
    image = work / "memory.raw"
    timings = {"plugin_cli_seconds": []}
    manifest = {
        "status": "running",
        "stage": "preflight",
        "started_ns": time.time_ns(),
        "platform": platform.platform(),
        "windows_version": platform.version(),
        "python": platform.python_version(),
        "mcp_sdk": importlib.metadata.version("mcp"),
        "volatility": importlib.metadata.version("volatility3"),
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip(),
        "winpmem_url": WINPMEM_URL,
        "winpmem_sha256": WINPMEM_SHA256,
        "physical_ram_bytes": physical_ram(),
        "free_disk_bytes": shutil.disk_usage(work).free,
        "raw_memory_uploaded": False,
        "logical_cpus": os.cpu_count(),
        "tool_calls_per_case": args.tool_calls,
        "scan_repeats": args.scan_repeats,
        "report_scan_limits": args.report_scan_limits,
        "timings_seconds": timings,
    }
    children, cases = [], []

    def checkpoint(stage):
        manifest["stage"] = stage
        write_json(report / "manifest.json", manifest)
        print(f"MCPTrace validation: {stage}", flush=True)

    try:
        checkpoint("preflight")
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("Physical acquisition requires administrator privileges")
        if manifest["free_disk_bytes"] < manifest["physical_ram_bytes"] + 1024**3:
            raise RuntimeError("Not enough free disk space for RAM capture plus analysis")
        tool = work / "winpmem.exe"
        with urllib.request.urlopen(WINPMEM_URL, timeout=60) as src, tool.open("xb") as dst:
            shutil.copyfileobj(src, dst)
        if sha256(tool) != WINPMEM_SHA256:
            raise ValueError("WinPmem release asset SHA-256 mismatch")
        checkpoint("capture-driver-probe")
        command(
            [str(tool), "acquire"], report / "driver-probe.txt", report / "driver-probe.stderr", 90
        )
        checkpoint("real-mcp-traffic")
        for mode in ["natural", "retained"]:
            output = work / mode
            output.mkdir()
            error_log = (report / f"{mode}-workload.stderr").open("wb")
            child_env = get_default_environment()
            child_env.update(PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(repo / "validation/windows_positive/workload.py"),
                    "client",
                    "--run-id",
                    str(uuid.uuid4()),
                    "--output",
                    str(output),
                    "--mode",
                    mode,
                    "--tool-calls",
                    str(args.tool_calls),
                ],
                stdout=subprocess.DEVNULL,
                stderr=error_log,
                env=child_env,
                cwd=repo,
            )
            children.append((proc, output, error_log))
        for proc, output, _ in children:
            deadline = time.monotonic() + 90
            while not (output / "ready.json").exists():
                if proc.poll() is not None:
                    raise RuntimeError(f"{output.name}: MCP workload exited before ready")
                if time.monotonic() > deadline:
                    raise TimeoutError(f"{output.name}: MCP workload did not become ready")
                time.sleep(0.1)
            ready = json.loads((output / "ready.json").read_text(encoding="utf-8"))
            if (
                ready["tool_calls_completed"] != args.tool_calls
                or ready["logged_messages"] != 5 + 2 * args.tool_calls
            ):
                raise RuntimeError("Incomplete MCP ground truth")
            cases.append(ready)
        pids = [c[key] for c in cases for key in ["client_pid", "server_pid"]]
        if len(set(pids)) != 4:
            raise RuntimeError("Expected four distinct live endpoint processes")
        manifest["cases"] = cases
        manifest["capture_started_ns"] = time.time_ns()
        checkpoint("physical-ram-acquisition")
        timings["acquisition"] = command(
            [str(tool), "acquire", str(image)],
            report / "capture.txt",
            report / "capture.stderr",
            300,
        )
        manifest["capture_finished_ns"] = time.time_ns()
        manifest["image_bytes"] = image.stat().st_size
        if image.stat().st_size < 1024**2:
            raise RuntimeError("Capture output is too small to be a physical memory image")
        for proc, output, _ in children:
            if proc.poll() is not None:
                raise RuntimeError("An MCP endpoint exited during capture")
            (output / "stop").touch()
        manifest["image_sha256"] = sha256(image)
        for proc, _, _ in children:
            proc.wait(timeout=15)
        checkpoint("volatility-analysis")
        symbols, cache, export = work / "symbols", work / "cache", work / "exports"
        for path in [symbols, cache, export]:
            path.mkdir()
        common = [
            sys.executable,
            "-c",
            "import sys; sys.argv[0]='vol'; from volatility3.cli import main; main()",
            "-q",
            "--cache-path",
            str(cache),
            "-s",
            str(symbols),
            "-f",
            str(image),
        ]
        # Windows symbols can be fetched during info; subsequent steps are offline.
        timings["symbols_and_info"] = command(
            common + ["-r", "json", "windows.info.Info"],
            report / "info.json",
            report / "info.stderr",
        )
        config = work / "mcptrace-config.json"
        trace_cmd = common + [
            "--offline",
            "-p",
            str(repo / "plugins"),
            "-o",
            str(export),
            "--save-config",
            str(config),
            "-r",
            "json",
            "windows.mcptrace.MCPTrace",
            "--pid",
            *map(str, pids),
            "--dump",
        ]
        manifest["plugin_command"] = trace_cmd
        timings["plugin_cli_seconds"].append(
            command(trace_cmd, work / "all-findings.json", report / "mcptrace.stderr")
        )
        exports = [export / f"mcptrace.pid-{pid}.jsonl" for pid in pids]
        expected_exports = {path.name: sha256(path) for path in exports}
        for repeat in range(1, args.scan_repeats):
            repeated_output = work / f"exports-{repeat + 1}"
            repeated_output.mkdir()
            repeated_cmd = trace_cmd.copy()
            repeated_cmd[repeated_cmd.index("-o") + 1] = str(repeated_output)
            repeated_cmd[repeated_cmd.index("--save-config") + 1] = str(
                work / f"mcptrace-config-{repeat + 1}.json"
            )
            timings["plugin_cli_seconds"].append(
                command(
                    repeated_cmd,
                    work / f"all-findings-{repeat + 1}.json",
                    report / f"mcptrace-{repeat + 1}.stderr",
                )
            )
            if any(
                sha256(repeated_output / name) != digest
                for name, digest in expected_exports.items()
            ):
                raise RuntimeError("Repeated scans of the same image produced different JSONL")
        manifest["repeated_exports_identical"] = True
        checkpoint("byte-verification-and-ground-truth-comparison")
        verification_started = time.perf_counter()
        artifacts, summaries = verify_exports(image, symbols, cache, config, exports)
        timings["native_byte_verification"] = time.perf_counter() - verification_started
        # Persist diagnostics before deciding whether a scan can be scored.
        write_json(report / "scan-summaries.json", summaries)
        limited = False
        for summary in summaries.values():
            if summary["error"] or summary["skipped_reason"] or summary["invalid_regions"]:
                raise RuntimeError("An endpoint scan failed; inspect scan summaries")
            if (
                summary["limits_hit"]
                or summary["anchor_limit_hits"]
                or summary["candidate_limit_hits"]
            ):
                limited = True
        manifest["scan_complete"] = not limited
        if limited and not args.report_scan_limits:
            raise RuntimeError("A selected endpoint scan was incomplete; inspect scan summaries")
        scores, publish_keys = [], set()
        for case in cases:
            mode = case["mode"]
            source, dest = work / mode, report / mode
            dest.mkdir()
            for name in ["ready.json", "ground-truth.jsonl", "unsent-controls.json"]:
                if (source / name).exists():
                    shutil.copyfile(source / name, dest / name)
            truth = [
                json.loads(s)
                for s in (source / "ground-truth.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            decoys = []
            if (source / "unsent-controls.json").exists():
                decoys = [
                    json.loads(base64.b64decode(s))
                    for s in json.loads((source / "unsent-controls.json").read_text())
                ]
            scores.append(score_case(case, truth, artifacts, decoys))
            publish_keys.update(canonical(row["message"]) for row in truth)
            publish_keys.update(canonical(row) for row in decoys)
        # Export only known synthetic workload messages and explicit controls.
        # Raw RAM and unrelated recovered content remain in the disposable VM.
        with (report / "known-test-artifacts.jsonl").open("w", encoding="utf-8") as out:
            for record in artifacts:
                if canonical(record["message"]) in publish_keys:
                    out.write(json.dumps(record, ensure_ascii=True) + "\n")
        result = {
            "cases": scores,
            "artifact_records_byte_verified": len(artifacts),
            "artifact_bytes_verified": sum(r["byte_length"] for r in artifacts),
            "positive_pair_observed": any(s["positive_pair_in_one_pid"] for s in scores),
        }
        write_json(report / "comparison.json", result)
        if sha256(image) != manifest["image_sha256"]:
            raise RuntimeError("RAM image changed during analysis")
        manifest["image_hash_unchanged_after_analysis"] = True
        if not result["positive_pair_observed"]:
            raise RuntimeError("No complete known tool request/response pair recovered")
        if any(s["incorrect_candidate_links"] for s in scores):
            raise RuntimeError("Incorrect candidate links observed in controlled traffic")
        manifest["analysis_status"] = "completed_with_limits" if limited else "passed"
        checkpoint("analysis-completed")
        print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    except BaseException as exc:
        manifest["status"] = "failed"
        manifest["failure"] = f"{type(exc).__name__}: {exc}"
        write_json(report / "manifest.json", manifest)
        raise
    finally:
        try:
            for proc, output, error_log in children:
                (output / "stop").touch()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                error_log.close()
            # This file was created by this run and is never an uploaded artifact.
            image.unlink(missing_ok=True)
        except BaseException as exc:
            manifest["status"] = "failed"
            manifest["cleanup_failure"] = f"{type(exc).__name__}: {exc}"
            write_json(report / "manifest.json", manifest)
            raise
        else:
            manifest["raw_memory_deleted"] = True
            write_json(report / "manifest.json", manifest)
    manifest["status"] = manifest["analysis_status"]
    timings["pipeline_total"] = time.perf_counter() - pipeline_started
    checkpoint("completed")


if __name__ == "__main__":
    main()
