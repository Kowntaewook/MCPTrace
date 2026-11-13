"""Capture and score real HTTP/SSE SDK clients in QEMU Linux x86-64 RAM."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from validation.linux_x64_http_ram.score import score
from validation.linux_x64_official.run import copy_from_guest, remote
from validation.linux_x64_positive.capture_qmp import QMP

ROOT = Path(__file__).resolve().parents[2]
CASES = ("node", "dotnet-legacy", "dotnet-modern")


def wait_guest_file(args, path: Path, log: Path, timeout: float) -> float:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if remote(args, f"test -f {shlex.quote(str(path))}", check=False).returncode == 0:
            return time.monotonic()
        time.sleep(0.1)
    detail = remote(args, f"tail -n 25 {shlex.quote(str(log))}", check=False)
    raise TimeoutError(f"guest did not write {path}: {detail.stdout} {detail.stderr}")


def launch(args, command: list[str], log: Path) -> None:
    quoted = " ".join(shlex.quote(value) for value in ["nohup", *command])
    remote(args, f"{quoted} >{shlex.quote(str(log))} 2>&1 </dev/null &")


def one_capture(args, case: str, delay: int, repetition: int, port: int) -> dict:
    run_id = f"{case}-d{delay}-r{repetition}"
    folder = args.output / run_id
    folder.mkdir(parents=True, exist_ok=False)
    guest_output = args.guest_runs / run_id
    remote(args, f"mkdir -p {shlex.quote(str(guest_output))}")
    fixture = args.guest_fixture / "node_fixture.mjs"
    server_command = [str(args.guest_node), str(fixture), "server", str(guest_output), str(port)]
    marker = f"{case.upper().replace('-', '_')}_{run_id}"
    if case == "node":
        client_command = [
            str(args.guest_node),
            str(fixture),
            "client",
            str(guest_output),
            str(port),
            marker,
        ]
    else:
        client_command = [
            str(args.guest_dotnet),
            str(args.guest_dotnet_client),
            str(guest_output),
            str(port),
            marker,
        ]
        if case == "dotnet-modern":
            client_command.append("modern")
    try:
        launch(args, server_command, guest_output / "server.log")
        wait_guest_file(args, guest_output / "server-ready.json", guest_output / "server.log", 90)
        started = time.monotonic()
        launch(args, client_command, guest_output / "client.log")
        detected = wait_guest_file(
            args, guest_output / "client-ready.json", guest_output / "client.log", 180
        )
        if delay:
            time.sleep(delay)
        image = folder / "ram.elf"
        qmp = QMP(args.qmp)
        try:
            qmp.command("stop")
            paused = time.monotonic()
            try:
                qmp.command("dump-guest-memory", {"paging": False, "protocol": f"file:{image}"})
            finally:
                qmp.command("cont")
        finally:
            qmp.close()
        ready, traffic = folder / "client-ready.json", folder / "traffic.jsonl"
        copy_from_guest(args, guest_output / "client-ready.json", ready)
        copy_from_guest(args, guest_output / "traffic.jsonl", traffic)
        pid = json.loads(ready.read_text(encoding="utf-8"))["pid"]
        exports = folder / "exports"
        exports.mkdir()
        config = folder / "config.json"
        command = [
            str(args.vol),
            "-q",
            "--cache-path",
            str(args.cache),
            "-s",
            str(args.symbols),
            "-p",
            str(ROOT / "plugins"),
            "-f",
            str(image),
            "-o",
            str(exports),
            "--save-config",
            str(config),
            "linux.mcptrace.MCPTrace",
            "--pid",
            str(pid),
            "--include-rpc",
            "--dump",
        ]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        with (folder / "vol-stdout.txt").open("w") as stdout:
            with (folder / "vol-stderr.txt").open("w") as stderr:
                subprocess.run(
                    command,
                    cwd=ROOT,
                    env=env,
                    stdout=stdout,
                    stderr=stderr,
                    check=True,
                    timeout=600,
                )
        result = score(
            case=case,
            image=image,
            symbols=args.symbols,
            cache=args.cache,
            config=config,
            ready=ready,
            traffic=traffic,
            export=exports / f"mcptrace.pid-{pid}.jsonl",
            requested_delay=delay,
            observed_delay=paused - detected,
            detection_bound=detected - started,
        )
        result["run_id"] = run_id
        (folder / "score.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        image.unlink()  # Only one multi-GiB RAM image exists at a time.
        return result
    finally:
        for name in ("client-stop", "server-stop"):
            try:
                remote(args, f"touch {shlex.quote(str(guest_output / name))}", check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass


def summarize(runs: list[dict], repetitions: int, cases: list[str], delays: list[int]) -> dict:
    expected = {
        f"{case}-d{delay}-r{rep}"
        for case in cases
        for delay in delays
        for rep in range(1, repetitions + 1)
    }
    if {run["run_id"] for run in runs} != expected or len(runs) != len(expected):
        raise ValueError("incomplete or duplicate case/delay/repetition matrix")
    counts = (
        "traffic_messages",
        "sse_response_messages",
        "wire_present_utf8",
        "wire_present_utf16le",
        "carved_logical_messages",
        "confirmed_scan_misses",
        "artifact_records",
        "mcp_candidate_records",
        "unmatched_artifact_records",
    )
    selected = (
        "run_id",
        "case",
        "requested_delay_seconds",
        "observed_ready_detection_to_pause_seconds",
        "client_launch_to_readiness_detection_upper_bound_seconds",
        "image_sha256",
        "image_bytes",
        "traffic_log_sha256",
        "export_sha256",
        "artifacts_reread_at_virtual_address",
        *counts,
    )
    return {
        "schema_version": 1,
        "status": "completed",
        "repetitions_per_case_delay": repetitions,
        "captures": [
            {
                **{key: run[key] for key in selected},
                "scan_unreadable_bytes": run["scan_summary"]["unreadable_bytes"],
                "scan_candidate_limit_hits": run["scan_summary"]["candidate_limit_hits"],
                "scan_limits_hit": run["scan_summary"]["limits_hit"],
            }
            for run in runs
        ],
        "by_case": {
            case: {key: sum(run[key] for run in runs if run["case"] == case) for key in counts}
            for case in cases
        },
        "totals": {key: sum(run[key] for run in runs) for key in counts},
        "limitations": (
            "Node uses official client and server SDKs. .NET uses an official C# client "
            "and a purpose-built local HTTP peer. The same guest VM hosts fresh client "
            "processes. A host readiness poll adds latency to nominal capture delays. "
            "Exact wire absence does not rule out other serializations."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "qmp",
        "ssh-key",
        "known-hosts",
        "guest-fixture",
        "guest-node",
        "guest-dotnet",
        "guest-dotnet-client",
        "guest-runs",
        "vol",
        "symbols",
        "cache",
        "output",
    ):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ssh-target", default="ubuntu@127.0.0.1")
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--delays", type=int, nargs="+", default=[0, 5, 30])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--base-port", type=int, default=19000)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    runs = []
    index = 0
    for case in args.cases:
        for delay in args.delays:
            for repetition in range(1, args.repetitions + 1):
                index += 1
                print(f"running {case} delay={delay}s repetition={repetition}", flush=True)
                run_id = f"{case}-d{delay}-r{repetition}"
                completed = args.output / run_id / "score.json"
                if completed.exists():
                    run = json.loads(completed.read_text(encoding="utf-8"))
                    if (
                        run.get("run_id") != run_id
                        or run.get("case") != case
                        or run.get("requested_delay_seconds") != delay
                    ):
                        raise ValueError(f"invalid completed score for {run_id}")
                    print("  reusing verified score", flush=True)
                else:
                    run = one_capture(args, case, delay, repetition, args.base_port + index)
                runs.append(run)
                print(
                    f"  wire={run['traffic_messages']} utf8={run['wire_present_utf8']} "
                    f"utf16le={run['wire_present_utf16le']} carved="
                    f"{run['carved_logical_messages']} misses={run['confirmed_scan_misses']}",
                    flush=True,
                )
    summary = summarize(runs, args.repetitions, args.cases, args.delays)
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
