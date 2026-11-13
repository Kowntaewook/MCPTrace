"""Run separate SDK clients and score timed QEMU RAM captures sequentially."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from validation.linux_x64_official.score import score
from validation.linux_x64_positive.capture_qmp import QMP

ROOT = Path(__file__).resolve().parents[2]


def remote(args, command: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "ssh",
            "-i",
            str(args.ssh_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"UserKnownHostsFile={args.known_hosts}",
            "-o",
            "ConnectTimeout=5",
            "-p",
            str(args.ssh_port),
            args.ssh_target,
            command,
        ],
        check=check,
        text=True,
        capture_output=True,
        timeout=30,
    )


def copy_from_guest(args, source: Path, destination: Path) -> None:
    subprocess.run(
        [
            "scp",
            "-q",
            "-i",
            str(args.ssh_key),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"UserKnownHostsFile={args.known_hosts}",
            "-P",
            str(args.ssh_port),
            f"{args.ssh_target}:{source}",
            str(destination),
        ],
        check=True,
        timeout=30,
    )


def one_capture(args, delay: int, repetition: int) -> dict:
    run_id = f"d{delay}-r{repetition}"
    folder = args.output / run_id
    folder.mkdir(parents=True, exist_ok=False)
    guest_output = args.guest_runs / run_id
    client = args.guest_fixture / "client.py"
    command = " ".join(
        shlex.quote(value)
        for value in (
            "nohup",
            str(args.guest_python),
            str(client),
            "--run-id",
            run_id,
            "--output",
            str(guest_output),
            "--tool-calls",
            str(args.tool_calls),
            "--hold-seconds",
            "300",
        )
    )
    launch = f"{command} >{shlex.quote(str(guest_output) + '.log')} 2>&1 </dev/null &"
    remote(args, launch)
    started = time.monotonic()
    ready_remote = guest_output / "ready.json"
    while True:
        if remote(args, f"test -f {shlex.quote(str(ready_remote))}", check=False).returncode == 0:
            detected = time.monotonic()
            break
        if time.monotonic() - started > 90:
            raise TimeoutError(f"{run_id}: SDK client did not become ready")
        time.sleep(0.1)
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
    observed_delay = paused - detected
    ready, wire = folder / "ready.json", folder / "wire.jsonl"
    copy_from_guest(args, ready_remote, ready)
    copy_from_guest(args, guest_output / "wire.jsonl", wire)
    pid = json.loads(ready.read_text(encoding="utf-8"))["client_pid"]
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
                timeout=300,
            )
    export = exports / f"mcptrace.pid-{pid}.jsonl"
    result = score(
        image=image,
        symbols=args.symbols,
        cache=args.cache,
        config=config,
        ready=ready,
        wire=wire,
        export=export,
        requested_delay=delay,
        observed_delay=observed_delay,
    )
    result["run_id"] = run_id
    result["ready_detection_latency_upper_bound_seconds"] = detected - started
    report = folder / "score.json"
    report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    remote(args, f"touch {shlex.quote(str(guest_output / 'stop'))}")
    image.unlink()  # Never accumulate several 1.5 GiB RAM captures.
    return result


def summarize(runs: list[dict], repetitions: int, tool_calls: int) -> dict:
    if not runs or {run["mcp_sdk"] for run in runs} != {"1.26.0"}:
        raise ValueError("missing runs or inconsistent official SDK version")
    count_keys = (
        "wire_messages",
        "wire_present_utf8",
        "wire_present_utf16le",
        "carved_logical_messages",
        "confirmed_scan_misses",
        "artifact_records",
        "unmatched_artifact_records",
    )
    delays = sorted({run["requested_delay_seconds"] for run in runs})
    if any(
        sum(run["requested_delay_seconds"] == delay for run in runs) != repetitions
        for delay in delays
    ):
        raise ValueError("incomplete delay/repetition matrix")
    return {
        "schema_version": 1,
        "status": "completed",
        "mcp_sdk": "1.26.0",
        "repetitions_per_delay": repetitions,
        "tool_calls_per_run": tool_calls,
        "captures": [
            {
                **{
                    key: run[key]
                    for key in (
                        "run_id",
                        "requested_delay_seconds",
                        "observed_ready_detection_to_pause_seconds",
                        "ready_detection_latency_upper_bound_seconds",
                        "image_sha256",
                        "image_bytes",
                        "wire_log_sha256",
                        "export_sha256",
                        "wire_messages",
                        "wire_present_utf8",
                        "wire_present_utf16le",
                        "carved_logical_messages",
                        "confirmed_scan_misses",
                        "artifact_records",
                        "artifacts_reread_at_virtual_address",
                        "unmatched_artifact_records",
                    )
                },
                "scan_unreadable_bytes": run["scan_summary"]["unreadable_bytes"],
                "scan_candidate_limit_hits": run["scan_summary"]["candidate_limit_hits"],
                "scan_limits_hit": run["scan_summary"]["limits_hit"],
            }
            for run in runs
        ],
        "by_delay": {
            str(delay): {
                key: sum(run[key] for run in runs if run["requested_delay_seconds"] == delay)
                for key in count_keys
            }
            for delay in delays
        },
        "totals": {key: sum(run[key] for run in runs) for key in count_keys},
        "limitations": (
            "Separate client processes and RAM captures share one guest VM. "
            "The ready-file poll adds latency to the requested capture delay. "
            "No client frame journal was used; exact-wire absence does not rule out "
            "other in-memory serializations."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "qmp",
        "ssh-key",
        "known-hosts",
        "guest-fixture",
        "guest-python",
        "guest-runs",
        "vol",
        "symbols",
        "cache",
        "output",
    ):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ssh-target", default="ubuntu@127.0.0.1")
    parser.add_argument("--delays", type=int, nargs="+", default=[0, 5, 30])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--tool-calls", type=int, default=4)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    runs = []
    for delay in args.delays:
        for repetition in range(1, args.repetitions + 1):
            print(f"running delay={delay}s repetition={repetition}", flush=True)
            try:
                runs.append(one_capture(args, delay, repetition))
            except Exception:
                guest_stop = args.guest_runs / f"d{delay}-r{repetition}" / "stop"
                remote(args, f"touch {shlex.quote(str(guest_stop))}", check=False)
                raise
            print(
                f"  wire={runs[-1]['wire_messages']} carved={runs[-1]['carved_logical_messages']} "
                f"confirmed_misses={runs[-1]['confirmed_scan_misses']}",
                flush=True,
            )
    summary = summarize(runs, args.repetitions, args.tool_calls)
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
