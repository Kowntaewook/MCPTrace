"""Capture one running Linux guest client from QEMU and score its full RAM.

The guest must already hold a live client and immutable traffic journal. Raw
RAM, SSH material, traffic, and Volatility exports stay in the private folder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from validation.linux_x64_positive.capture_qmp import QMP
from validation.linux_x64_positive.score import sha256
from validation.linux_x64_real_host_ram.score import CASES, score


ROOT = Path(__file__).resolve().parents[2]


def ssh_args(args: argparse.Namespace) -> list[str]:
    return ["-i", str(args.ssh_key), "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={args.known_hosts}"]


def copy_from_guest(args: argparse.Namespace, source: str, destination: Path) -> None:
    subprocess.run(["scp", "-q", *ssh_args(args), "-P", str(args.ssh_port),
                    f"{args.ssh_target}:{source}", str(destination)],
                   check=True, timeout=120)


def assert_alive(args: argparse.Namespace, pid: int) -> None:
    subprocess.run(["ssh", *ssh_args(args), "-p", str(args.ssh_port),
                    args.ssh_target, f"kill -0 {pid}"],
                   check=True, timeout=30, capture_output=True)


def guest_event_age(args: argparse.Namespace) -> float | None:
    """Measure a guest completion marker's age immediately before QMP stop."""
    if not args.guest_event_file:
        return None
    probe = ("import os,sys,time; "
             "print((time.time_ns()-os.stat(sys.argv[1]).st_mtime_ns)/1e9)")
    remote = f"python3 -c {shlex.quote(probe)} {shlex.quote(args.guest_event_file)}"
    result = subprocess.run(["ssh", *ssh_args(args), "-p", str(args.ssh_port),
                             args.ssh_target, remote],
                            check=True, timeout=30, capture_output=True, text=True)
    age = float(result.stdout.strip())
    if age < 0:
        raise ValueError("guest completion marker has a future timestamp")
    return round(age, 3)


def archive_image(image: Path, destination: Path, image_hash: str) -> tuple[str, int]:
    subprocess.run(["zstd", "-q", "-3", "-o", str(destination), str(image)],
                   check=True, timeout=900)
    recovered = hashlib.sha256()
    with subprocess.Popen(["zstd", "-q", "-d", "-c", str(destination)],
                          stdout=subprocess.PIPE) as decoder:
        assert decoder.stdout is not None
        for chunk in iter(lambda: decoder.stdout.read(4 * 1024 * 1024), b""):
            recovered.update(chunk)
        if decoder.wait(timeout=900) != 0 or recovered.hexdigest() != image_hash:
            raise ValueError("compressed RAM did not reconstruct to the captured SHA-256")
    return sha256(destination), destination.stat().st_size


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ssh-target", default="ubuntu@127.0.0.1")
    parser.add_argument("--guest-event-file", type=str,
                        help="Guest file written after the last tool result or control response")
    for name in ("qmp", "ssh-key", "known-hosts", "guest-ready", "guest-traffic",
                 "private-dir", "symbols", "cache", "vol", "report"):
        parser.add_argument(f"--{name}", required=True,
                            type=str if name.startswith("guest-") else Path)
    args = parser.parse_args()
    private = args.private_dir.resolve()
    private.mkdir(parents=True, exist_ok=False)
    ready = private / "client-ready.json"
    traffic_before = private / "traffic.before.jsonl"
    traffic = private / "traffic.jsonl"
    copy_from_guest(args, args.guest_ready, ready)
    copy_from_guest(args, args.guest_traffic, traffic_before)
    pid = int(json.loads(ready.read_text(encoding="utf-8"))["pid"])
    assert_alive(args, pid)
    event_age = guest_event_age(args)
    image = private / "ram.elf"
    qmp = QMP(args.qmp)
    started = time.monotonic()
    try:
        qmp.command("stop")
        try:
            qmp.command("dump-guest-memory", {"paging": False, "protocol": f"file:{image}"})
        finally:
            qmp.command("cont")
    finally:
        qmp.close()
    capture_seconds = round(time.monotonic() - started, 3)
    copy_from_guest(args, args.guest_traffic, traffic)
    if sha256(traffic_before) != sha256(traffic):
        raise ValueError("traffic journal changed during acquisition")
    assert_alive(args, pid)

    exports = private / "exports"
    exports.mkdir()
    config = private / "config.json"
    command = [str(args.vol.resolve()), "-q", "--cache-path", str(args.cache.resolve()),
               "-s", str(args.symbols.resolve()), "-p", str(ROOT / "plugins"),
               "-f", str(image), "-o", str(exports), "--save-config", str(config),
               "linux.mcptrace.MCPTrace", "--pid", str(pid), "--include-rpc", "--dump"]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT)
    with (private / "vol-stdout.txt").open("w") as stdout, (private / "vol-stderr.txt").open("w") as stderr:
        subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr,
                       check=True, timeout=900)
    export = exports / f"mcptrace.pid-{pid}.jsonl"
    if not export.is_file():
        raise ValueError("Volatility did not export the expected client PID")
    result = score(case=args.case, image=image, symbols=args.symbols, cache=args.cache,
                   config=config, ready=ready, traffic=traffic, export=export)
    result["qmp_pause_and_capture_seconds"] = capture_seconds
    if event_age is not None:
        result["event_age_at_pre_capture_probe_seconds"] = event_age
        result["event_age_reference"] = "guest file mtime measured immediately before QMP stop"
    image_hash = result["image_sha256"]
    archive = private / "ram.elf.zst"
    archive_hash, archive_size = archive_image(image, archive, image_hash)
    result["private_ram_archive_sha256"] = archive_hash
    result["private_ram_archive_bytes"] = archive_size
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    image.unlink()
    print(json.dumps({"case": args.case, "pid": pid, "report": str(args.report),
                      "wire_present": result["wire_present_any_encoding"],
                      "carved": result["carved_logged_messages"],
                      "mcp_candidate_records": result["mcp_candidate_records"]}))


if __name__ == "__main__":
    main()
