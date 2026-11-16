"""Run one fresh Linux VM client exchange and score its full-RAM capture.

Raw images, traffic and scanner exports stay in --private-root. The report in
--report contains only hashes, counts and per-message flags.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GUEST_SCRIPT = "/home/ubuntu/experiment/guest_case.sh"
CASES = {"inspector-http", "inspector-stdio", "lsp-control", "jsonrpc-control",
         "codex-stdio"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--min-age-seconds", type=int, default=0)
    parser.add_argument("--ssh-port", type=int, default=2223)
    parser.add_argument("--ssh-target", default="ubuntu@127.0.0.1")
    for name in ("private-root", "ssh-key", "known-hosts", "qmp", "symbols",
                 "cache", "vol", "report"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9-]+", args.run_id):
        parser.error("--run-id must contain lowercase letters, digits and hyphens")
    if not re.fullmatch(r"[A-Z0-9_]+", args.marker):
        parser.error("--marker must be synthetic uppercase letters, digits and underscores")
    if not 0 <= args.min_age_seconds <= 300:
        parser.error("--min-age-seconds must be 0..300")
    if args.case == "inspector-http" and not 1024 <= args.port <= 65535:
        parser.error("inspector-http requires --port")
    guest_dir = f"/home/ubuntu/experiment/repeat/{args.run_id}"
    private = args.private_root.resolve()
    capture_dir = private / "captures" / args.run_id
    if capture_dir.exists() or args.report.exists():
        parser.error("capture or report already exists")
    ssh_base = ["ssh", "-i", str(args.ssh_key.resolve()), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o",
                f"UserKnownHostsFile={args.known_hosts.resolve()}", "-p",
                str(args.ssh_port), args.ssh_target]
    scp_base = ["scp", "-i", str(args.ssh_key.resolve()), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o",
                f"UserKnownHostsFile={args.known_hosts.resolve()}", "-P",
                str(args.ssh_port)]
    subprocess.run([*scp_base, str(ROOT / "validation/linux_x64_repeat/guest_case.sh"),
                    f"{args.ssh_target}:{GUEST_SCRIPT}"], check=True, timeout=60)

    def guest(*words: str, timeout: int = 300) -> None:
        remote = " ".join(shlex.quote(word) for word in ("bash", GUEST_SCRIPT, *words))
        subprocess.run([*ssh_base, remote], check=True, timeout=timeout)

    started = False
    try:
        guest("start", args.case, args.run_id, args.marker, str(args.port))
        started = True
        if args.min_age_seconds:
            time.sleep(args.min_age_seconds)
        command = [sys.executable, str(ROOT / "validation/linux_x64_real_host_ram/capture.py"),
                   "--case", args.case, "--ssh-port", str(args.ssh_port),
                   "--ssh-target", args.ssh_target, "--qmp", str(args.qmp),
                   "--ssh-key", str(args.ssh_key), "--known-hosts", str(args.known_hosts),
                   "--guest-ready", f"{guest_dir}/client-ready.json",
                   "--guest-traffic", f"{guest_dir}/traffic.jsonl",
                   "--guest-event-file", f"{guest_dir}/event-complete",
                   "--private-dir", str(capture_dir), "--symbols", str(args.symbols),
                   "--cache", str(args.cache), "--vol", str(args.vol),
                   "--report", str(args.report)]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT)
        subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=1800)
        report = json.loads(args.report.read_text())
        report["run_id"] = args.run_id
        report["planned_minimum_event_age_seconds"] = args.min_age_seconds
        report["experiment_group"] = "independent fresh-process Linux live-host repeats"
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"case": args.case, "run_id": args.run_id,
                          "pid": report["client_pid"],
                          "logged": report["traffic_messages"],
                          "present": report["wire_present_any_encoding"],
                          "carved": report["carved_logged_messages"],
                          "mcp_labeled": report["mcp_labeled_logged_messages"],
                          "event_age_seconds": report["event_age_at_pre_capture_probe_seconds"]}),
              flush=True)
    finally:
        if started:
            guest("stop", args.case, args.run_id, timeout=90)


if __name__ == "__main__":
    main()
