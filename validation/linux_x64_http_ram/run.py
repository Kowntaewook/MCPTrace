"""Capture and score real HTTP/SSE SDK clients in QEMU Linux x86-64 RAM."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from validation.linux_x64_http_ram.archive import make_patch_archive, verify_patch_archive
from validation.linux_x64_http_ram.score import score
from validation.linux_x64_official.run import copy_from_guest, remote
from validation.linux_x64_positive.capture_qmp import QMP
from validation.linux_x64_positive.score import sha256

ROOT = Path(__file__).resolve().parents[2]
CASES = ("node", "dotnet-legacy", "dotnet-modern")


def archive_and_upload(args, image: Path, run_id: str, image_sha256: str) -> dict:
    """Keep a hash-checked RAM image as a full or lossless patch release asset."""
    args.archive_dir.mkdir(parents=True, exist_ok=True)
    patch = args.archive_base_image is not None and run_id != "node-d0-r1"
    if patch and (not args.archive_base_image.exists() or args.archive_base_sha256 is None):
        raise ValueError("archive base RAM image is unavailable")
    suffix = "ram.elf.patch.tar" if patch else "ram.elf.zst"
    archive = args.archive_dir / f"mcptrace-{run_id}-{suffix}"
    patch_manifest = None
    if patch:
        if not archive.exists():
            patch_manifest = make_patch_archive(
                args.archive_base_image,
                image,
                archive,
                base_sha256=args.archive_base_sha256,
                image_sha256=image_sha256,
            )
        patch_manifest = verify_patch_archive(
            args.archive_base_image, archive, image_sha256, args.archive_base_sha256
        )
    else:
        if not archive.exists():
            command = ["zstd", "-q", "-T2", "-3"]
            subprocess.run(
                [*command, "-o", str(archive), str(image)],
                check=True,
                timeout=600,
            )
        subprocess.run(["zstd", "-q", "-t", str(archive)], check=True, timeout=600)
    size = archive.stat().st_size
    if size >= 2 * 1024**3:
        raise ValueError(f"{archive.name} exceeds GitHub's 2 GiB release asset limit")
    digest = sha256(archive)
    result = {
        "name": archive.name,
        "format": "zstd-chunk-patch-tar" if patch else "zstd",
        "sha256": digest,
        "bytes": size,
    }
    if patch:
        result["base_asset_name"] = "mcptrace-node-d0-r1-ram.elf.zst"
        result["base_image_sha256"] = args.archive_base_sha256
        result["chunk_bytes"] = patch_manifest["chunk_bytes"]
        result["part_count"] = patch_manifest["part_count"]
    if args.archive_local_only:
        result["local_path"] = str(archive)
        return result
    asset = None
    for attempt in range(3):
        try:
            subprocess.run(
                [
                    "gh",
                    "release",
                    "upload",
                    args.archive_release,
                    str(archive),
                    "--clobber",
                    "--repo",
                    args.archive_repo,
                ],
                cwd=ROOT,
                check=True,
                timeout=3600,
                capture_output=True,
                text=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise
            time.sleep(3 * (attempt + 1))
            continue
        for inspection in range(10):
            try:
                release = json.loads(
                    subprocess.check_output(
                        [
                            "gh",
                            "api",
                            f"repos/{args.archive_repo}/releases/{args.archive_release_id}",
                        ],
                        cwd=ROOT,
                        text=True,
                        timeout=30,
                    )
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                if inspection == 9:
                    raise
                time.sleep(3)
                continue
            assets = [row for row in release["assets"] if row["name"] == archive.name]
            if len(assets) == 1 and assets[0]["size"] == size:
                asset = assets[0]
                remote_digest = asset.get("digest")
                if remote_digest == f"sha256:{digest}":
                    break
                if remote_digest is not None:
                    raise ValueError(f"uploaded asset digest mismatch: {archive.name}")
            if inspection == 9:
                raise ValueError(f"uploaded asset metadata unavailable: {archive.name}")
            time.sleep(3)
        if asset is not None:
            break
    if asset is None:
        raise RuntimeError(f"no verified release asset: {archive.name}")
    result.update(
        github_asset_id=asset["id"],
        github_asset_digest=asset.get("digest"),
        url=(
            f"https://github.com/{args.archive_repo}/releases/download/"
            f"{args.archive_release}/{archive.name}"
        ),
    )
    archive.unlink()
    return result


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
        if args.archive_release or args.archive_local_only:
            if run_id == "node-d0-r1" and args.archive_base_image:
                if not args.archive_base_image.exists():
                    args.archive_base_image.parent.mkdir(parents=True, exist_ok=True)
                    os.link(image, args.archive_base_image)
                args.archive_base_sha256 = sha256(args.archive_base_image)
                if args.archive_base_sha256 != result["image_sha256"]:
                    raise ValueError("archive base does not match first captured RAM image")
            (folder / "score-pending.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
            result["ram_archive"] = archive_and_upload(args, image, run_id, result["image_sha256"])
        (folder / "score.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        image.unlink()  # Only one multi-GiB RAM image exists at a time.
        (folder / "score-pending.json").unlink(missing_ok=True)
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
                **({"ram_archive": run["ram_archive"]} if "ram_archive" in run else {}),
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
    parser.add_argument("--archive-release")
    parser.add_argument("--archive-release-id", type=int)
    parser.add_argument("--archive-repo", default="Kowntaewook/MCPTrace")
    parser.add_argument("--archive-dir", type=Path)
    parser.add_argument("--archive-base-image", type=Path)
    parser.add_argument("--archive-local-only", action="store_true")
    args = parser.parse_args()
    if args.archive_local_only and args.archive_release:
        parser.error("--archive-local-only and --archive-release are mutually exclusive")
    if bool(args.archive_release or args.archive_local_only) != bool(args.archive_dir):
        parser.error("an archive mode and --archive-dir must be used together")
    if bool(args.archive_release) != bool(args.archive_release_id):
        parser.error("--archive-release-id is required with --archive-release")
    if args.archive_base_image and not args.archive_dir:
        parser.error("--archive-base-image requires an archive mode")
    if args.archive_base_image and args.archive_base_image.is_dir():
        args.archive_base_sha256 = json.loads(
            (args.archive_base_image / "manifest.json").read_text(encoding="utf-8")
        )["image_sha256"]
    elif args.archive_base_image and args.archive_base_image.exists():
        args.archive_base_sha256 = sha256(args.archive_base_image)
    else:
        args.archive_base_sha256 = None
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
                    if (
                        run_id == "node-d0-r1"
                        and args.archive_base_sha256
                        and run["image_sha256"] != args.archive_base_sha256
                    ):
                        raise ValueError("archive base does not match first captured RAM image")
                    print("  reusing verified score", flush=True)
                    (args.output / run_id / "ram.elf").unlink(missing_ok=True)
                elif (args.output / run_id / "score-pending.json").exists():
                    pending = args.output / run_id / "score-pending.json"
                    run = json.loads(pending.read_text(encoding="utf-8"))
                    image = args.output / run_id / "ram.elf"
                    if (
                        not (args.archive_release or args.archive_local_only)
                        or not image.exists()
                        or run.get("run_id") != run_id
                    ):
                        raise ValueError(f"invalid pending archive for {run_id}")
                    run["ram_archive"] = archive_and_upload(
                        args, image, run_id, run["image_sha256"]
                    )
                    completed.write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
                    image.unlink()
                    pending.unlink()
                    print("  resumed verified archive", flush=True)
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
