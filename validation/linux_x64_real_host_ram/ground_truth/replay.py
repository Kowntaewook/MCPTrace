"""Recompute one live-host result from its original Linux RAM archive.

Run in a private scratch directory with enough space for one ELF image. The
temporary image, Volatility config, and raw exports are removed on completion.
Only the numeric comparison report is retained when --output is supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from validation.linux_x64_real_host_ram.ground_truth.prepare_public import (
    HERE, ROOT, audit_journal, digest,
)
from validation.linux_x64_real_host_ram.score import score


def restore(archive: Path, image: Path, expected_hash: str, expected_size: int) -> None:
    actual = hashlib.sha256()
    size = 0
    with subprocess.Popen(["zstd", "-d", "-c", str(archive)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        assert proc.stdout is not None
        with image.open("wb") as out:
            for chunk in iter(lambda: proc.stdout.read(4 * 1024 * 1024), b""):
                out.write(chunk)
                actual.update(chunk)
                size += len(chunk)
        if proc.wait() != 0:
            raise ValueError("RAM archive decompression failed")
    if actual.hexdigest() != expected_hash or size != expected_size:
        raise ValueError("RAM archive did not reconstruct the published image")


def hash_file(path: Path) -> str:
    actual = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            actual.update(chunk)
    return actual.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True,
                        choices=["inspector-http", "inspector-stdio", "lsp-control",
                                 "jsonrpc-control", "codex-first", "codex-later"])
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--traffic", type=Path,
                        help="Required for the two Codex cases; original private journal")
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--vol", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = json.loads((HERE / "manifest.json").read_text())
    source_check = subprocess.run(
        ["git", "diff", "--quiet", manifest["scanner_source_commit"], "--", "mcptrace", "plugins"],
        cwd=ROOT, check=False,
    )
    if source_check.returncode != 0:
        raise ValueError("scanner source differs from the pinned capture commit")
    item = next(row for row in manifest["captures"] if row["case"] == args.case)
    reference = json.loads((ROOT / item["report_path"]).read_text())
    traffic = args.traffic if args.traffic else HERE / item["traffic_path"] if item["traffic_path"] else None
    if traffic is None:
        parser.error("the original private Codex journal is required with --traffic")
    journal = traffic.read_bytes()
    if digest(journal) != item["traffic_sha256"]:
        raise ValueError("traffic journal differs from published digest")
    audit_journal(journal, args.case, reference, item["traffic_path"] is not None)
    if (args.archive.stat().st_size != item["archive_bytes"]
            or hash_file(args.archive) != item["archive_sha256"]):
        raise ValueError("RAM archive differs from published digest")
    args.scratch.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(args.scratch).free
    required = item["image_bytes"] + 256 * 1024 * 1024
    if free < required:
        raise OSError(f"scratch needs at least {required:,} free bytes; has {free:,}")
    with tempfile.TemporaryDirectory(prefix="mcptrace-live-replay-", dir=args.scratch) as temp:
        work = Path(temp)
        image = work / "ram.elf"
        restore(args.archive, image, item["image_sha256"], item["image_bytes"])
        exports = work / "exports"
        exports.mkdir()
        config = work / "config.json"
        ready = work / "client-ready.json"
        ready.write_text(json.dumps({"pid": item["client_pid"]}))
        command = [str(args.vol.resolve()), "-q", "--cache-path", str(args.cache.resolve()),
                   "-s", str(args.symbols.resolve()), "-p", str(ROOT / "plugins"),
                   "-f", str(image), "-o", str(exports), "--save-config", str(config),
                   "linux.mcptrace.MCPTrace", "--pid", str(item["client_pid"]),
                   "--include-rpc", "--dump"]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        with (work / "vol-stdout.txt").open("w") as stdout, \
                (work / "vol-stderr.txt").open("w") as stderr:
            subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=1800,
                           stdout=stdout, stderr=stderr)
        export = exports / f"mcptrace.pid-{item['client_pid']}.jsonl"
        measured = score(case="codex-stdio" if args.case.startswith("codex-") else args.case,
                         image=image, symbols=args.symbols, cache=args.cache, config=config,
                         ready=ready, traffic=traffic, export=export)
        differences = {key: {"expected": reference[key], "observed": value}
                       for key, value in measured.items()
                       if key in reference and reference[key] != value}
        if differences:
            raise ValueError(f"replay differs in: {', '.join(sorted(differences))}")
        result = {"case": args.case, "matches_published_score": True,
                  "image_sha256": item["image_sha256"],
                  "traffic_sha256": item["traffic_sha256"],
                  "artifact_records": measured["artifact_records"],
                  "wire_present_any_encoding": measured["wire_present_any_encoding"],
                  "carved_logged_messages": measured["carved_logged_messages"],
                  "mcp_labeled_logged_messages": measured["mcp_labeled_logged_messages"]}
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))


if __name__ == "__main__":
    main()
