"""Serially replay all public RAM captures with bounded temporary disk use.

The compressed base is streamed into each patch reconstruction. Only one raw
image and one patch-sized base chunk are held on disk at a time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import tarfile
import time
from pathlib import Path

from validation.linux_x64_positive.score import sha256
from validation.mcprecon_comparison.replay_public import ROOT, TRUTH, REFERENCE, aggregate, score_run


def reconstruct_patch(base_asset: Path, patch: Path, row: dict,
                      base_row: dict, target: Path, scratch: Path) -> None:
    image_hash = hashlib.sha256()
    base_hash = hashlib.sha256()
    total = 0
    with tarfile.open(patch, "r") as bundle:
        member = bundle.extractfile("manifest.json")
        if member is None:
            raise ValueError("patch has no manifest")
        info = json.load(member)
        if (info["format"] != "zstd-chunk-patch-tar"
                or info["image_sha256"] != row["image_sha256"]
                or info["base_image_sha256"] != base_row["image_sha256"]
                or info["image_bytes"] != row["image_bytes"]
                or info["part_count"] != (row["image_bytes"] + info["chunk_bytes"] - 1)
                    // info["chunk_bytes"]):
            raise ValueError("patch manifest disagrees with public capture manifest")
        with tempfile.TemporaryDirectory(prefix="patch-chunks-", dir=scratch) as temp_name:
            temp = Path(temp_name)
            base_chunk = temp / "base.chunk"
            patch_chunk = temp / "patch.zst"
            with subprocess.Popen(["zstd", "-q", "-d", "-c", str(base_asset)],
                                  stdout=subprocess.PIPE) as base_process, target.open("xb") as output:
                assert base_process.stdout is not None
                for index in range(info["part_count"]):
                    length = min(info["chunk_bytes"], row["image_bytes"] - total)
                    with base_chunk.open("wb") as base_output:
                        remaining = length
                        while remaining:
                            block = base_process.stdout.read(min(4 * 1024**2, remaining))
                            if not block:
                                raise ValueError("compressed base ended early")
                            base_output.write(block)
                            base_hash.update(block)
                            remaining -= len(block)
                    part = bundle.extractfile(f"part-{index:02d}.zst")
                    if part is None:
                        raise ValueError("patch part missing")
                    with patch_chunk.open("wb") as patch_output:
                        shutil.copyfileobj(part, patch_output)
                    command = ["zstd", "-q", "-d", "-c",
                               f"--patch-from={base_chunk}", str(patch_chunk)]
                    recovered = 0
                    with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
                        assert process.stdout is not None
                        for block in iter(lambda: process.stdout.read(4 * 1024**2), b""):
                            output.write(block)
                            image_hash.update(block)
                            recovered += len(block)
                        if process.wait(timeout=600) != 0:
                            raise ValueError("patch decompression failed")
                    if recovered != length:
                        raise ValueError("patch part has wrong reconstructed length")
                    total += recovered
                if base_process.stdout.read(1) or base_process.wait(timeout=600) != 0:
                    raise ValueError("compressed base contains extra data or failed")
    if (total != row["image_bytes"] or base_hash.hexdigest() != base_row["image_sha256"]
            or image_hash.hexdigest() != row["image_sha256"]):
        raise ValueError("reconstructed RAM hash differs from public manifest")


def valid_saved_report(path: Path, row: dict, reference: dict) -> bool:
    if not path.exists():
        return False
    saved = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "run_id": row["run_id"],
        "image_sha256": row["image_sha256"],
        "traffic_log_sha256": row["traffic_log_sha256"],
        "traffic_messages": reference["traffic_messages"],
        "present_utf8": reference["present_utf8"],
        "present_utf16le": reference["present_utf16le"],
        "wire_present": reference["present_utf8"] + reference["present_utf16le"]
                        - reference["present_both"],
        "mcptrace_records_verified": reference["mcptrace_artifact_records"],
        "mcptrace_carved": reference["mcptrace_truth_messages_any_label"],
        "mcptrace_mcp_labeled": reference["mcptrace_truth_messages_mcp_labeled"],
        "mcprecon_records_verified": reference["mcprecon_client_records"],
        "mcprecon_carved": reference["mcprecon_client_truth_messages_any_label"],
        "mcprecon_mcp_labeled": reference["mcprecon_client_truth_messages_mcp_labeled"],
        "mcptrace_unmatched_records": 0,
        "mcprecon_unmatched_records": 0,
    }
    return (all(saved.get(key) == value for key, value in expected.items())
            and saved.get("scan_limits_hit") == [])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("assets", "symbols", "cache", "vol", "mcprecon", "reports", "scratch"):
        parser.add_argument(f"--{key}", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((TRUTH / "manifest.json").read_text(encoding="utf-8"))
    published = json.loads((ROOT / "validation/linux_x64_http_ram/results/2026-11-14-qemu-http-sdk-rerun.json")
                           .read_text(encoding="utf-8"))
    source = {row["run_id"]: row for row in published["captures"]}
    references = {row["run_id"]: row for row in json.loads(REFERENCE.read_text(encoding="utf-8"))["captures"]}
    if len(manifest["runs"]) != 27 or len(source) != 27:
        raise ValueError("expected 27 published captures")
    for row in manifest["runs"]:
        archive = source[row["run_id"]]["ram_archive"]
        path = args.assets / archive["name"]
        if path.stat().st_size != archive["bytes"] or sha256(path) != archive["sha256"]:
            raise ValueError(f"asset differs from published release: {archive['name']}")
    args.reports.mkdir(parents=True, exist_ok=True)
    args.scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="all-public-", dir=args.scratch) as temp_name:
        scratch = Path(temp_name)
        base_row = next(row for row in manifest["runs"] if row["run_id"] == "node-d0-r1")
        base_asset = args.assets / source["node-d0-r1"]["ram_archive"]["name"]
        rows = [base_row] + [row for row in manifest["runs"] if row != base_row]
        for index, row in enumerate(rows, 1):
            run_id = row["run_id"]
            report = args.reports / f"{run_id}.json"
            if valid_saved_report(report, row, references[run_id]):
                print(f"[{index}/27] resumed verified {run_id}", flush=True)
                continue
            image = scratch / "current.elf"
            try:
                if row == base_row:
                    with image.open("xb") as output:
                        subprocess.run(["zstd", "-q", "-d", "-c", str(base_asset)],
                                       stdout=output, check=True, timeout=1200)
                    if image.stat().st_size != row["image_bytes"] or sha256(image) != row["image_sha256"]:
                        raise ValueError("base image differs from public manifest")
                else:
                    archive = args.assets / source[run_id]["ram_archive"]["name"]
                    reconstruct_patch(base_asset, archive, row, base_row, image, scratch)
                print(f"[{index}/27] replaying {run_id}", flush=True)
                for attempt in range(3):
                    try:
                        measured = score_run(argparse.Namespace(
                            run_id=run_id, image=image, symbols=args.symbols,
                            cache=args.cache, vol=args.vol, mcprecon=args.mcprecon,
                            work_dir=scratch, report=report))
                        break
                    except TimeoutError:
                        if attempt == 2:
                            raise
                        print(f"[{index}/27] transient filesystem timeout; retrying {run_id}",
                              flush=True)
                        time.sleep(2)
                report.write_text(json.dumps(measured, indent=2) + "\n", encoding="utf-8")
                print(f"[{index}/27] verified {run_id}: "
                      f"{measured['wire_present']} present, "
                      f"{measured['mcptrace_carved']} Trace, "
                      f"{measured['mcprecon_carved']} Recon", flush=True)
            finally:
                image.unlink(missing_ok=True)
        totals = args.reports / "replayed-totals.json"
        totals.write_text(json.dumps(aggregate(args.reports), indent=2) + "\n", encoding="utf-8")
        print(f"verified all 27 captures: {totals}", flush=True)


if __name__ == "__main__":
    main()
