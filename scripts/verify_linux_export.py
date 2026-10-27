"""Re-read Linux JSONL artifacts through native Volatility process layers.

This checks exported bytes, hashes, and VMA bounds. It does not establish that
the JSON was transmitted or measure message recovery against ground truth.
No MCPTrace scanner or adapter is used to perform the verification.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

import volatility3.plugins
import volatility3.symbols
from volatility3 import framework
from volatility3.framework import automagic, constants, contexts, plugins
from volatility3.framework.automagic import stacker
from volatility3.plugins.linux import pslist


def verify_file(path, context, tasks):
    with path.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if len(rows) < 2 or rows[0].get("type") != "metadata":
        raise ValueError(f"{path.name}: missing export metadata")
    header, *records, summary = rows
    pid = header["pid"]
    if header.get("target_os") != "linux" or header.get("region_kind") != "vma":
        raise ValueError(f"{path.name}: not a Linux VMA export")
    if header.get("address_space") != "process-virtual":
        raise ValueError(f"{path.name}: not a process virtual address export")
    if summary.get("type") != "scan-summary" or summary.get("displayed_records") != len(records):
        raise ValueError(f"{path.name}: summary/count mismatch")
    if pid not in tasks:
        raise ValueError(f"{path.name}: PID {pid} is not in native linux.pslist")
    task = tasks[pid]
    total_bytes = 0
    if records:
        if not task.mm:
            raise ValueError(f"{path.name}: records attributed to a kernel thread")
        layer_name = task.add_process_layer()
        if not layer_name:
            raise ValueError(f"{path.name}: process layer unavailable")
        layer = context.layers[layer_name]
        regions = {int(v.vm_start): int(v.vm_end) for v in task.mm.get_vma_iter()}
        for index, record in enumerate(records, 2):
            label = f"{path.name}:{index}"
            if (
                record.get("type") != "artifact"
                or record.get("pid") != pid
                or record.get("target_os") != "linux"
                or record.get("region_kind") != "vma"
            ):
                raise ValueError(f"{label}: artifact metadata mismatch")
            raw = base64.b64decode(record["raw_base64"], validate=True)
            if not raw or len(raw) != record["byte_length"]:
                raise ValueError(f"{label}: byte length mismatch")
            if hashlib.sha256(raw).hexdigest() != record["raw_sha256"]:
                raise ValueError(f"{label}: SHA-256 mismatch")
            start, address = record["region_start"], record["virtual_address"]
            if (
                record.get("vma_start") != start
                or start not in regions
                or not start <= address < address + len(raw) <= regions[start]
            ):
                raise ValueError(f"{label}: VMA bounds mismatch")
            if layer.read(address, len(raw), pad=False) != raw:
                raise ValueError(f"{label}: process memory bytes differ")
            total_bytes += len(raw)
    return {"pid": pid, "artifacts_verified": len(records), "bytes_verified": total_bytes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--require-artifacts", action="store_true")
    parser.add_argument("exports", type=Path, nargs="+")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    constants.CACHE_PATH = str(args.cache.resolve())
    constants.OFFLINE = True
    volatility3.symbols.__path__ = [str(args.symbols.resolve()), *constants.SYMBOL_BASEPATHS]
    context = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    # Import automagic modules before selecting stackers: the Linux stackers
    # live there, not in framework.layers.
    magics = automagic.choose_automagic(automagic.available(context), pslist.PsList)
    context.config["automagic.LayerStacker.single_location"] = args.image.resolve().as_uri()
    context.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(pslist.PsList)
    plugin = plugins.construct_plugin(context, magics, pslist.PsList, "plugins", None, None)
    tasks = {
        int(task.tgid): task
        for task in pslist.PsList.list_tasks(
            context, plugin.config["kernel"], include_threads=False
        )
    }
    results = [verify_file(path, context, tasks) for path in args.exports]
    count = sum(result["artifacts_verified"] for result in results)
    if args.require_artifacts and not count:
        raise ValueError("No artifacts to verify")
    print(json.dumps({"artifacts_verified": count, "exports": results}, indent=2))


if __name__ == "__main__":
    main()
