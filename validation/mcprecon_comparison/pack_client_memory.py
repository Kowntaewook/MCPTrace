"""Pack one client's readable VMAs from a saved Linux RAM capture.

This creates a private derived byte stream for a process-scoped MCPRecon run.
It inserts NUL separators at gaps and VMA boundaries, so it is not an
unaltered RAM image and does not preserve physical file offsets.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from volatility3.framework import exceptions

from mcptrace.core import ScanStats
from mcptrace.memory import readable_chunks
from validation.linux_x64_positive.score import process_context


SEPARATOR = b"\0" * 65536


def pack(image: Path, config: Path, symbols: Path, cache: Path, pid: int, output: Path) -> dict:
    cache.mkdir(parents=True, exist_ok=True)
    saved = json.loads(config.read_text(encoding="utf-8"))
    locations = [key for key in saved if key.endswith(".memory_layer.base_layer.location")]
    isfs = [key for key in saved if key.endswith(".symbol_table_name.isf_url")]
    symbol_files = list((symbols / "linux").glob("Ubuntu_6.8.0-146-generic_6.8.0-146.146_amd64.json.xz"))
    if len(locations) != 1 or len(isfs) != 1 or len(symbol_files) != 1:
        raise ValueError("expected one RAM location and matching kernel ISF")
    saved[locations[0]] = image.resolve().as_uri()
    saved[isfs[0]] = symbol_files[0].resolve().as_uri()
    overlay = output.with_suffix(".config.json")
    overlay.write_text(json.dumps(saved), encoding="utf-8")

    stats = ScanStats()
    segments = []
    with process_context(symbols, cache, overlay) as (context, processes, _):
        if pid not in processes:
            raise ValueError(f"PID {pid} absent from reconstructed RAM")
        task = processes[pid]
        layer = context.layers[task.add_process_layer()]
        with output.open("wb") as dest:
            for vma in task.mm.get_vma_iter():
                start, end = int(vma.vm_start), int(vma.vm_end)
                if end <= start:
                    stats.invalid_regions += 1
                    continue
                stats.regions_scanned += 1
                previous_end = None
                for address, data in readable_chunks(
                    layer, start, end - start, stats, exceptions.InvalidAddressException
                ):
                    if previous_end != address and dest.tell():
                        dest.write(SEPARATOR)
                    segments.append({"packed_start": dest.tell(), "virtual_address": address, "length": len(data)})
                    dest.write(data)
                    previous_end = address + len(data)
                if dest.tell():
                    dest.write(SEPARATOR)
    details = {
        "pid": pid,
        "packed_bytes": output.stat().st_size,
        "bytes_read": stats.bytes_read,
        "unreadable_bytes": stats.unreadable_bytes,
        "regions_scanned": stats.regions_scanned,
        "segments": segments,
    }
    output.with_suffix(".index.json").write_text(json.dumps(details), encoding="utf-8")
    return details


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "config", "symbols", "cache", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--pid", required=True, type=int)
    args = parser.parse_args()
    result = pack(args.image, args.config, args.symbols, args.cache, args.pid, args.output)
    print(json.dumps({key: value for key, value in result.items() if key != "segments"}))


if __name__ == "__main__":
    main()
