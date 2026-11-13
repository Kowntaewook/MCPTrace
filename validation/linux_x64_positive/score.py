"""Verify Linux RAM exports against one controlled stdio exchange and the image."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import platform
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@contextmanager
def process_context(symbols: Path, cache: Path, config: Path):
    import volatility3.plugins
    import volatility3.symbols
    from volatility3 import framework
    from volatility3.framework import automagic, constants, contexts, interfaces, plugins
    from volatility3.plugins.linux import pslist

    constants.CACHE_PATH = str(cache.resolve())
    constants.OFFLINE = True
    volatility3.symbols.__path__ = [str(symbols.resolve()), *constants.SYMBOL_BASEPATHS]
    context = contexts.Context()
    try:
        framework.import_files(volatility3.plugins, True)
        configuration = json.loads(config.read_text())
        context.config.splice(
            "plugins.PsList", interfaces.configuration.HierarchicalDict(configuration)
        )
        magics = automagic.choose_automagic(automagic.available(context), pslist.PsList)
        plugin = plugins.construct_plugin(context, magics, pslist.PsList, "plugins", None, None)
        processes = {
            int(task.tgid): task
            for task in pslist.PsList.list_tasks(
                context, vmlinux_module_name=plugin.config["kernel"]
            )
        }
        yield context, processes, configuration
    finally:
        for name in reversed(list(context.layers)):
            context.layers.del_layer(name)


def verify_exports(
    paths: list[Path], symbols: Path, cache: Path, config: Path
) -> tuple[list, list]:
    artifacts, scans = [], []
    with process_context(symbols, cache, config) as (context, processes, _):
        for path in paths:
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            header, *records, summary = rows
            pid = header["pid"]
            if header["target_os"] != "linux" or header["region_kind"] != "vma":
                raise ValueError(f"{path}: wrong OS or region kind")
            if summary["type"] != "scan-summary" or len(records) != summary["displayed_records"]:
                raise ValueError(f"{path}: incomplete export")
            if pid not in processes:
                raise ValueError(f"{path}: PID absent from pslist")
            process = processes[pid]
            layer = context.layers[process.add_process_layer()]
            vmas = {int(v.vm_start): int(v.vm_end) for v in process.mm.get_vma_iter()}
            for row in records:
                raw = base64.b64decode(row["raw_base64"], validate=True)
                start, address = row["vma_start"], row["virtual_address"]
                if (
                    row["type"] != "artifact"
                    or row["pid"] != pid
                    or row["target_os"] != "linux"
                    or row["region_kind"] != "vma"
                    or row["region_start"] != start
                    or not raw
                    or len(raw) != row["byte_length"]
                    or hashlib.sha256(raw).hexdigest() != row["raw_sha256"]
                    or start not in vmas
                    or not start <= address < address + len(raw) <= vmas[start]
                    or layer.read(address, len(raw), pad=False) != raw
                ):
                    raise ValueError(f"{path}: PID {pid} byte/address/VMA verification failed")
            artifacts.extend(records)
            scans.append({"pid": pid, "summary": summary, "export_sha256": sha256(path)})
    return artifacts, scans


def score(
    image: Path,
    symbols: Path,
    cache: Path,
    config: Path,
    truth: Path,
    exports: list[Path],
    repeats: list[Path],
) -> dict:
    if len(exports) != len(repeats):
        raise ValueError("one repeat export is required for each original export")
    configuration = json.loads(config.read_text())
    locations = [
        value
        for key, value in configuration.items()
        if key.endswith(".memory_layer.base_layer.location")
    ]
    configured_image = Path(unquote(urlparse(locations[0]).path)).resolve() if locations else None
    if len(locations) != 1 or configured_image != image.resolve():
        raise ValueError("saved Volatility configuration refers to another image")
    artifacts, scans = verify_exports(exports, symbols, cache, config)
    repeat_hashes = [sha256(path) for path in repeats]
    identical = [row["export_sha256"] for row in scans] == repeat_hashes
    if not identical:
        raise ValueError("same-image repeated exports differ")
    truth_data = json.loads(truth.read_text())
    expected_pids = {truth_data["client_pid"], truth_data["server_pid"]}
    if {row["pid"] for row in scans} != expected_pids:
        raise ValueError("truth and exports refer to different process IDs")
    controls = truth_data["messages"]
    recovered = {canonical(row["message"]) for row in artifacts}
    expected = {canonical(row["message"]) for row in controls}
    exact_hashes = {row["raw_sha256"] for row in artifacts}
    directions = {}
    for direction in ("sent", "received", "unsent"):
        rows = [row for row in controls if row["direction"] == direction]
        directions[direction] = {
            "expected": len(rows),
            "found_by_message": sum(canonical(row["message"]) in recovered for row in rows),
            "found_as_exact_wire_bytes": sum(row["sha256"] in exact_hashes for row in rows),
        }
    unmatched = sum(canonical(row["message"]) not in expected for row in artifacts)
    all_expected = all(
        row["expected"] == row["found_by_message"] == row["found_as_exact_wire_bytes"]
        for row in directions.values()
    )
    limited = any(
        row["summary"]["candidate_limit_hits"] or row["summary"]["limits_hit"] for row in scans
    )
    return {
        "schema_version": 1,
        "status": (
            "failed_validation"
            if not all_expected or unmatched
            else "completed_with_limits"
            if limited
            else "passed"
        ),
        "scope": "one purpose-built retained stdio exchange in QEMU Linux x86-64 physical RAM",
        "analysis_host": platform.platform(),
        "python": platform.python_version(),
        "volatility3": importlib.metadata.version("volatility3"),
        "scan_options": {
            "max_object_bytes": configuration["max-object-bytes"],
            "max_records": configuration["max-records"],
            "max_bytes": configuration["max-bytes"],
        },
        "image_sha256": sha256(image),
        "image_bytes": image.stat().st_size,
        "symbol_sha256": sha256(next(symbols.glob("linux/*.json.xz"))),
        "truth_sha256": sha256(truth),
        "kernel_banner": configuration["kernel.layer_name.kernel_banner"].strip("\0\n"),
        "artifact_records": len(artifacts),
        "artifacts_reread_at_virtual_addresses": len(artifacts),
        "unique_raw_hashes": len(exact_hashes),
        "unmatched_artifact_records": unmatched,
        "directions": directions,
        "repeated_exports_identical": identical,
        "scans": scans,
        "limitations": (
            "Retained Python bytes make this an easy positive case, "
            "not a population recovery rate. "
            "The peer is purpose-built, not an official MCP SDK. A recovered unsent control "
            "demonstrates that memory presence does not prove transmission. "
            "Scan limits and unreadable bytes remain visible."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "symbols", "cache", "config", "truth", "report"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--export", action="append", type=Path, required=True)
    parser.add_argument("--repeat", action="append", type=Path, required=True)
    args = parser.parse_args()
    result = score(
        args.image, args.symbols, args.cache, args.config, args.truth, args.export, args.repeat
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] == "failed_validation":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
