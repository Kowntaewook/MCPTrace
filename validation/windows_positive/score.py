"""Compare controlled SDK traffic to carved evidence without equating copies to messages."""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from contextlib import contextmanager


def canonical(message):
    return json.dumps(
        message, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def typed_id(message):
    value = message.get("id")
    return type(value).__name__, value


def score_case(metadata, truth, artifacts, decoys=()):
    expected = {canonical(row["message"]): row["message"] for row in truth}
    if len(expected) != len(truth):
        raise ValueError(
            "This fixture requires distinct logical messages; repeated events need alignment"
        )
    pids = {metadata["client_pid"], metadata["server_pid"]}
    records = [r for r in artifacts if r["pid"] in pids]
    keys = {canonical(r["message"]) for r in records if r["state"] == "complete"}
    matched = keys & expected.keys()
    decoy_keys = {canonical(d) for d in decoys}
    responses = {
        typed_id(m): canonical(m)
        for m in expected.values()
        if "method" not in m and ("result" in m or "error" in m)
    }
    requests = {typed_id(m): canonical(m) for m in expected.values() if "method" in m and "id" in m}
    pairs = [
        (canonical(m), responses[typed_id(m)])
        for m in expected.values()
        if m.get("method") == "tools/call" and typed_id(m) in responses
    ]
    per_pid = {}
    for pid in sorted(pids):
        found = {canonical(r["message"]) for r in records if r["pid"] == pid}
        per_pid[str(pid)] = {
            "artifact_records": sum(r["pid"] == pid for r in records),
            "distinct_expected_messages_found": len(found & expected.keys()),
            "complete_tool_pairs": sum(a in found and b in found for a, b in pairs),
        }
    by_address = {(r["pid"], r["virtual_address"]): r for r in records}
    evaluated = incorrect = unverifiable = 0
    for record in records:
        message = record["message"]
        key = canonical(message)
        if key not in expected:
            continue
        counterpart = (responses if "method" in message else requests).get(typed_id(message))
        for address in record["candidate_virtual_addresses"]:
            other = by_address.get((record["pid"], address))
            if other is None or canonical(other["message"]) not in expected:
                unverifiable += 1
            else:
                evaluated += 1
                incorrect += canonical(other["message"]) != counterpart
    matched_records = sum(canonical(r["message"]) in expected for r in records)
    return {
        "mode": metadata["mode"],
        "expected_logical_messages": len(expected),
        "distinct_expected_messages_found": len(matched),
        "logical_message_coverage": len(matched) / len(expected) if expected else None,
        "expected_tool_pairs": len(pairs),
        "complete_tool_pairs_any_endpoint": sum(a in matched and b in matched for a, b in pairs),
        "positive_pair_in_one_pid": any(p["complete_tool_pairs"] for p in per_pid.values()),
        "artifact_records": len(records),
        "records_matching_logged_traffic": matched_records,
        "distinct_unsent_controls_found": len(keys & decoy_keys),
        "records_matching_unsent_controls": sum(
            canonical(r["message"]) in decoy_keys for r in records
        ),
        "unmatched_artifact_records": sum(
            canonical(r["message"]) not in expected.keys() | decoy_keys for r in records
        ),
        "record_match_fraction": matched_records / len(records) if records else None,
        "evaluated_candidate_links": evaluated,
        "incorrect_candidate_links": incorrect,
        "unverifiable_candidate_links": unverifiable,
        "relations": dict(Counter(r["relation"] for r in records)),
        "per_pid": per_pid,
        "limits": (
            "Fixture-specific logical-message coverage; copies remain separate evidence records. "
            "SDK logging changes memory. Retained mode deliberately keeps serialized frames. "
            "Unmatched candidates are not automatically false positives. Candidate links are "
            "evaluated only where both messages match this controlled single-session truth."
        ),
    }


@contextmanager
def managed_context():
    """Close native memory layers even if verification raises an exception."""
    from volatility3.framework import contexts

    context = contexts.Context()
    try:
        yield context
    finally:
        # Layers are added after their dependencies, so remove dependents first.
        for name in reversed(list(context.layers)):
            context.layers.del_layer(name)


def verify_exports(image, symbols, cache, config_file, exports):
    """Re-read every exported artifact with native Windows process layers."""
    import volatility3.plugins
    import volatility3.symbols
    from volatility3 import framework
    from volatility3.framework import automagic, constants, interfaces, plugins
    from volatility3.plugins.windows import pslist

    constants.CACHE_PATH = str(cache.resolve())
    constants.OFFLINE = True
    volatility3.symbols.__path__ = [str(symbols.resolve()), *constants.SYMBOL_BASEPATHS]
    with managed_context() as context:
        framework.import_files(volatility3.plugins, True)
        config = json.loads(config_file.read_text(encoding="utf-8"))
        config["kernel.layer_name.memory_layer.location"] = image.resolve().as_uri()
        context.config.splice("plugins.PsList", interfaces.configuration.HierarchicalDict(config))
        magics = automagic.choose_automagic(automagic.available(context), pslist.PsList)
        plugin = plugins.construct_plugin(context, magics, pslist.PsList, "plugins", None, None)
        processes = {
            int(p.UniqueProcessId): p
            for p in pslist.PsList.list_processes(
                context, kernel_module_name=plugin.config["kernel"]
            )
        }
        artifacts, summaries = [], {}
        for path in exports:
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            header, *records, summary = rows
            pid = header["pid"]
            if header["target_os"] != "windows" or header["region_kind"] != "vad":
                raise ValueError("Wrong OS/region metadata")
            if summary["displayed_records"] != len(records):
                raise ValueError("JSONL count mismatch")
            proc = processes[pid]
            layer = context.layers[proc.add_process_layer()]
            vads = {
                int(v.get_start()): int(v.get_end()) + 1 for v in proc.get_vad_root().traverse()
            }
            for record in records:
                raw = base64.b64decode(record["raw_base64"], validate=True)
                start, address = record["vad_start"], record["virtual_address"]
                if (
                    record["type"] != "artifact"
                    or record["pid"] != pid
                    or record["target_os"] != "windows"
                    or record["region_kind"] != "vad"
                    or record["region_start"] != start
                    or not raw
                    or len(raw) != record["byte_length"]
                    or hashlib.sha256(raw).hexdigest() != record["raw_sha256"]
                    or start not in vads
                    or not start <= address < address + len(raw) <= vads[start]
                    or layer.read(address, len(raw), pad=False) != raw
                ):
                    raise ValueError(f"PID {pid}: exported bytes/hash/address/VAD do not agree")
            artifacts.extend(records)
            summaries[str(pid)] = summary
        return artifacts, summaries
