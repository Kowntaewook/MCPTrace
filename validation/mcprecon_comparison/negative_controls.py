"""Compare MCP labels on preserved non-MCP process-memory captures.

Raw captures, derived streams and tool outputs remain in the private bundle.
Only counts and hashes are written to the requested report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from mcptrace.core import scan_chunks
from validation.mcprecon_comparison.run import MCPRECON_GIT_BLOB, canonical, digest, lines
from validation.real_host.scan_mach_capture import chunks


ROOT = Path(__file__).resolve().parents[2]
SEPARATOR = b"\0" * 65536
CASES = (
    ("macos-lsp-negative", "mac-lsp/host.capture", "mac-lsp/lsp-traffic.jsonl", None),
    ("macos-jsonrpc-negative", "mac-jsonrpc/host.capture", "mac-jsonrpc/traffic.jsonl", None),
    ("linux-lsp-negative", "captures/linux-lsp.capture", "lsp-final/lsp-traffic.jsonl", "archive"),
    ("linux-jsonrpc-negative", "captures/linux-jsonrpc.capture", "jsonrpc/traffic.jsonl", "archive"),
)


def pack_capture(source: Path, output: Path) -> dict:
    segments = 0
    source_bytes = 0
    previous_end = None
    with output.open("wb") as dest:
        for address, data in chunks(source):
            if previous_end != address and dest.tell():
                dest.write(SEPARATOR)
            dest.write(data)
            previous_end = address + len(data)
            segments += 1
            source_bytes += len(data)
    return {"segments": segments, "source_bytes": source_bytes, "packed_bytes": output.stat().st_size}


def run_case(case: tuple, private: Path, source: Path, work: Path) -> dict:
    name, capture_name, traffic_name, archive = case
    original = json.loads((ROOT / "validation" / "real_host" / "results" / "2026-11-14" / f"{name}.json").read_text())
    capture = private / capture_name
    traffic = private / traffic_name
    if archive:
        with tarfile.open(private / "linux-real-host-private.tar.gz", "r:gz") as bundle:
            for member_name, target in ((capture_name, capture), (traffic_name, traffic)):
                member = bundle.extractfile(member_name)
                if member is None:
                    raise ValueError(f"missing archive member: {member_name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as dest:
                    while data := member.read(1024 * 1024):
                        dest.write(data)
    try:
        if digest(capture) != original["snapshot_sha256"] or digest(traffic) != original["traffic_sha256"]:
            raise ValueError(f"{name}: capture or traffic hash mismatch")
        observed = list(scan_chunks(chunks(capture)))
        trace_mcp = sum(item.mcp for item in observed)
        if len(observed) != original["artifact_records"] or trace_mcp != original["mcp_candidate_records"]:
            raise ValueError(f"{name}: MCPTrace rescan differs from stored report")
        packed = work / f"{name}.packed.bin"
        counts = pack_capture(capture, packed)
        output = work / f"{name}.mcprecon.jsonl"
        with output.open("w", encoding="utf-8") as result:
            subprocess.run(
                [sys.executable, str(source), str(packed), "--quiet", "--emit-raw",
                 "--temp-dir", str(work / "temp")],
                stdout=result, check=True,
            )
        records = lines(output)
        with packed.open("rb") as stream:
            verified = 0
            for row in records:
                raw = row["raw"].encode("utf-8")
                stream.seek(row["offset"])
                verified += stream.read(len(raw)) == raw
        truth = {canonical(row["message"]) for row in lines(traffic)}
        if len(truth) != original["distinct_logged_messages"]:
            raise ValueError(f"{name}: traffic truth count differs")
        recon_found = {canonical(row["json"]) for row in records}
        result = {
            "case": name,
            "capture_sha256": original["snapshot_sha256"],
            "traffic_sha256": original["traffic_sha256"],
            "logged_nonmcp_messages": len(truth),
            "mcptrace_records": len(observed),
            "mcptrace_mcp_candidate_records": trace_mcp,
            "mcptrace_truth_messages_carved": len({canonical(item.obj) for item in observed if item.obj} & truth),
            "mcprecon_records": len(records),
            "mcprecon_mcp_flagged_records": sum(bool(row["mcp"]) for row in records),
            "mcprecon_truth_messages_carved": len(recon_found & truth),
            "mcprecon_file_offset_bytes_verified": verified,
            **counts,
        }
        packed.unlink()
        return result
    finally:
        if archive:
            capture.unlink(missing_ok=True)
            traffic.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--mcprecon", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    private = args.private.resolve()
    source = args.mcprecon.resolve()
    contents = source.read_bytes()
    blob = hashlib.sha1(f"blob {len(contents)}\0".encode() + contents).hexdigest()
    if blob != MCPRECON_GIT_BLOB:
        raise ValueError("MCPRecon source differs from pinned public Git blob")
    with tempfile.TemporaryDirectory(dir=private) as temp_dir:
        work = Path(temp_dir)
        results = [run_case(case, private, source, work) for case in CASES]
        report = {
            "schema_version": 1,
            "scope": "Four preserved non-MCP host process-memory captures, macOS and Linux; derived byte stream for MCPRecon",
            "mcprecon_source_git_blob": blob,
            "cases": results,
            "totals": {
                key: sum(row[key] for row in results)
                for key in ("logged_nonmcp_messages", "mcptrace_records", "mcptrace_mcp_candidate_records",
                            "mcptrace_truth_messages_carved", "mcprecon_records", "mcprecon_mcp_flagged_records",
                            "mcprecon_truth_messages_carved", "mcprecon_file_offset_bytes_verified")
            },
            "limitations": [
                "These four captured processes are known non-MCP controls, not a random sample of deployed software.",
                "The packed stream removes capture headers and adds NUL separators at noncontiguous regions; MCPRecon's native workflow is whole-image scanning.",
                "Zero MCP labels in these controls would not establish a zero population false-positive rate.",
                "A separate constructed generic JSON-RPC tools-list response is an MCPTrace MCP candidate despite its non-MCP source; candidate status alone does not establish protocol origin.",
            ],
        }
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
