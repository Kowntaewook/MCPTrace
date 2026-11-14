"""Run both published scanners on the exact constructed protocol buffers."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from mcptrace.core import scan_chunks
from validation.mcprecon_comparison.run import MCPRECON_GIT_BLOB
from validation.protocol_corpus.run import CASES


NON_MCP_SOURCES = {"lsp", "generic-json-rpc", "conflicting-signals"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcprecon", type=Path, required=True)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    source = args.mcprecon.resolve()
    contents = source.read_bytes()
    blob = hashlib.sha1(f"blob {len(contents)}\0".encode() + contents).hexdigest()
    if blob != MCPRECON_GIT_BLOB:
        raise ValueError("MCPRecon source differs from pinned public Git blob")
    results = []
    with tempfile.TemporaryDirectory(dir=args.private) as name:
        temp = Path(name)
        for case in CASES:
            payload = case.buffer()
            input_file = temp / "buffer.bin"
            input_file.write_bytes(payload)
            trace = list(scan_chunks([(0x1000, payload)]))
            command = [sys.executable, str(source), str(input_file), "--quiet", "--temp-dir", str(temp / "mcprecon-temp")]
            output = subprocess.check_output(command, text=True)
            recon = [json.loads(row) for row in output.splitlines()]
            results.append({
                "case": case.name,
                "source_protocol": case.source_protocol,
                "encoding": case.encoding,
                "frame": case.frame,
                "buffer_sha256": hashlib.sha256(payload).hexdigest(),
                "non_mcp_protocol_origin": case.source_protocol in NON_MCP_SOURCES,
                "mcptrace_records": len(trace),
                "mcptrace_mcp_candidate": any(item.mcp for item in trace),
                "mcprecon_records": len(recon),
                "mcprecon_mcp_flagged": any(row["mcp"] for row in recon),
            })
    non_mcp = [row for row in results if row["non_mcp_protocol_origin"]]
    report = {
        "schema_version": 1,
        "scope": "Constructed single-buffer protocol cases; no captured memory or field error rate",
        "mcprecon_source_git_blob": blob,
        "cases": results,
        "non_mcp_origin_cases": len(non_mcp),
        "non_mcp_origin_labeled_mcp_by_mcptrace": sum(row["mcptrace_mcp_candidate"] for row in non_mcp),
        "non_mcp_origin_labeled_mcp_by_mcprecon": sum(row["mcprecon_mcp_flagged"] for row in non_mcp),
        "interpretation": (
            "The origin labels are controlled fixture facts. A protocol-shaped memory candidate is not "
            "evidence of actual transport, transmission, or execution."
        ),
    }
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
