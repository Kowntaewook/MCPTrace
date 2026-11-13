"""Compare released and current carving on the same small, controlled buffers.

These are constructed protocol controls, not captured traffic or RAM images.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Case:
    name: str
    message: dict | None
    expected_mcp: bool | None
    expected_hint: str | None
    encoding: str = "utf-8"
    frame: str = "none"
    provenance: str = "constructed"
    source_protocol: str = "mcp"

    def buffer(self) -> bytes:
        if self.message is None:
            return b"noise only: {\"method\":\"tools/call\"}"
        raw = json.dumps(self.message, ensure_ascii=False, separators=(",", ":")).encode(
            self.encoding
        )
        if self.frame == "content-length":
            return f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw
        if self.frame == "sse":
            return b"data: " + raw + b"\n\n"
        return raw


LEGACY = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "controlled-client", "version": "1"},
    },
}
LSP = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "initialize",
    "params": {
        "clientInfo": {"name": "controlled-editor"},
        "capabilities": {},
        "rootUri": "file:///case",
        "workspaceFolders": [{"uri": "file:///case", "name": "case"}],
    },
}
MODERN = {
    "jsonrpc": "2.0",
    "id": "modern",
    "method": "server/discover",
    "params": {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    },
}
TOOL = {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "echo_marker", "arguments": {"text": "통제 표본 🐈"}},
}

CASES = (
    Case("legacy-initialize", LEGACY, True, "mcp-candidate"),
    Case("modern-discover", MODERN, True, "mcp-candidate"),
    Case("utf16-tool-call", TOOL, True, "mcp-candidate", encoding="utf-16-le"),
    Case("sse-tool-call", TOOL, True, "mcp-candidate", frame="sse"),
    Case("framed-legacy", LEGACY, True, "mcp-candidate", frame="content-length"),
    Case(
        "lsp-workspace", LSP, False, "lsp-candidate", frame="content-length",
        source_protocol="lsp",
    ),
    Case(
        "utf16-lsp-workspace", LSP, False, "lsp-candidate", encoding="utf-16-le",
        source_protocol="lsp",
    ),
    Case(
        "shared-initialize-fields",
        {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {
            "clientInfo": {"name": "editor"}, "capabilities": {}
        }},
        False,
        "generic-json-rpc",
        source_protocol="generic-json-rpc",
    ),
    Case(
        "framed-shared-fields",
        {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {
            "clientInfo": {"name": "editor"}, "capabilities": {}
        }},
        False,
        "lsp-candidate",
        frame="content-length",
        source_protocol="lsp",
    ),
    Case(
        "conflicting-initialize",
        {**LEGACY, "params": {**LEGACY["params"], "rootUri": "file:///case"}},
        False,
        "ambiguous",
        source_protocol="conflicting-signals",
    ),
    Case(
        "generic-rpc",
        {"jsonrpc": "2.0", "id": 5, "method": "other/action", "params": {}},
        False,
        "generic-json-rpc",
        source_protocol="generic-json-rpc",
    ),
    Case(
        "generic-response",
        {"jsonrpc": "2.0", "id": 6, "result": {"ok": True}},
        False,
        "generic-json-rpc",
        source_protocol="generic-json-rpc",
    ),
    Case(
        "unrelated-tools-list-response",
        {"jsonrpc": "2.0", "id": 7, "result": {"tools": ["hammer"]}},
        True,
        "mcp-candidate",
        source_protocol="generic-json-rpc",
    ),
    Case(
        "unsent-mcp-shaped-control",
        TOOL,
        True,
        "mcp-candidate",
        provenance="deliberately-unsent",
        source_protocol="mcp-shaped-control",
    ),
    Case("non-rpc-noise", None, None, None, source_protocol="not-json-rpc"),
    Case(
        "invalid-id",
        {"jsonrpc": "2.0", "id": True, "method": "tools/call"},
        None,
        None,
        source_protocol="invalid-json-rpc",
    ),
)


def load_core(ref: str) -> types.ModuleType:
    source = subprocess.check_output(
        ["git", "show", f"{ref}:mcptrace/core.py"], cwd=ROOT
    ).decode("utf-8")
    name = f"mcptrace_corpus_{ref.replace('.', '_').replace('-', '_')}"
    module = types.ModuleType(name)
    module.__file__ = f"{ref}:mcptrace/core.py"
    sys.modules[name] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def score(ref: str) -> dict:
    core = load_core(ref)
    rows = []
    for case in CASES:
        data = case.buffer()
        records = list(core.scan_chunks([(0x1000, data)]))
        if len(records) > 1:
            raise RuntimeError(f"{ref}: multiple records in {case.name}")
        record = records[0] if records else None
        actual_mcp = record.mcp if record else None
        hint = getattr(record, "protocol_hint", None) if record else None
        rows.append(
            {
                "case": case.name,
                "provenance": case.provenance,
                "source_protocol": case.source_protocol,
                "encoding": case.encoding,
                "frame": case.frame,
                "buffer_sha256": hashlib.sha256(data).hexdigest(),
                "expected_mcp_candidate": case.expected_mcp,
                "observed_mcp_candidate": actual_mcp,
                "mcp_candidate_matches_expectation": actual_mcp == case.expected_mcp,
                "expected_current_hint": case.expected_hint,
                "observed_hint": hint,
                "hint_matches_expectation": (
                    hint == case.expected_hint if hasattr(core, "classify_with_evidence") else None
                ),
            }
        )
    return {
        "revision": subprocess.check_output(["git", "rev-parse", ref], cwd=ROOT, text=True).strip(),
        "case_count": len(rows),
        "mcp_candidate_matches": sum(row["mcp_candidate_matches_expectation"] for row in rows),
        "hint_matches": (
            sum(row["hint_matches_expectation"] for row in rows)
            if hasattr(core, "classify_with_evidence") else None
        ),
        "non_mcp_source_labeled_mcp": sum(
            row["observed_mcp_candidate"] is True
            and row["source_protocol"] in {"lsp", "generic-json-rpc", "conflicting-signals"}
            for row in rows
        ),
        "cases": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="v0.3.0")
    parser.add_argument("--current", default="HEAD")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    baseline = score(args.baseline)
    current = score(args.current)
    result = {
        "schema_version": 1,
        "scope": (
            "constructed byte buffers scanned by core.scan_chunks; "
            "no physical RAM or Volatility"
        ),
        "interpretation": (
            "MCP candidacy describes recovered bytes, not transmission or execution; "
            "case counts are not population precision, recall, or runtime benchmarks"
        ),
        "baseline": baseline,
        "current": current,
        "changed_cases": [
            row["case"] for before, row in zip(baseline["cases"], current["cases"], strict=True)
            if before["observed_mcp_candidate"] != row["observed_mcp_candidate"]
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    all_expected = (
        current["mcp_candidate_matches"] == len(CASES)
        and current["hint_matches"] == len(CASES)
    )
    return 0 if all_expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
