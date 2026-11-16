"""Audit six retained live-host journals; publish only four synthetic controls.

The two Codex CLI journals contain session metadata. Their exact wire bytes and
all six physical-RAM images remain private. This script fails closed for the
four journals copied into the public tree and never copies RAM or raw exports.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path

from mcptrace.core import strict_loads


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CASES = (
    ("inspector-http", "real", "http", "2026-11-15-inspector-http.json"),
    ("inspector-stdio", "real", "stdio", "2026-11-15-inspector-stdio.json"),
    ("lsp-control", "real", "lsp", "2026-11-15-lsp-control.json"),
    ("jsonrpc-control", "real", "jsonrpc", "2026-11-15-jsonrpc-control.json"),
    ("codex-first", "codex", "pilot2", "2026-11-16-codex-pilot.json"),
    ("codex-later", "codex", "pilot2-delayed", "2026-11-16-codex-delayed.json"),
)
PUBLIC_KEYS = frozenset("""$schema account additionalProperties arguments capabilities
clientInfo content description elicitation execution extensions form id inputSchema
io.modelcontextprotocol/skills io.modelcontextprotocol/tasks jsonrpc listChanged
marker method name params processId properties protocolVersion required result
rootUri roots serverInfo source status taskSupport text textDocumentSync tools type
url version workspaceFolders""".split())
PUBLIC_STRINGS = frozenset({
    "1.0", "1.0.0", "2.0", "2.15.0", "2025-11-25",
    "Return a synthetic marker", "Return the marker supplied by the client",
    "account/query", "echo_marker", "file:///tmp/mcptrace-lsp-control",
    "forbidden", "http://json-schema.org/draft-07/schema#", "initialize",
    "inspector-cli", "lsp-control", "marker", "mcptrace-real-host-control",
    "mcptrace-validation", "non-mcp-control", "notifications/initialized",
    "object", "ok", "string", "synthetic-control", "text", "tools/call",
    "tools/list",
})
EXPECTED = {
    "inspector-http": (9, "REALHOST_HTTP_20261115"),
    "inspector-stdio": (9, "REALHOST_STDIO_20261115"),
    "lsp-control": (2, None),
    "jsonrpc-control": (2, None),
    "codex-first": (7, None),
    "codex-later": (7, None),
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_public_value(value: object, marker: str | None) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in PUBLIC_KEYS:
                raise ValueError(f"unexpected public protocol field: {key}")
            inspect_public_value(child, marker)
    elif isinstance(value, list):
        for child in value:
            inspect_public_value(child, marker)
    elif isinstance(value, str):
        if value not in PUBLIC_STRINGS and value != marker:
            raise ValueError("unexpected string in public synthetic traffic")
    elif value is not None and not isinstance(value, (int, float, bool)):
        raise ValueError("unexpected scalar in public synthetic traffic")


def audit_journal(data: bytes, case: str, report: dict, public: bool) -> int:
    expected_count, marker = EXPECTED[case]
    lines = data.splitlines()
    if len(lines) != expected_count or len(lines) != report["traffic_messages"]:
        raise ValueError(f"{case}: traffic message count mismatch")
    for index, line in enumerate(lines):
        row = json.loads(line)
        if public:
            expected_fields = {
                "inspector-http": {"direction", "framing", "message", "wire_base64"},
                "inspector-stdio": {"direction", "observed_ns", "message", "raw_base64", "raw_sha256"},
                "lsp-control": {"direction", "framing", "message", "raw_base64", "raw_sha256"},
                "jsonrpc-control": {"direction", "message", "raw_base64", "raw_sha256"},
            }[case]
            if set(row) != expected_fields:
                raise ValueError(f"{case}: unexpected journal field")
            inspect_public_value(row["message"], marker)
            if case == "lsp-control" and row["framing"] != "content-length":
                raise ValueError("LSP framing changed")
            if case == "inspector-http" and row["framing"] not in {"json", "sse"}:
                raise ValueError("HTTP framing changed")
            if case == "inspector-stdio" and type(row["observed_ns"]) is not int:
                raise ValueError("stdio timing metadata changed")
        else:
            if set(row) != {"direction", "observed_ns", "message", "raw_base64", "raw_sha256"}:
                raise ValueError(f"{case}: Codex journal schema changed")
            if type(row["observed_ns"]) is not int:
                raise ValueError(f"{case}: Codex timing metadata changed")
        if row["direction"] not in {"client-to-server", "server-to-client"}:
            raise ValueError(f"{case}: invalid traffic direction")
        encoded = row.get("wire_base64", row.get("raw_base64"))
        raw = base64.b64decode(encoded, validate=True)
        if not raw.startswith(b"{") or not raw.endswith(b"}"):
            raise ValueError(f"{case}: non-object JSON body")
        parsed = strict_loads(raw.decode("utf-8"))
        if parsed != row["message"]:
            raise ValueError(f"{case}: raw and parsed message differ")
        if "raw_sha256" in row and digest(raw) != row["raw_sha256"]:
            raise ValueError(f"{case}: raw byte digest differs")
        measured = report["messages"][index]
        if (digest(raw) != measured["raw_sha256"]
                or row["direction"] != measured["direction"]
                or row["message"].get("method", "") != measured["method"]):
            raise ValueError(f"{case}: journal and published per-message report differ")
        if public and row.get("framing", "stdio") != measured["framing"]:
            raise ValueError(f"{case}: framing differs from published report")
    if public and marker is not None:
        markers = [r["message"]["params"]["arguments"]["marker"]
                   for r in map(json.loads, lines)
                   if r["message"].get("method") == "tools/call"]
        if markers != [marker]:
            raise ValueError(f"{case}: synthetic tool marker changed")
    return len(lines)


def verify_archive(archive: Path, report: dict) -> None:
    if not HEX64.fullmatch(report["private_ram_archive_sha256"]):
        raise ValueError("invalid archive digest in published report")
    if archive.stat().st_size != report["private_ram_archive_bytes"]:
        raise ValueError(f"archive byte length mismatch: {archive}")
    compressed = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            compressed.update(chunk)
    if compressed.hexdigest() != report["private_ram_archive_sha256"]:
        raise ValueError(f"archive digest mismatch: {archive}")
    restored = hashlib.sha256()
    size = 0
    with subprocess.Popen(["zstd", "-d", "-c", str(archive)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        assert proc.stdout is not None
        for chunk in iter(lambda: proc.stdout.read(4 * 1024 * 1024), b""):
            restored.update(chunk)
            size += len(chunk)
        if proc.wait() != 0:
            raise ValueError(f"archive decompression failed: {archive}")
    if restored.hexdigest() != report["image_sha256"] or size != report["image_bytes"]:
        raise ValueError(f"restored image mismatch: {archive}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--real-private", required=True, type=Path)
    parser.add_argument("--codex-private", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=HERE)
    parser.add_argument("--verify-archives", action="store_true")
    args = parser.parse_args()
    rows = []
    public_data = {}
    for case, family, folder, report_name in CASES:
        private = args.real_private if family == "real" else args.codex_private
        capture = private / "captures" / folder
        report_path = ROOT / "validation" / ("linux_x64_real_host_ram" if family == "real"
                                              else "linux_x64_codex_ram") / "results" / report_name
        report_data = report_path.read_bytes()
        report = json.loads(report_data)
        journal = (capture / "traffic.jsonl").read_bytes()
        public = family == "real"
        count = audit_journal(journal, case, report, public)
        if digest(journal) != report["traffic_log_sha256"]:
            raise ValueError(f"{case}: journal digest differs from published report")
        ready = json.loads((capture / "client-ready.json").read_text())
        if type(ready["pid"]) is not int or ready["pid"] != report["client_pid"]:
            raise ValueError(f"{case}: client PID differs")
        export = capture / "exports" / f"mcptrace.pid-{ready['pid']}.jsonl"
        if digest(export.read_bytes()) != report["export_sha256"]:
            raise ValueError(f"{case}: raw export differs from published report")
        archive = capture / "ram.elf.zst"
        if args.verify_archives:
            verify_archive(archive, report)
        rows.append({
            "case": case,
            "client_pid": ready["pid"],
            "image_sha256": report["image_sha256"],
            "image_bytes": report["image_bytes"],
            "archive_sha256": report["private_ram_archive_sha256"],
            "archive_bytes": report["private_ram_archive_bytes"],
            "traffic_messages": count,
            "traffic_sha256": digest(journal),
            "traffic_path": f"traffic/{case}.jsonl" if public else None,
            "traffic_access": "public exact-wire" if public else "private exact-wire with session metadata",
            "export_sha256": report["export_sha256"],
            "report_path": str(report_path.relative_to(ROOT)),
            "report_sha256": digest(report_data),
        })
        if public:
            public_data[case] = journal
    if len(rows) != 6 or sum(r["traffic_messages"] for r in rows) != 36:
        raise ValueError("unexpected live-host corpus size")
    out = args.output
    (out / "traffic").mkdir(parents=True, exist_ok=True)
    for case, data in public_data.items():
        (out / "traffic" / f"{case}.jsonl").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "scope": "six single-capture Linux x86-64 physical-RAM observations",
        "scanner_source_commit": "ded4c00235f5c41222f72e8529f3dbd617bc3c9f",
        "volatility_version": "2.28.2",
        "private_ram_images": 6,
        "public_exact_wire_journals": 4,
        "private_exact_wire_journals": 2,
        "captures": rows,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Audited six journals and exports; published four synthetic exact-wire journals.")


if __name__ == "__main__":
    main()
