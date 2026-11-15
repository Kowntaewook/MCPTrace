"""Audit and copy the synthetic 27-capture wire journals for public replay.

Fails closed if a journal contains a new field or string not observed in the
controlled fixture. This is a content review for these exact logs, not a
general secret scanner or permission to publish arbitrary RAM images.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from mcptrace.core import strict_loads
from validation.mcprecon_comparison.run import canonical


ROOT = Path(__file__).resolve().parents[2]
SOURCE_MANIFEST = ROOT / "validation/linux_x64_http_ram/results/2026-11-14-qemu-http-sdk-rerun.json"
ALLOWED_KEYS = frozenset("""$schema _meta additionalProperties arguments cacheScope capabilities
clientInfo content description execution id inputSchema io.modelcontextprotocol/clientCapabilities
io.modelcontextprotocol/clientInfo io.modelcontextprotocol/protocolVersion
io.modelcontextprotocol/serverInfo jsonrpc listChanged marker method name params properties
protocolVersion required result resultType serverInfo supportedVersions taskSupport text
tools ttlMs type version""".split())
ALLOWED_STRINGS = frozenset({
    "1.0.0", "1.0.0.0", "2.0", "2025-11-25", "2026-07-28", "Client",
    "Return the marker supplied by the client", "complete", "echo_marker",
    "forbidden", "http://json-schema.org/draft-07/schema#", "initialize",
    "marker", "mcptrace-node-validation", "mcptrace-validation",
    "notifications/initialized", "object", "private", "server/discover",
    "string", "text", "tools/call", "tools/list",
})


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_value(value: object, marker_pattern: re.Pattern[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in ALLOWED_KEYS:
                raise ValueError(f"unexpected protocol field: {key}")
            inspect_value(child, marker_pattern)
    elif isinstance(value, list):
        for child in value:
            inspect_value(child, marker_pattern)
    elif isinstance(value, str):
        if value not in ALLOWED_STRINGS and not marker_pattern.fullmatch(value):
            raise ValueError("unexpected string in synthetic traffic")
    elif value is not None and not isinstance(value, (int, float, bool)):
        raise ValueError("unexpected scalar in synthetic traffic")


def audit_journal(data: bytes, run_id: str) -> int:
    prefix = {"node": "NODE", "dotnet-legacy": "DOTNET_LEGACY",
              "dotnet-modern": "DOTNET_MODERN"}[run_id.rsplit("-d", 1)[0]]
    marker_pattern = re.compile(rf"{prefix}_{re.escape(run_id)}-[0-3]")
    distinct = set()
    calls = set()
    responses = set()
    rows = data.splitlines()
    for line in rows:
        row = json.loads(line)
        if set(row) != {"direction", "framing", "message", "wire_base64"}:
            raise ValueError(f"{run_id}: unexpected journal field")
        if row["direction"] not in {"client-to-server", "server-to-client"}:
            raise ValueError(f"{run_id}: unexpected direction")
        if row["framing"] not in {"json", "sse"}:
            raise ValueError(f"{run_id}: unexpected framing")
        wire = base64.b64decode(row["wire_base64"], validate=True)
        if not wire.startswith(b"{") or not wire.endswith(b"}"):
            raise ValueError(f"{run_id}: non-object wire body")
        message = strict_loads(wire.decode("utf-8"))
        if not isinstance(message, dict) or message != row["message"]:
            raise ValueError(f"{run_id}: wire bytes and parsed message differ")
        inspect_value(message, marker_pattern)
        key = canonical(message)
        if key in distinct:
            raise ValueError(f"{run_id}: duplicated logical message")
        distinct.add(key)
        if message.get("method") == "tools/call":
            calls.add(message["params"]["arguments"]["marker"])
        for item in message.get("result", {}).get("content", []):
            responses.add(item["text"])
    if len(calls) != 4 or responses != calls:
        raise ValueError(f"{run_id}: tool-call markers or responses differ")
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.evidence.resolve()
    output = args.output.resolve()
    original = SOURCE_MANIFEST.read_bytes()
    captures = json.loads(original)["captures"]
    runs = []
    for capture in captures:
        run_id = capture["run_id"]
        folder = source / "rerun" / run_id
        data = (folder / "traffic.jsonl").read_bytes()
        count = audit_journal(data, run_id)
        if sha256(data) != capture["traffic_log_sha256"] or count != capture["traffic_messages"]:
            raise ValueError(f"{run_id}: public numeric manifest and traffic differ")
        ready = json.loads((folder / "client-ready.json").read_text(encoding="utf-8"))
        export = next((folder / "exports").glob("mcptrace.pid-*.jsonl"))
        with export.open(encoding="utf-8") as stream:
            header = json.loads(stream.readline())
        if type(ready["pid"]) is not int or ready["pid"] != header["pid"]:
            raise ValueError(f"{run_id}: client PID differs from scanner export")
        runs.append({
            "run_id": run_id, "case": capture["case"], "client_pid": ready["pid"],
            "image_sha256": capture["image_sha256"], "image_bytes": capture["image_bytes"],
            "traffic_messages": count, "traffic_log_sha256": sha256(data),
            "traffic_path": f"traffic/{run_id}.jsonl",
        })
    if len(runs) != 27 or sum(row["traffic_messages"] for row in runs) != 342:
        raise ValueError("expected 27 captures and 342 transmitted messages")
    traffic_dir = output / "traffic"
    traffic_dir.mkdir(parents=True, exist_ok=True)
    for row in runs:
        run_id = row["run_id"]
        (traffic_dir / f"{run_id}.jsonl").write_bytes(
            (source / "rerun" / run_id / "traffic.jsonl").read_bytes()
        )
    manifest = {
        "schema_version": 1,
        "scope": "Synthetic external wire JSON bodies for the preserved 27 Linux RAM captures",
        "source_numeric_manifest_sha256": sha256(original),
        "runs": runs,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Audited 27 synthetic traffic journals and copied 342 exact wire bodies.")


if __name__ == "__main__":
    main()
