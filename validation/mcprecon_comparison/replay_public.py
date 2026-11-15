"""Recompute the client-scoped MCPTrace/MCPRecon comparison from public inputs.

One `run` uses a reconstructed RAM image, its published synthetic traffic log,
the pinned scanner sources, and a matching Volatility Linux ISF. `aggregate`
combines 27 independently regenerated numeric run reports. Raw scanner exports
and the derived client stream are temporary and are never put in the report.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from mcptrace.core import strict_loads
from validation.linux_x64_official.score import probe_wire
from validation.linux_x64_positive.score import sha256, verify_exports
from validation.mcprecon_comparison.pack_client_memory import pack
from validation.mcprecon_comparison.prepare_truth import SOURCE_MANIFEST, audit_journal
from validation.mcprecon_comparison.run import MCPRECON_GIT_BLOB, canonical


ROOT = Path(__file__).resolve().parents[2]
TRUTH = ROOT / "validation/mcprecon_comparison/ground_truth"
REFERENCE = ROOT / "validation/mcprecon_comparison/results/2026-11-15-archived-breakdown.json"
ISF_SHA256 = "18dd41722ad7d3b411d442065e6fafa3c177960e3e19ea484b391dfb1526e55b"


def load_run(run_id: str) -> tuple[dict, list[dict]]:
    manifest = json.loads((TRUTH / "manifest.json").read_text(encoding="utf-8"))
    if sha256(SOURCE_MANIFEST) != manifest["source_numeric_manifest_sha256"]:
        raise ValueError("source capture manifest differs from the ground-truth bundle")
    matching = [row for row in manifest["runs"] if row["run_id"] == run_id]
    if len(matching) != 1:
        raise ValueError("unknown or duplicated run ID")
    info = matching[0]
    traffic = TRUTH / info["traffic_path"]
    data = traffic.read_bytes()
    if sha256(traffic) != info["traffic_log_sha256"] or audit_journal(data, run_id) != info["traffic_messages"]:
        raise ValueError("published traffic journal failed its hash or content audit")
    rows = []
    for line in data.splitlines():
        source = json.loads(line)
        raw = base64.b64decode(source["wire_base64"], validate=True)
        if strict_loads(raw.decode("utf-8")) != source["message"]:
            raise ValueError("wire payload and parsed truth differ")
        rows.append({"raw": raw, "message": source["message"],
                     "direction": source["direction"], "framing": source["framing"]})
    return info, rows


def git_blob(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def score_run(args: argparse.Namespace) -> dict:
    info, traffic = load_run(args.run_id)
    if args.image.stat().st_size != info["image_bytes"] or sha256(args.image) != info["image_sha256"]:
        raise ValueError("reconstructed RAM image size or SHA-256 mismatch")
    symbol_files = list((args.symbols / "linux").glob(
        "Ubuntu_6.8.0-146-generic_6.8.0-146.146_amd64.json.xz"))
    if len(symbol_files) != 1 or sha256(symbol_files[0]) != ISF_SHA256:
        raise ValueError("Linux symbol file SHA-256 mismatch")
    if git_blob(args.mcprecon) != MCPRECON_GIT_BLOB:
        raise ValueError("MCPRecon source differs from the pinned public Git blob")
    pid = info["client_pid"]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"replay-{args.run_id}-", dir=args.work_dir) as temp:
        work = Path(temp)
        exports = work / "exports"
        exports.mkdir()
        config = work / "config.json"
        command = [str(args.vol.resolve()), "-q", "--cache-path", str(args.cache.resolve()),
                   "-s", str(args.symbols.resolve()), "-p", str(ROOT / "plugins"),
                   "-f", str(args.image.resolve()), "-o", str(exports),
                   "--save-config", str(config), "linux.mcptrace.MCPTrace",
                   "--pid", str(pid), "--include-rpc", "--dump"]
        with (work / "vol.stdout").open("w") as stdout, (work / "vol.stderr").open("w") as stderr:
            subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout,
                           stderr=stderr, check=True, timeout=1800)
        exported = exports / f"mcptrace.pid-{pid}.jsonl"
        if not exported.exists():
            raise ValueError("no MCPTrace export for the published client PID")
        artifacts, scans = verify_exports([exported], args.symbols, args.cache, config)
        if len(scans) != 1 or scans[0]["pid"] != pid:
            raise ValueError("scanner export does not belong to the published client PID")
        flags, _ = probe_wire(pid, traffic, args.symbols, args.cache, config)
        present = {canonical(row["message"]) for row, flag in zip(traffic, flags, strict=True)
                   if flag["utf8"] or flag["utf16le"]}
        truth = {canonical(row["message"]) for row in traffic}
        if len(truth) != len(traffic):
            raise ValueError("duplicate transmitted logical messages")
        trace = {canonical(row["message"]) for row in artifacts}
        trace_mcp = {canonical(row["message"]) for row in artifacts if row["mcp_candidate"]}
        packed = work / "client.bin"
        pack_stats = pack(args.image, config, args.symbols, args.cache, pid, packed)
        # Cross-check the independent Volatility probe against the exact derived
        # bytes that the MCPRecon CLI will scan.
        packed_bytes = packed.read_bytes()
        for row, flag in zip(traffic, flags, strict=True):
            utf8 = row["raw"] in packed_bytes
            utf16le = row["raw"].decode("utf-8").encode("utf-16-le") in packed_bytes
            if (utf8, utf16le) != (flag["utf8"], flag["utf16le"]):
                raise ValueError("packed client bytes and independent VMA probe differ")
        del packed_bytes
        recon_path = work / "mcprecon.jsonl"
        with recon_path.open("w") as output, (work / "mcprecon.stderr").open("w") as stderr:
            subprocess.run([sys.executable, str(args.mcprecon.resolve()), str(packed),
                            "--quiet", "--emit-raw", "--temp-dir", str(work / "mcprecon-temp")],
                           cwd=ROOT, stdout=output, stderr=stderr, check=True, timeout=1800)
        recon = [json.loads(line) for line in recon_path.read_text(encoding="utf-8").splitlines()]
        with packed.open("rb") as stream:
            for record in recon:
                raw = record["raw"].encode("utf-8")
                stream.seek(record["offset"])
                if stream.read(len(raw)) != raw:
                    raise ValueError("MCPRecon output does not match its scanned byte offset")
        recon_found = {canonical(row["json"]) for row in recon}
        recon_mcp = {canonical(row["json"]) for row in recon if row["mcp"]}
        result = {
            "schema_version": 1, "run_id": args.run_id, "case": info["case"],
            "image_sha256": info["image_sha256"], "traffic_log_sha256": info["traffic_log_sha256"],
            "traffic_messages": len(traffic), "present_utf8": sum(x["utf8"] for x in flags),
            "present_utf16le": sum(x["utf16le"] for x in flags), "wire_present": len(present),
            "mcptrace_records_verified": len(artifacts), "mcptrace_carved": len(trace & present),
            "mcptrace_mcp_labeled": len(trace_mcp & present),
            "mcprecon_records_verified": len(recon), "mcprecon_carved": len(recon_found & present),
            "mcprecon_mcp_labeled": len(recon_mcp & present),
            "mcptrace_unmatched_records": sum(canonical(x["message"]) not in truth for x in artifacts),
            "mcprecon_unmatched_records": sum(canonical(x["json"]) not in truth for x in recon),
            "packed_client_bytes": pack_stats["packed_bytes"],
            "scan_limits_hit": scans[0]["summary"]["limits_hit"],
        }
    reference = next(row for row in json.loads(REFERENCE.read_text(encoding="utf-8"))["captures"]
                     if row["run_id"] == args.run_id)
    comparisons = {
        "traffic_messages": "traffic_messages",
        "mcptrace_records_verified": "mcptrace_artifact_records",
        "mcptrace_carved": "mcptrace_truth_messages_any_label",
        "mcptrace_mcp_labeled": "mcptrace_truth_messages_mcp_labeled",
        "mcprecon_records_verified": "mcprecon_client_records",
        "mcprecon_carved": "mcprecon_client_truth_messages_any_label",
        "mcprecon_mcp_labeled": "mcprecon_client_truth_messages_mcp_labeled",
    }
    for measured, published in comparisons.items():
        if result[measured] != reference[published]:
            raise ValueError(f"{args.run_id}: regenerated {measured} differs from published audit")
    expected_present = (reference["present_utf8"] + reference["present_utf16le"]
                        - reference["present_both"])
    if (result["wire_present"] != expected_present
            or result["present_utf8"] != reference["present_utf8"]
            or result["present_utf16le"] != reference["present_utf16le"]
            or result["scan_limits_hit"]):
        raise ValueError("encoding count or scan limits differ from published audit")
    return result


def audit_public_truth() -> dict:
    manifest = json.loads((TRUTH / "manifest.json").read_text(encoding="utf-8"))
    original = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    source = {row["run_id"]: row for row in original["captures"]}
    if len(manifest["runs"]) != 27 or len(source) != 27:
        raise ValueError("expected 27 distinct capture identifiers")
    total = 0
    for row in manifest["runs"]:
        info, traffic = load_run(row["run_id"])
        prior = source[info["run_id"]]
        if (info["image_sha256"] != prior["image_sha256"]
                or info["traffic_log_sha256"] != prior["traffic_log_sha256"]):
            raise ValueError("public traffic or RAM hash differs from the capture manifest")
        total += len(traffic)
    if total != 342:
        raise ValueError("expected 342 transmitted messages")
    return {"schema_version": 1, "runs": 27, "traffic_messages": total,
            "status": "all source hashes and synthetic content verified"}


def aggregate(directory: Path) -> dict:
    manifest = json.loads((TRUTH / "manifest.json").read_text())
    required = {row["run_id"]: row for row in manifest["runs"]}
    rows = [json.loads(path.read_text(encoding="utf-8")) for path in directory.glob("*.json")]
    if len(rows) != 27 or {row["run_id"] for row in rows} != set(required):
        raise ValueError("aggregate needs one report for each of the 27 distinct runs")
    for row in rows:
        if (row["schema_version"] != 1 or row["image_sha256"] != required[row["run_id"]]["image_sha256"]
                or row["traffic_log_sha256"] != required[row["run_id"]]["traffic_log_sha256"]):
            raise ValueError("run report hash differs from the public truth manifest")
    fields = ("traffic_messages", "wire_present", "mcptrace_records_verified", "mcptrace_carved",
              "mcptrace_mcp_labeled", "mcprecon_records_verified", "mcprecon_carved",
              "mcprecon_mcp_labeled", "mcptrace_unmatched_records", "mcprecon_unmatched_records")
    totals = {field: sum(row[field] for row in rows) for field in fields}
    expected = {"traffic_messages": 342, "wire_present": 251, "mcptrace_records_verified": 626,
                "mcptrace_carved": 251, "mcptrace_mcp_labeled": 233,
                "mcprecon_records_verified": 315, "mcprecon_carved": 184,
                "mcprecon_mcp_labeled": 94, "mcptrace_unmatched_records": 0,
                "mcprecon_unmatched_records": 0}
    if totals != expected:
        raise ValueError(f"regenerated totals differ from published comparison: {totals}")
    return {"schema_version": 1, "runs": 27, "totals": totals}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="replay one reconstructed RAM image")
    for name in ("image", "symbols", "cache", "vol", "mcprecon", "work-dir", "report"):
        run.add_argument(f"--{name}", required=True, type=Path)
    run.add_argument("--run-id", required=True)
    joined = commands.add_parser("aggregate", help="combine all 27 run reports")
    joined.add_argument("--reports", required=True, type=Path)
    joined.add_argument("--report", required=True, type=Path)
    commands.add_parser("audit", help="check all 27 published traffic journals")
    args = parser.parse_args()
    result = (score_run(args) if args.command == "run" else
              aggregate(args.reports) if args.command == "aggregate" else audit_public_truth())
    if args.command != "audit":
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"run_id": result.get("run_id"), "totals": result.get("totals"),
                      "status": result.get("status", "verified")}))


if __name__ == "__main__":
    main()
