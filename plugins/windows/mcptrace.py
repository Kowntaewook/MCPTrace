"""MCP artifacts in Windows process virtual memory (Volatility 3)."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

from mcptrace import __version__
from mcptrace.core import ScanStats, correlate, relevant_records, scan_chunks, strict_loads
from mcptrace.memory import readable_chunks
from mcptrace.policy import evaluate, validate_policy

LOG = logging.getLogger(__name__)


def _json(value) -> str:
    # Escape terminal control characters and preserve string versus numeric IDs.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


class MCPTrace(interfaces.plugins.PluginInterface):
    """Extract MCP/JSON-RPC candidates and policy findings from Windows VADs."""

    _required_framework_version = (2, 28, 0)
    _version = (0, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows x64 kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Only scan these process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max-object-bytes",
                description="Maximum complete JSON size in bytes",
                default=65536,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max-records",
                description="Maximum candidate artifacts per process",
                default=10000,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max-bytes",
                description="VAD bytes to attempt per process; 0 is unlimited",
                default=0,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-partial",
                description="Include raw, unparsed JSON-RPC fragments",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-rpc",
                description="Also show unrelated generic JSON-RPC artifacts",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="policy",
                description="Local JSON policy path (optional; no built-in verdicts)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="suspicious-only",
                description="Show policy matches only, plus scan summaries",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Export JSONL with exact raw bytes and SHA-256 using -o",
                default=False,
                optional=True,
            ),
        ]

    def _scan_process(self, proc, stats, records, limits):
        layer = self.context.layers[proc.add_process_layer()]
        pid = int(proc.UniqueProcessId)
        seen = set()
        attempted = 0
        maximum = self.config["max-object-bytes"]
        budget = self.config["max-bytes"]
        for vad in proc.get_vad_root().traverse():
            start, size = int(vad.get_start()), int(vad.get_size())
            if start < 0 or size <= 0:
                continue
            if budget and attempted >= budget:
                limits.append("max-bytes")
                break
            amount = min(size, budget - attempted) if budget else size
            chunks = readable_chunks(
                layer, start, amount, stats, exceptions.InvalidAddressException
            )
            for record in scan_chunks(
                chunks,
                max_object_bytes=maximum,
                include_partial=self.config["include-partial"],
                stats=stats,
            ):
                key = record.address, record.encoding
                if key in seen:
                    continue
                seen.add(key)
                record.pid, record.vad_start = pid, start
                records.append(record)
                if len(records) >= self.config["max-records"]:
                    limits.append("max-records")
                    return
            attempted += amount
            if amount < size:
                limits.append("max-bytes")
                break

    @staticmethod
    def _row(pid, name, record):
        return (
            pid,
            name,
            format_hints.Hex(record.vad_start),
            format_hints.Hex(record.address),
            record.encoding,
            record.state,
            record.kind,
            _json(record.request_id),
            _json(record.method),
            _json(record.tool),
            record.relation,
            _json(
                {
                    "addresses": [hex(a) for a in record.candidate_addresses],
                    "total": record.candidate_count,
                    "truncated": record.candidate_count > len(record.candidate_addresses),
                }
            ),
            _json(record.findings),
            _json(record.raw.decode(record.encoding, errors="backslashreplace")),
            record.sha256,
        )

    @staticmethod
    def _summary_row(pid, name, summary):
        return (
            pid,
            name,
            format_hints.Hex(0),
            format_hints.Hex(0),
            "",
            "scan-summary",
            "scan-summary",
            "",
            "",
            "",
            "",
            "",
            "",
            _json(summary),
            "",
        )

    def _export(self, pid, process, records, summary):
        with self.open(f"mcptrace.pid-{pid}.jsonl") as output:
            header = {
                "type": "metadata",
                "mcptrace_version": __version__,
                "pid": pid,
                "process": process,
                "address_space": "process-virtual",
                "correlation": "same PID and typed ID only; session/direction not recovered",
            }
            output.write((_json(header) + "\n").encode())
            for record in records:
                output.write((_json({"type": "artifact", **record.to_dict()}) + "\n").encode())
            output.write((_json({"type": "scan-summary", **summary}) + "\n").encode())
        # The CLI may rename an existing destination when the handler closes.
        return output.preferred_filename

    def _generator(self, rules):
        filters = pslist.PsList.create_pid_filter(self.config.get("pid"))
        processes = pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config["kernel"], filter_func=filters
        )
        for proc in processes:
            pid = int(proc.UniqueProcessId)
            try:
                name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                name = "<unreadable>"
            display_name = _json(name)[1:-1]
            stats = ScanStats()
            error = None
            records, limits = [], []
            try:
                self._scan_process(proc, stats, records, limits)
            except (exceptions.InvalidAddressException, exceptions.SymbolError) as exc:
                # Keep evidence recovered before a later VAD or symbol failure.
                limits.append("process-read-error")
                error = str(exc)
                LOG.warning("PID %d: %s", pid, exc)
            correlate(records)
            for record in records:
                record.findings = evaluate(record, rules)
            relevant = relevant_records(records, self.config["include-rpc"])
            visible = relevant
            if self.config["suspicious-only"]:
                visible = [
                    r for r in relevant if any(f["status"] == "policy-match" for f in r.findings)
                ]
            summary = {
                **asdict(stats),
                "candidate_records": len(records),
                "relevant_records": len(relevant),
                "displayed_records": len(visible),
                "limits_hit": limits,
                "error": error,
                "scope": "readable bytes exposed by pslist process VAD layers",
                "absence_is_not_proof": True,
            }
            if limits or stats.anchor_limit_hits or stats.candidate_limit_hits:
                LOG.warning("PID %d scan is limited: %s", pid, _json(summary))
            if self.config["dump"]:
                summary["export"] = self._export(pid, name, visible, summary)
            for record in sorted(visible, key=lambda r: (r.address, r.encoding)):
                yield 0, self._row(pid, display_name, record)
            yield 0, self._summary_row(pid, display_name, summary)

    def run(self):
        maximum = self.config["max-object-bytes"]
        if not 256 <= maximum <= 4 * 1024 * 1024:
            raise ValueError("--max-object-bytes must be between 256 and 4194304")
        if not 1 <= self.config["max-records"] <= 100000:
            raise ValueError("--max-records must be between 1 and 100000")
        if self.config["max-bytes"] < 0:
            raise ValueError("--max-bytes cannot be negative")
        rules = []
        if self.config.get("policy"):
            policy_path = Path(self.config["policy"])
            if policy_path.stat().st_size > 1024 * 1024:
                raise ValueError("Policy file exceeds 1 MiB")
            rules = validate_policy(strict_loads(policy_path.read_text(encoding="utf-8")))
        if self.config["suspicious-only"] and not rules:
            raise ValueError("--suspicious-only requires a nonempty --policy")
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("VADStart", format_hints.Hex),
                ("VirtualAddress", format_hints.Hex),
                ("Encoding", str),
                ("State", str),
                ("Kind", str),
                ("RequestID", str),
                ("Method", str),
                ("Tool", str),
                ("Relation", str),
                ("CandidateAddresses", str),
                ("Findings", str),
                ("Raw", str),
                ("SHA256", str),
            ],
            self._generator(rules),
        )
