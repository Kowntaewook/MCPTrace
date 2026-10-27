"""Shared scanning and output for OS-specific Volatility adapters.

The mixin deliberately is not a PluginInterface subclass: only the concrete
Windows and Linux adapters should appear in Volatility's plugin discovery.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from mcptrace import __version__
from mcptrace.core import ScanStats, correlate, relevant_records, scan_chunks, strict_loads
from mcptrace.memory import readable_chunks
from mcptrace.policy import evaluate, validate_policy

LOG = logging.getLogger(__name__)


def _json(value) -> str:
    # Escape terminal control characters and preserve string versus numeric IDs.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


class SkipProcess(Exception):
    """An enumerated process has no usable user address space; report the reason."""


class UnsupportedMemoryLayout(Exception):
    """The framework cannot enumerate this process's memory mappings."""


class MCPTraceMixin:
    """Adapters provide process enumeration, identity, and memory regions."""

    @classmethod
    def common_requirements(cls):
        return [
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
                description="Memory-region bytes to attempt per process; 0 is unlimited",
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
        layer_name = self._process_layer_name(proc)
        if not layer_name:
            raise SkipProcess("no-process-layer")
        layer = self.context.layers[layer_name]
        pid = self._pid(proc)
        seen = set()
        attempted = 0
        maximum = self.config["max-object-bytes"]
        budget = self.config["max-bytes"]
        for start, size in self._regions(proc):
            if start < 0 or size <= 0:
                stats.invalid_regions += 1
                continue
            if budget and attempted >= budget:
                limits.append("max-bytes")
                break
            amount = min(size, budget - attempted) if budget else size
            stats.regions_scanned += 1
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
                record.pid, record.region_start = pid, start
                record.region_kind = self._region_kind
                record.target_os = self._target_os
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
            format_hints.Hex(record.region_start),
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
                "target_os": self._target_os,
                "region_kind": self._region_kind,
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
        for proc in self._list_processes():
            pid = self._pid(proc)
            try:
                name = self._process_name(proc)
            except exceptions.InvalidAddressException:
                name = "<unreadable>"
            display_name = _json(name)[1:-1]
            stats = ScanStats()
            error = None
            skipped_reason = None
            records, limits = [], []
            try:
                self._scan_process(proc, stats, records, limits)
            except SkipProcess as exc:
                skipped_reason = str(exc)
            except (
                exceptions.InvalidAddressException,
                exceptions.SymbolError,
                UnsupportedMemoryLayout,
            ) as exc:
                # Keep evidence recovered before a later mapping or symbol failure.
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
                "skipped_reason": skipped_reason,
                "target_os": self._target_os,
                "scope": (
                    f"readable bytes exposed by pslist process {self._region_kind.upper()} layers"
                ),
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
                (self._region_kind.upper() + "Start", format_hints.Hex),
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
