import base64
import hashlib
import importlib
import json
import subprocess
import sys
import sysconfig
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_core import encode, request
from volatility3.cli import CommandLine
from volatility3.framework import contexts, exceptions
from volatility3.framework.layers.physical import BufferDataLayer

from mcptrace.core import ScanStats, scan_chunks
from mcptrace.memory import readable_chunks

ROOT = Path(__file__).resolve().parents[1]


def plugin_module():
    import volatility3.plugins.windows

    plugin_path = str(ROOT / "plugins" / "windows")
    if plugin_path not in volatility3.plugins.windows.__path__:
        volatility3.plugins.windows.__path__.insert(0, plugin_path)
    return importlib.import_module("volatility3.plugins.windows.mcptrace")


class GappedLayer(BufferDataLayer):
    def read(self, offset, length, pad=False):
        if offset < 8192 and offset + length > 4096:
            raise exceptions.InvalidAddressException(self.name, max(offset, 4096))
        return super().read(offset, length, pad=pad)


def test_real_volatility_layer_does_not_bridge_missing_page():
    context = contexts.Context()
    intact = encode(request(2))
    split = encode(request(1))
    data = bytearray(b"\0" * 12288)
    data[4000:4096] = split[:96]
    data[8192 : 8192 + len(split[96:])] = split[96:]
    data[9000 : 9000 + len(intact)] = intact
    layer = GappedLayer(context, "memory", "memory", bytes(data))
    stats = ScanStats()
    records = list(
        scan_chunks(
            readable_chunks(layer, 0, len(data), stats, exceptions.InvalidAddressException),
            include_partial=True,
        )
    )
    assert [r.request_id for r in records if r.state == "complete"] == [2]
    assert stats.bytes_read == 8192 and stats.unreadable_bytes == 4096


@pytest.fixture
def adapter(monkeypatch):
    module = plugin_module()
    context = contexts.Context()
    req = encode(request(tool="read_file", arguments={"path": r"C:\Secret\key.txt"}))
    resp = encode({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}, "utf-16-le")
    memory = b"\0" * 256 + req + b"\0" * 100 + resp + b"\0" * 256
    context.layers.add_layer(BufferDataLayer(context, "mem", "mem", memory))
    vad = SimpleNamespace(get_start=lambda: 0, get_size=lambda: len(memory))
    proc = SimpleNamespace(
        UniqueProcessId=42,
        ImageFileName="agent.exe",
        add_process_layer=lambda: "mem",
        get_vad_root=lambda: SimpleNamespace(traverse=lambda: iter([vad])),
    )
    monkeypatch.setattr(module.pslist.PsList, "list_processes", lambda **kw: iter([proc]))
    monkeypatch.setattr(module.utility, "array_to_string", lambda value: value)
    requirements = module.MCPTrace.get_requirements()
    # Synthetic EPROCESS/VADs, real Volatility memory layer and TreeGrid. This does
    # not replace a real Windows kernel/symbol integration test.
    monkeypatch.setattr(module.MCPTrace, "get_requirements", classmethod(lambda cls: []))
    context.config["plugins.MCPTrace.kernel"] = "synthetic-kernel"
    for requirement in requirements:
        if requirement.name not in {"kernel", "pslist"}:
            context.config[f"plugins.MCPTrace.{requirement.name}"] = requirement.default
    plugin = module.MCPTrace(context, "plugins.MCPTrace")
    return plugin, proc


def rows_of(plugin):
    rows = []
    grid = plugin.run()
    grid.populate(lambda node, acc: acc.append(tuple(node.values)) or acc, rows)
    return rows


def test_adapter_treegrid_with_real_framework_and_policy(adapter):
    plugin, _ = adapter
    plugin.config["policy"] = str(ROOT / "examples" / "policy.json")
    rows = rows_of(plugin)
    artifacts = [row for row in rows if row[5] != "scan-summary"]
    assert len(artifacts) == 2
    assert {row[4] for row in artifacts} == {"utf-8", "utf-16-le"}
    assert all(row[0] == 42 and row[10] == "candidate-only" for row in artifacts)
    assert json.loads(artifacts[0][12])[0]["status"] == "policy-match"
    assert json.loads(rows[-1][13])["candidate_records"] == 2


def test_limit_is_in_summary(adapter):
    plugin, _ = adapter
    plugin.config["max-records"] = 1
    rows = rows_of(plugin)
    assert json.loads(rows[-1][13])["limits_hit"] == ["max-records"]


def test_suspicious_only_retains_summary(adapter):
    plugin, _ = adapter
    plugin.config["policy"] = str(ROOT / "examples" / "policy.json")
    plugin.config["suspicious-only"] = True
    rows = rows_of(plugin)
    assert len(rows) == 2 and rows[0][6] == "request" and rows[1][5] == "scan-summary"


def test_suspicious_only_without_policy_fails(adapter):
    plugin, _ = adapter
    plugin.config["suspicious-only"] = True
    with pytest.raises(ValueError, match="nonempty"):
        plugin.run()


def test_cli_plugin_discovery_and_help():
    executable = Path(sysconfig.get_path("scripts")) / (
        "vol.exe" if sys.platform == "win32" else "vol"
    )
    result = subprocess.run(
        [str(executable), "-p", str(ROOT / "plugins"), "windows.mcptrace.MCPTrace", "-h"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "--include-partial" in result.stdout and "--max-object-bytes" in result.stdout


def test_later_vad_failure_keeps_prior_evidence(adapter):
    plugin, proc = adapter
    first = next(proc.get_vad_root().traverse())

    def broken_traversal():
        yield first
        raise exceptions.InvalidAddressException("synthetic-kernel", 0xBAD)

    proc.get_vad_root = lambda: SimpleNamespace(traverse=broken_traversal)
    rows = rows_of(plugin)
    assert len([row for row in rows if row[5] == "complete"]) == 2
    summary = json.loads(rows[-1][13])
    assert summary["limits_hit"] == ["process-read-error"]
    assert summary["error"] is not None


def test_byte_budget_keeps_summary_without_claiming_no_evidence(adapter):
    plugin, _ = adapter
    plugin.config["max-bytes"] = 128
    rows = rows_of(plugin)
    assert len(rows) == 1
    summary = json.loads(rows[0][13])
    assert summary["bytes_read"] == 128
    assert summary["limits_hit"] == ["max-bytes"] and summary["absence_is_not_proof"]


def test_export_uses_real_cli_handler_and_roundtrips_raw_evidence(adapter, tmp_path):
    plugin, _ = adapter
    cli = CommandLine()
    cli.output_dir = str(tmp_path)
    plugin.set_open_method(cli.file_handler_class_factory())
    plugin.config["dump"] = True
    rows_of(plugin)
    exported = [
        json.loads(line) for line in (tmp_path / "mcptrace.pid-42.jsonl").read_text().splitlines()
    ]
    assert exported[0]["type"] == "metadata"
    assert exported[-1]["type"] == "scan-summary"
    artifacts = [item for item in exported if item["type"] == "artifact"]
    assert len(artifacts) == 2
    for item in artifacts:
        raw = base64.b64decode(item["raw_base64"])
        assert hashlib.sha256(raw).hexdigest() == item["raw_sha256"]
        assert json.loads(raw.decode(item["encoding"])) == item["message"]


def test_export_collision_reports_actual_filename(adapter, tmp_path):
    plugin, _ = adapter
    original = tmp_path / "mcptrace.pid-42.jsonl"
    original.write_text("existing evidence", encoding="utf-8")
    cli = CommandLine()
    cli.output_dir = str(tmp_path)
    plugin.set_open_method(cli.file_handler_class_factory())
    plugin.config["dump"] = True
    rows = rows_of(plugin)
    filename = json.loads(rows[-1][13])["export"]
    assert filename != original.name
    assert (tmp_path / filename).is_file()
    assert original.read_text() == "existing evidence"


def test_adjacent_vads_are_never_joined(adapter):
    plugin, proc = adapter
    data = encode(request(text="x" * 200))
    context = plugin.context
    context.layers.add_layer(BufferDataLayer(context, "split", "split", data))
    proc.add_process_layer = lambda: "split"
    vads = [
        SimpleNamespace(get_start=lambda: 0, get_size=lambda: 80),
        SimpleNamespace(get_start=lambda: 80, get_size=lambda: len(data) - 80),
    ]
    proc.get_vad_root = lambda: SimpleNamespace(traverse=lambda: iter(vads))
    rows = rows_of(plugin)
    assert len(rows) == 1 and rows[0][5] == "scan-summary"
