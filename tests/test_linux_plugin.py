"""Linux adapter integration with real Volatility layers and synthetic tasks/VMAs."""

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest
from test_core import encode, request
from test_plugin import ROOT, GappedLayer, plugin_module, rows_of
from volatility3.cli import CommandLine
from volatility3.framework import contexts, exceptions
from volatility3.framework.layers.physical import BufferDataLayer


def make_task(context, pid, data, ranges=None, layer_type=BufferDataLayer):
    layer_name = f"task-{pid}"
    context.layers.add_layer(layer_type(context, layer_name, layer_name, data))
    ranges = ranges if ranges is not None else [(0, len(data))]
    vmas = [SimpleNamespace(vm_start=start, vm_end=end) for start, end in ranges]
    return SimpleNamespace(
        pid=pid,
        tgid=pid,
        comm="mcp-server",
        mm=SimpleNamespace(get_vma_iter=lambda: iter(vmas)),
        add_process_layer=lambda: layer_name,
    )


@pytest.fixture
def linux_adapter(monkeypatch):
    module = plugin_module("linux")
    context = contexts.Context()
    req = encode(request(tool="read_file", arguments={"path": "/etc/shadow"}))
    resp = encode({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}, "utf-16-le")
    memory = b"\0" * 256 + req + b"\0" * 101 + resp + b"\0" * 256
    tasks = [make_task(context, 42, memory)]

    def list_tasks(*, context, vmlinux_module_name, filter_func, include_threads):
        assert vmlinux_module_name == "synthetic-kernel"
        assert include_threads is False
        return (task for task in tasks if not filter_func(task))

    monkeypatch.setattr(module.pslist.PsList, "list_tasks", list_tasks)
    monkeypatch.setattr(module.utility, "array_to_string", lambda value: value)
    requirements = module.MCPTrace.get_requirements()
    # Kernel objects are test doubles; layer reading, filtering, parsing, TreeGrid,
    # and the JSONL file handler use the real installed Volatility implementation.
    monkeypatch.setattr(module.MCPTrace, "get_requirements", classmethod(lambda cls: []))
    config = "plugins.LinuxMCPTrace"
    context.config[f"{config}.kernel"] = "synthetic-kernel"
    for requirement in requirements:
        if requirement.name not in {"kernel", "pslist"}:
            context.config[f"{config}.{requirement.name}"] = requirement.default
    return module.MCPTrace(context, config), tasks


def summary(rows):
    return json.loads(rows[-1][13])


def test_linux_extracts_both_encodings_and_posix_policy(linux_adapter):
    plugin, _ = linux_adapter
    plugin.config["policy"] = str(ROOT / "examples" / "policy-linux.json")
    grid = plugin.run()
    assert "VMAStart" in [column.name for column in grid.columns]
    rows = rows_of(plugin)
    assert len(rows) == 3
    assert {row[4] for row in rows[:-1]} == {"utf-8", "utf-16-le"}
    assert all(row[0] == 42 and row[10] == "candidate-only" for row in rows[:-1])
    assert rows[0][3] == 256
    assert json.loads(rows[0][12])[0]["status"] == "policy-match"
    assert summary(rows)["target_os"] == "linux"
    assert summary(rows)["regions_scanned"] == 1


@pytest.mark.parametrize("selected,expected", [([42], {42}), ([99], {99}), ([123], set())])
def test_linux_pid_filter(linux_adapter, selected, expected):
    plugin, tasks = linux_adapter
    tasks.append(make_task(plugin.context, 99, encode(request(99))))
    plugin.config["pid"] = selected
    assert {row[0] for row in rows_of(plugin)} == expected


def test_linux_does_not_link_ids_between_processes(linux_adapter):
    plugin, tasks = linux_adapter
    tasks[:] = [
        make_task(plugin.context, 100, encode(request(8))),
        make_task(plugin.context, 101, encode({"jsonrpc": "2.0", "id": 8, "result": {}})),
    ]
    plugin.config["include-rpc"] = True
    rows = [row for row in rows_of(plugin) if row[5] == "complete"]
    assert len(rows) == 2 and all(row[10] == "unpaired" for row in rows)


def test_linux_kernel_thread_never_uses_borrowed_mm(linux_adapter):
    plugin, tasks = linux_adapter
    tasks[0].active_mm = tasks[0].mm
    tasks[0].mm = None

    def forbidden_layer():
        pytest.fail("No process layer should be constructed for a kernel thread")

    tasks[0].add_process_layer = forbidden_layer
    rows = rows_of(plugin)
    assert len(rows) == 1
    assert summary(rows)["skipped_reason"] == "no-user-address-space"
    assert summary(rows)["bytes_read"] == 0 and summary(rows)["error"] is None


def test_linux_failed_process_layer_does_not_abort_next_process(linux_adapter):
    plugin, tasks = linux_adapter
    tasks[0].add_process_layer = lambda: None
    tasks.append(make_task(plugin.context, 99, encode(request(99))))
    rows = rows_of(plugin)
    assert json.loads(rows[0][13])["skipped_reason"] == "no-process-layer"
    assert any(row[0] == 99 and row[5] == "complete" for row in rows)


def test_linux_vm_end_is_exclusive(linux_adapter):
    plugin, tasks = linux_adapter
    first, second = encode(request(1)), encode(request(2))
    start = 123
    tasks[:] = [
        make_task(plugin.context, 99, b"\0" * start + first + second, [(start, start + len(first))])
    ]
    rows = rows_of(plugin)
    assert len(rows) == 2 and json.loads(rows[0][7]) == 1
    assert rows[0][2] == start and summary(rows)["bytes_read"] == len(first)


def test_linux_adjacent_vmas_are_not_joined(linux_adapter):
    plugin, tasks = linux_adapter
    raw = encode(request(text="x" * 200))
    tasks[:] = [make_task(plugin.context, 99, raw, [(0, 80), (80, len(raw))])]
    plugin.config["include-partial"] = True
    rows = rows_of(plugin)
    assert any(row[5] == "fragment" for row in rows)
    assert all(row[5] != "complete" for row in rows)
    assert summary(rows)["regions_scanned"] == 2


def test_linux_missing_page_does_not_bridge_messages(linux_adapter):
    plugin, tasks = linux_adapter
    raw = encode(request(1, text="x" * 200))
    intact = encode(request(2))
    data = bytearray(12288)
    data[4000:4096] = raw[:96]
    data[8192 : 8192 + len(raw[96:])] = raw[96:]
    data[9000 : 9000 + len(intact)] = intact
    tasks[:] = [make_task(plugin.context, 99, bytes(data), layer_type=GappedLayer)]
    plugin.config["include-partial"] = True
    rows = rows_of(plugin)
    assert [json.loads(row[7]) for row in rows if row[5] == "complete"] == [2]
    assert summary(rows)["unreadable_bytes"] == 4096
    assert summary(rows)["bytes_read"] == 8192


@pytest.mark.parametrize("failure", ["unreadable", "unsupported-layout"])
def test_linux_later_vma_failure_preserves_existing_evidence(linux_adapter, failure):
    plugin, tasks = linux_adapter
    first = next(tasks[0].mm.get_vma_iter())

    def broken_vmas():
        yield first
        if failure == "unreadable":
            raise exceptions.InvalidAddressException("synthetic-kernel", 0xBAD)
        raise AttributeError("Unable to find mmap or mm_mt in mm_struct")

    tasks[0].mm.get_vma_iter = broken_vmas
    rows = rows_of(plugin)
    assert len([row for row in rows if row[5] == "complete"]) == 2
    assert summary(rows)["limits_hit"] == ["process-read-error"]
    assert summary(rows)["error"] is not None


def test_linux_invalid_vma_ranges_are_reported(linux_adapter):
    plugin, tasks = linux_adapter
    raw = encode(request())
    tasks[:] = [make_task(plugin.context, 99, raw, [(-1, 1), (0, 0), (2, 1), (0, len(raw))])]
    rows = rows_of(plugin)
    assert len(rows) == 2 and summary(rows)["invalid_regions"] == 3


@pytest.mark.parametrize("option,limit,count", [("max-bytes", 128, 0), ("max-records", 1, 1)])
def test_linux_limits_are_visible(linux_adapter, option, limit, count):
    plugin, _ = linux_adapter
    plugin.config[option] = limit
    rows = rows_of(plugin)
    assert len(rows) == count + 1
    assert summary(rows)["limits_hit"] == [option]


def test_linux_suspicious_only_with_posix_policy(linux_adapter):
    plugin, _ = linux_adapter
    plugin.config["policy"] = str(ROOT / "examples" / "policy-linux.json")
    plugin.config["suspicious-only"] = True
    rows = rows_of(plugin)
    assert len(rows) == 2 and rows[0][6] == "request"


def test_linux_jsonl_records_vma_provenance_and_exact_raw(linux_adapter, tmp_path):
    plugin, _ = linux_adapter
    cli = CommandLine()
    cli.output_dir = str(tmp_path)
    plugin.set_open_method(cli.file_handler_class_factory())
    plugin.config["dump"] = True
    rows_of(plugin)
    exported = [
        json.loads(line)
        for line in (tmp_path / "mcptrace.pid-42.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert exported[0]["target_os"] == "linux" and exported[0]["region_kind"] == "vma"
    records = exported[1:-1]
    assert len(records) == 2 and exported[-1]["type"] == "scan-summary"
    for item in records:
        assert item["target_os"] == "linux" and item["region_kind"] == "vma"
        assert item["vma_start"] == item["region_start"] == 0 and "vad_start" not in item
        raw = base64.b64decode(item["raw_base64"])
        assert hashlib.sha256(raw).hexdigest() == item["raw_sha256"]
        assert json.loads(raw.decode(item["encoding"])) == item["message"]
