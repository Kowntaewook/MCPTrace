"""Check the independent wire probe at read-block boundaries."""

import base64
import json

from validation.cross_runtime import run


def test_exact_wire_probe_uses_the_scanned_bytes(tmp_path, monkeypatch):
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo"}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    ]
    wire = [json.dumps(message, separators=(",", ":")).encode() for message in messages]
    content = (
        b" " * (run.BLOCK - 8)
        + wire[0]
        + b" " * (run.BLOCK - len(wire[0]) - 8)
        + wire[1].decode().encode("utf-16-le")
        + b" " * 100
    )
    memory = tmp_path / "memory.bin"
    memory.write_bytes(content)
    original_open = run.os.open
    monkeypatch.setattr(run, "readable_private_maps", lambda _pid: [(0, len(content))])
    monkeypatch.setattr(run.os, "open", lambda _path, flags: original_open(memory, flags))
    rows = [{"wire_base64": base64.b64encode(payload).decode()} for payload in wire]

    artifacts, stats, encodings = run.scan_process(1, rows)

    assert encodings == [["utf-8"], ["utf-16-le"], []]
    assert {item.obj["id"] for item in artifacts if item.obj} == {1, 2}
    assert stats["artifacts_reverified_at_virtual_address"] == len(artifacts)
    assert stats["read_errors"] == 0
