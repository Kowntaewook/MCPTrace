import json

from mcptrace import core
from mcptrace.core import classify, scan_chunks


def carve(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return list(scan_chunks([(0x4000, raw)]))


def test_legacy_initialize():
    msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "fixture", "version": "1.0"}}}
    record, = carve(msg)
    assert record.mcp and record.protocol_version == "2025-11-25"
    assert record.to_dict()["declared_protocol_version"] == "2025-11-25"


def test_lsp_initialize_not_mcp():
    msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"processId": 12, "capabilities": {}}}
    assert classify(msg) == ("request", False)
    record, = carve(msg)
    assert not record.mcp


def test_modern_mcp_request():
    msg = {"jsonrpc": "2.0", "id": 7, "method": "server/discover", "params": {
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                  "io.modelcontextprotocol/clientCapabilities": {}}}}
    record, = carve(msg)
    assert record.mcp and record.protocol_version == "2026-07-28"


def test_modern_response_and_methods():
    assert classify({"jsonrpc": "2.0", "id": 1, "method": "subscriptions/listen"}) == ("request", True)
    assert classify({"jsonrpc": "2.0", "id": 2, "method": "tasks/update"}) == ("request", True)
    msg = {"jsonrpc": "2.0", "id": 2, "result": {
        "resultType": "complete", "supportedVersions": ["2026-07-28"], "capabilities": {}}}
    assert classify(msg) == ("response", True)


def test_unrelated_metadata_not_mcp():
    msg = {"jsonrpc": "2.0", "id": 1, "method": "other/call", "params": {
        "_meta": {"io.modelcontextprotocol/protocolVersion": "bad",
                  "io.modelcontextprotocol/clientCapabilities": {}}}}
    assert classify(msg) == ("request", False)


def test_anchor_free_skips_object_start_search(monkeypatch):
    class ForbiddenStartSearch:
        def finditer(self, data):
            raise AssertionError("object starts scanned without anchor")
    monkeypatch.setattr(core, "PATTERNS", {
        encoding: (anchor, ForbiddenStartSearch())
        for encoding, (anchor, _) in core.PATTERNS.items()
    })
    assert list(scan_chunks([(0, b'{"a":1}' * 50000)])) == []
