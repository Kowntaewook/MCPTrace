"""Regression checks for legacy and modern MCP candidate recognition."""

import json

import pytest

from mcptrace import core
from mcptrace.core import classify, relevant_records, scan_chunks


def carve(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return list(scan_chunks([(0x4000, raw)]))


def test_legacy_initialize():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "fixture", "version": "1.0"},
        },
    }
    (record,) = carve(msg)
    assert record.mcp and record.protocol_version == "2025-11-25"
    assert record.to_dict()["declared_protocol_version"] == "2025-11-25"
    assert record.protocol_hint == "mcp-candidate"
    assert "mcp-legacy-initialize-envelope" in record.classification_reasons


def test_lsp_initialize_not_mcp():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": 12, "capabilities": {}},
    }
    assert classify(msg) == ("request", False)
    (record,) = carve(msg)
    assert not record.mcp


def test_shared_client_info_and_capabilities_do_not_identify_mcp():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"clientInfo": {"name": "editor"}, "capabilities": {}},
    }
    (record,) = carve(msg)
    assert not record.mcp and record.protocol_hint == "generic-json-rpc"
    assert "mcp-legacy-initialize-envelope" not in record.classification_reasons


def test_lsp_workspace_fields_and_mcp_version_conflict_is_ambiguous():
    params = {
        "protocolVersion": "2025-11-25",
        "clientInfo": {"name": "editor"},
        "capabilities": {},
        "rootUri": "file:///workspace",
        "workspaceFolders": [{"uri": "file:///workspace", "name": "workspace"}],
    }
    (record,) = carve({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})
    assert not record.mcp and record.protocol_hint == "ambiguous"
    assert set(record.classification_reasons) >= {
        "mcp-legacy-initialize-envelope",
        "lsp-workspace-params",
        "conflicting-initialize-signals",
    }
    assert relevant_records([record]) == [record]
    assert relevant_records([record], include_rpc=True) == [record]


@pytest.mark.parametrize(
    "workspace",
    [{"rootUri": None}, {"workspaceFolders": []}],
)
def test_lsp_workspace_signal_without_protocol_version(workspace):
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"clientInfo": {"name": "editor"}, "capabilities": {}, **workspace},
    }
    (record,) = carve(msg)
    assert not record.mcp and record.protocol_hint == "lsp-candidate"
    assert "lsp-workspace-params" in record.classification_reasons


def test_workspace_field_alone_is_not_lsp_verdict():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"rootUri": "file:///workspace"},
    }
    (record,) = carve(msg)
    assert record.protocol_hint == "generic-json-rpc" and not record.mcp


def test_modern_mcp_envelope_with_lsp_workspace_signal_is_ambiguous():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "rootUri": "file:///workspace",
        },
    }
    (record,) = carve(msg)
    assert not record.mcp and record.protocol_hint == "ambiguous"
    assert "mcp-versioned-meta-envelope" in record.classification_reasons
    assert "lsp-workspace-params" in record.classification_reasons


def test_content_length_frame_is_observed_without_overriding_mcp_version():
    mcp = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mcp-client"},
        },
    }
    raw = json.dumps(mcp, separators=(",", ":")).encode()
    framed = f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw
    (record,) = list(scan_chunks([(0x4000, framed)]))
    assert record.mcp and record.protocol_hint == "mcp-candidate"
    assert "content-length-frame" in record.classification_reasons


def test_lsp_content_length_frame_and_workspace_fields():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "clientInfo": {"name": "lsp-client"},
            "capabilities": {},
            "rootUri": None,
            "workspaceFolders": [],
        },
    }
    raw = json.dumps(msg, separators=(",", ":")).encode()
    framed = (
        f"Content-Length: {len(raw)}\r\nContent-Type: application/vscode-jsonrpc\r\n\r\n".encode()
        + raw
    )
    (record,) = list(scan_chunks([(0x4000, framed)]))
    assert not record.mcp and record.protocol_hint == "lsp-candidate"
    assert "lsp-workspace-params" in record.classification_reasons
    assert "content-length-frame" in record.classification_reasons
    assert not record.to_dict()["mcp_candidate"]

    wrong_length = framed.replace(f"Content-Length: {len(raw)}".encode(), b"Content-Length: 1")
    (wrong,) = list(scan_chunks([(0x4000, wrong_length)]))
    assert "content-length-frame" not in wrong.classification_reasons
    assert wrong.protocol_hint == "lsp-candidate"


def test_content_length_plus_initialize_capabilities_is_only_lsp_hint():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"clientInfo": {"name": "editor"}, "capabilities": {}},
    }
    raw = json.dumps(msg, separators=(",", ":")).encode()
    framed = f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw
    (record,) = list(scan_chunks([(0x4000, framed)]))
    assert record.protocol_hint == "lsp-candidate" and not record.mcp
    assert "initialize-capabilities-with-content-length" in record.classification_reasons

    split = len(framed) - len(raw) - 2
    (spanning,) = list(scan_chunks([(0x4000, framed[:split]), (0x4000 + split, framed[split:])]))
    assert "content-length-frame" in spanning.classification_reasons

    header = framed[: len(framed) - len(raw)]
    (separate_mapping,) = list(scan_chunks([(0x4000, header), (0x5000, raw)]))
    assert "content-length-frame" not in separate_mapping.classification_reasons


def test_modern_mcp_request():
    msg = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    (record,) = carve(msg)
    assert record.mcp and record.protocol_version == "2026-07-28"


def test_modern_response_and_methods():
    for method in ("subscriptions/listen", "tasks/update"):
        assert classify({"jsonrpc": "2.0", "id": 1, "method": method}) == ("request", True)
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {},
        },
    }
    assert classify(msg) == ("response", True)


def test_input_required_matches_official_map_shape():
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "resultType": "input_required",
            "inputRequests": {
                "github_login": {"method": "elicitation/create", "params": {"mode": "form"}}
            },
            "requestState": "opaque-state",
        },
    }
    assert classify(msg) == ("response", True)
    (record,) = carve(msg)
    assert record.mcp


def test_input_required_request_state_only_and_invalid_list():
    state_only = {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {"resultType": "input_required", "requestState": "opaque-state"},
    }
    assert classify(state_only) == ("response", True)

    incorrect_shape = {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {"resultType": "input_required", "inputRequests": []},
    }
    assert classify(incorrect_shape) == ("response", False)


def test_unrelated_metadata_not_mcp():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "other/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "bad",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    assert classify(msg) == ("request", False)


def test_anchor_free_skips_object_start_search(monkeypatch):
    class ForbiddenStartSearch:
        def finditer(self, data):
            raise AssertionError("object starts scanned without anchor")

    monkeypatch.setattr(
        core,
        "PATTERNS",
        {
            encoding: (anchor, ForbiddenStartSearch())
            for encoding, (anchor, _) in core.PATTERNS.items()
        },
    )
    assert list(scan_chunks([(0, b'{"a":1}' * 50000)])) == []
