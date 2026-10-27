import base64
import hashlib
import json

import pytest

from mcptrace.core import ScanStats, classify, correlate, relevant_records, scan_chunks


def request(rid=1, text="hello", tool="echo", arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments if arguments is not None else {"text": text},
        },
    }


def encode(obj, encoding="utf-8"):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(encoding)


def carve(obj, **kwargs):
    return list(scan_chunks([(0x1000, encode(obj))], **kwargs))[0]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
@pytest.mark.parametrize(
    "text", ["normal", "unbalanced }", "unbalanced {", 'quote \\" and }', "한글😀"]
)
def test_intact_message_and_exact_provenance(encoding, text):
    obj = request(text=text)
    raw = encode(obj, encoding)
    records = list(scan_chunks([(0x1001, b"xyz" + raw + b"\0" * 8)]))
    assert len(records) == 1
    record = records[0]
    assert record.address == 0x1004
    assert record.obj == obj and record.encoding == encoding
    assert record.raw == raw and record.sha256 == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(record.to_dict()["raw_base64"]) == raw


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_last_jsonrpc_member_and_every_chunk_boundary(encoding):
    obj = {
        "params": {"name": "echo", "arguments": {"a": {"b": "} { 한글"}}},
        "method": "tools/call",
        "id": 7,
        "jsonrpc": "2.0",
    }
    raw = encode(obj, encoding)
    for split in range(1, len(raw)):
        records = list(scan_chunks([(123, raw[:split]), (123 + split, raw[split:])]))
        assert len(records) == 1 and records[0].obj == obj


def test_large_stream_overlap_keeps_one_record_per_address():
    raw = encode(request())
    data = b"\0" * 500 + raw + b"\0" * 2000 + raw + b"\0" * 600
    records = list(
        scan_chunks(
            ((i, data[i : i + 128]) for i in range(0, len(data), 128)), max_object_bytes=256
        )
    )
    assert [r.address for r in records] == [500, 500 + len(raw) + 2000]


def test_gap_is_not_filled_or_joined():
    raw = encode(request(text="x" * 100))
    chunks = [(0x1000, raw[:80]), (0x3000, raw[80:])]
    records = list(scan_chunks(chunks, include_partial=True))
    assert records and all(r.state == "fragment" for r in records)
    assert all(r.obj is None and r.request_id is None and not r.tool for r in records)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","id":2}',
        b'{"jsonrpc":"2.0","id":true,"method":"tools/list"}',
        b'{"jsonrpc":"2.0","id":1.5,"method":"tools/list"}',
        b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":NaN}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":1e999}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":"\xff"}}',
    ],
)
def test_malformed_data_not_silently_repaired(raw):
    assert list(scan_chunks([(0, raw)])) == []
    fragments = list(scan_chunks([(0, raw)], include_partial=True))
    assert fragments and all(r.state == "fragment" and r.obj is None for r in fragments)


def test_plain_text_mentions_and_non_rpc_json_do_not_count():
    assert list(scan_chunks([(0, b'tools/call jsonrpc {"method":"tools/call"}')])) == []


def test_notifications_and_errors():
    assert carve({"jsonrpc": "2.0", "method": "notifications/initialized"}).kind == "notification"
    response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}}
    assert carve(response).kind == "response"
    assert classify({"jsonrpc": "2.0", "id": 1, "error": {"code": True, "message": "x"}}) is None


def test_pid_and_id_type_boundaries():
    req = carve(request(1))
    other_pid = carve({"jsonrpc": "2.0", "id": 1, "result": {}})
    other_pid.pid = 2
    string_id = carve({"jsonrpc": "2.0", "id": "1", "result": {}})
    records = [req, other_pid, string_id]
    correlate(records)
    assert all(r.relation == "unpaired" for r in records)
    assert relevant_records(records) == [req]


def test_pair_is_only_a_candidate_and_copies_keep_addresses():
    req, duplicate = carve(request()), carve(request())
    duplicate.address += 500
    response = carve({"jsonrpc": "2.0", "id": 1, "result": {}})
    response.address += 1000
    records = [req, duplicate, response]
    correlate(records)
    assert all(r.relation == "candidate-only" for r in records)
    assert response.candidate_addresses == [req.address, duplicate.address]
    assert len(relevant_records(records)) == 3


def test_id_collision_is_ambiguous_without_inventing_session():
    records = [
        carve(request(text="session A")),
        carve(request(text="session B")),
        carve({"jsonrpc": "2.0", "id": 1, "result": {}}),
    ]
    correlate(records)
    assert all(r.relation == "ambiguous-id" for r in records)
    assert all("session" not in r.to_dict() for r in records)


def test_same_json_in_two_encodings_preserves_both_locations():
    obj = request()
    first = encode(obj)
    records = list(scan_chunks([(0, first + b"\0" * 8 + encode(obj, "utf-16-le"))]))
    assert len(records) == 2
    assert {r.encoding for r in records} == {"utf-8", "utf-16-le"}
    assert records[0].address != records[1].address


def test_oversized_messages_are_not_complete():
    records = list(
        scan_chunks(
            [(0, encode(request(text="x" * 400)))], max_object_bytes=256, include_partial=True
        )
    )
    assert records and all(r.state == "fragment" for r in records)


def test_backtrack_limit_is_observable():
    obj = {
        "params": {"x": [{"v": i} for i in range(70)]},
        "method": "tools/list",
        "id": 1,
        "jsonrpc": "2.0",
    }
    stats = ScanStats()
    list(scan_chunks([(0, encode(obj))], stats=stats))
    assert stats.candidate_limit_hits > 0


def test_candidate_addresses_are_bounded_without_dropping_artifacts():
    req = carve(request())
    responses = [carve({"jsonrpc": "2.0", "id": 1, "result": {}}) for _ in range(300)]
    for i, response in enumerate(responses):
        response.address += i * 100
    records = [req, *responses]
    correlate(records)
    assert len(relevant_records(records)) == 301
    assert len(req.candidate_addresses) == 256 and req.candidate_count == 300
    assert req.to_dict()["candidate_addresses_truncated"] is True


def test_distinct_numeric_lexemes_are_not_collapsed_by_float_rounding():
    template = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"value":%s}}'
    data = template % b"1.00000000000000001" + b"\0" + template % b"1.00000000000000002"
    records = list(scan_chunks([(0, data)]))
    correlate(records)
    assert len(records) == 2
    assert all(r.relation == "ambiguous-id" for r in records)
