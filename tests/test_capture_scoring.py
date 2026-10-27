"""Ground-truth metrics must distinguish messages, copies, controls, and PIDs."""

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "capture_score", Path(__file__).resolve().parents[1] / "validation/windows_positive/score.py"
)
scoring = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scoring)

REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo_marker"}}
RESPONSE = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
TRUTH = [{"message": REQUEST}, {"message": RESPONSE}]
METADATA = {"client_pid": 10, "server_pid": 20, "mode": "natural"}


def artifact(message, address, pid=10, candidates=()):
    return {
        "pid": pid,
        "state": "complete",
        "message": message,
        "virtual_address": address,
        "candidate_virtual_addresses": list(candidates),
        "relation": "candidate-only" if candidates else "unpaired",
    }


def test_copies_do_not_inflate_logical_coverage():
    records = [artifact(REQUEST, 1), artifact(REQUEST, 2), artifact(RESPONSE, 3)]
    score = scoring.score_case(METADATA, TRUTH, records)
    assert score["artifact_records"] == 3
    assert score["distinct_expected_messages_found"] == 2
    assert score["logical_message_coverage"] == 1
    assert score["positive_pair_in_one_pid"]


def test_unsent_control_is_not_counted_as_traffic():
    decoy = {**REQUEST, "id": 900001}
    score = scoring.score_case(METADATA, TRUTH, [artifact(decoy, 1)], [decoy])
    assert score["distinct_expected_messages_found"] == 0
    assert score["records_matching_unsent_controls"] == 1
    assert score["record_match_fraction"] == 0
    assert not score["positive_pair_in_one_pid"]


def test_other_process_and_cross_endpoint_pair_are_separate():
    records = [artifact(REQUEST, 1), artifact(RESPONSE, 2, pid=20), artifact(RESPONSE, 3, pid=99)]
    score = scoring.score_case(METADATA, TRUTH, records)
    assert score["artifact_records"] == 2
    assert score["complete_tool_pairs_any_endpoint"] == 1
    assert not score["positive_pair_in_one_pid"]


def test_candidate_link_scoring_keeps_typed_ids():
    text_request, text_response = {**REQUEST, "id": "1"}, {**RESPONSE, "id": "1"}
    truth = [*TRUTH, {"message": text_request}, {"message": text_response}]
    records = [
        artifact(REQUEST, 1, candidates=[2, 3, 9]),
        artifact(RESPONSE, 2),
        artifact(text_response, 3),
    ]
    score = scoring.score_case(METADATA, truth, records)
    assert score["evaluated_candidate_links"] == 2
    assert score["incorrect_candidate_links"] == 1
    assert score["unverifiable_candidate_links"] == 1


def test_repeated_ground_truth_events_require_explicit_alignment():
    with pytest.raises(ValueError, match="distinct logical messages"):
        scoring.score_case(METADATA, [*TRUTH, {"message": REQUEST}], [])
