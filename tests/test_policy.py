import copy

import pytest
from test_core import carve, request

from mcptrace.policy import evaluate, validate_policy


def rule(operator, value, argument="/path"):
    return {
        "id": "R1",
        "description": "Analyst-defined policy",
        "severity": "medium",
        "tool": "read_file",
        "argument": argument,
        "operator": operator,
        "value": value,
    }


def run_rule(value, operator="windows_path_outside", expected=None):
    spec = rule(operator, expected if expected is not None else [r"C:\Cases"])
    rules = validate_policy({"version": 1, "rules": [spec]})
    return evaluate(carve(request(tool="read_file", arguments={"path": value})), rules)


@pytest.mark.parametrize(
    "value",
    [r"C:\Cases\evidence.txt", r"c:\CASES\sub\a.txt", r"C:/Cases/a.txt", r"\\?\C:\Cases\a.txt"],
)
def test_allowed_path_boundaries(value):
    assert run_rule(value) == []


@pytest.mark.parametrize("value", [r"C:\Cases2\a.txt", r"C:\Cases\..\secret.txt", r"D:\Cases\a"])
def test_outside_paths_match(value):
    assert run_rule(value)[0]["status"] == "policy-match"


@pytest.mark.parametrize(
    "value",
    [
        r"C:relative.txt",
        r"\rooted.txt",
        r"%USERPROFILE%\a",
        3,
        None,
        r"C:\Cases\a.txt:secret",
        r"C:\Cases\a. ",
        r"C:\Cases\*.txt",
    ],
)
def test_unresolved_inputs_are_not_marked_safe(value):
    assert run_rule(value)[0]["status"] == "not-evaluated"


@pytest.mark.parametrize(
    "url,matched",
    [
        ("https://API.EXAMPLE.TEST./x", False),
        ("https://api.example.test.evil.test/x", True),
        ("https://api.example.test@evil.test/x", True),
        ("https://evil.test/?allowed=api.example.test", True),
        ("https://api.example.test:443/path", False),
    ],
)
def test_url_host_uses_parsed_authority(url, matched):
    findings = run_rule(url, "url_host_not_in", ["api.example.test"])
    assert bool(findings) == matched


def test_policy_requires_exact_tool_and_complete_request():
    rules = validate_policy({"version": 1, "rules": [rule("contains", "secret")]})
    assert evaluate(carve(request(tool="another_tool", arguments={"path": "secret"})), rules) == []
    record = carve(request(tool="read_file", arguments={"path": "secret"}))
    assert evaluate(record, rules)[0]["status"] == "policy-match"
    record.state = "fragment"
    assert evaluate(record, rules) == []


def test_json_pointer_and_missing_arguments():
    spec = rule("equals", "secret", "/nested/a~1b/0")
    rules = validate_policy({"version": 1, "rules": [spec]})
    rec = carve(request(tool="read_file", arguments={"nested": {"a/b": ["secret"]}}))
    assert evaluate(rec, rules)[0]["status"] == "policy-match"
    rec.obj["params"]["arguments"] = {}
    assert evaluate(rec, rules)[0]["status"] == "not-evaluated"


@pytest.mark.parametrize(
    "change",
    [
        {"operator": "execute"},
        {"severity": "critical"},
        {"extra": "ignored?"},
        {"argument": "path"},
        {"value": []},
        {"value": ["relative"]},
        {"argument": "/bad~2pointer"},
    ],
)
def test_bad_policy_is_rejected(change):
    spec = rule("windows_path_outside", [r"C:\Cases"])
    spec.update(change)
    with pytest.raises(ValueError):
        validate_policy({"version": 1, "rules": [spec]})


def test_duplicate_rule_ids_rejected():
    spec = rule("contains", "x")
    with pytest.raises(ValueError):
        validate_policy({"version": 1, "rules": [spec, copy.deepcopy(spec)]})


@pytest.mark.parametrize(
    "value,matched",
    [
        ("/srv/cases/a.txt", False),
        ("/srv/cases", False),
        ("/srv/cases/", False),
        ("/srv/cases/./a", False),
        ("/srv/cases/sub/../a", False),
        ("/srv/cases2/a", True),
        ("/srv/cases/../secret", True),
        ("/etc/shadow", True),
        ("/SRV/CASES/a", True),
        (r"/srv/cases\..\secret", True),
        (r"/srv/cases/a\b", False),
    ],
)
def test_posix_path_semantics_are_independent_of_analysis_host(value, matched):
    findings = run_rule(value, "posix_path_outside", ["/srv/cases"])
    assert bool(findings) == matched
    if matched:
        assert findings[0]["status"] == "policy-match"


@pytest.mark.parametrize(
    "value",
    [
        "relative",
        "~/cases/a",
        "$HOME/a",
        "/srv/$CASE/a",
        "//server/share",
        "/srv/cases/*.txt",
        "/srv/cases/a\0b",
    ],
)
def test_unresolved_posix_paths_are_not_evaluated(value):
    assert run_rule(value, "posix_path_outside", ["/srv/cases"])[0]["status"] == "not-evaluated"


@pytest.mark.parametrize("root", ["cases", "~/cases", "//server/share", "/$HOME", "/srv/*"])
def test_invalid_posix_allowlist_is_rejected(root):
    with pytest.raises(ValueError, match="POSIX"):
        validate_policy({"version": 1, "rules": [rule("posix_path_outside", [root])]})


def test_posix_root_and_multiple_allowed_roots():
    assert run_rule("/etc/shadow", "posix_path_outside", ["/"]) == []
    assert run_rule("/tmp/cases/a", "posix_path_outside", ["/srv/cases", "/tmp/cases"]) == []
