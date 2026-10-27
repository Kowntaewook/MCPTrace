"""Explicit analyst policy checks on complete tools/call arguments only."""

from __future__ import annotations

import ntpath
import re
from urllib.parse import urlsplit

from mcptrace.core import Artifact

OPERATORS = {"equals", "contains", "url_host_not_in", "windows_path_outside"}


def validate_policy(document: object) -> list[dict]:
    if (
        not isinstance(document, dict)
        or type(document.get("version")) is not int
        or document["version"] != 1
        or set(document) != {"version", "rules"}
    ):
        raise ValueError("Policy must be an object with version 1")
    rules = document.get("rules")
    if not isinstance(rules, list) or len(rules) > 100:
        raise ValueError("Policy rules must be an array of at most 100 entries")
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Each rule must be an object")
        if set(rule) - {"id", "description", "severity", "tool", "argument", "operator", "value"}:
            raise ValueError("Unknown rule field")
        for key in ("id", "description", "tool", "argument", "operator", "severity"):
            if not isinstance(rule.get(key), str) or not rule[key]:
                raise ValueError(f"Rule requires a nonempty {key}")
        if rule["id"] in seen:
            raise ValueError("Duplicate rule ID")
        seen.add(rule["id"])
        if rule["severity"] not in {"low", "medium", "high"}:
            raise ValueError("Severity must be low, medium, or high")
        if (
            not rule["argument"].startswith("/")
            or re.search(r"~(?![01])", rule["argument"])
            or rule["operator"] not in OPERATORS
        ):
            raise ValueError("Invalid argument JSON pointer or operator")
        value = rule.get("value")
        if rule["operator"] in {"equals", "contains"}:
            if not isinstance(value, str) or not value:
                raise ValueError("String operators require a nonempty string value")
        else:
            if (
                not isinstance(value, list)
                or not value
                or any(not isinstance(v, str) or not v for v in value)
            ):
                raise ValueError("Allowlist operators require a nonempty string array")
            if rule["operator"] == "windows_path_outside" and any(
                _absolute_windows(v) is None for v in value
            ):
                raise ValueError("Allowed Windows paths must be absolute, without variables")
            if rule["operator"] == "url_host_not_in" and any(_host(v) is None for v in value):
                raise ValueError("Allowed URL hosts must be host names, without ports or wildcards")
    return rules


def _pointer(obj: object, pointer: str) -> object:
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(obj, dict):
            obj = obj[token]
        elif isinstance(obj, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            obj = obj[int(token)]
        else:
            raise KeyError(pointer)
    return obj


def _host(value: str) -> str | None:
    if not value or any(c in value for c in "/:@* \\?#") or any(ord(c) < 33 for c in value):
        return None
    try:
        return value.rstrip(".").encode("idna").decode("ascii").lower() or None
    except UnicodeError:
        return None


def _absolute_windows(value: str) -> str | None:
    value = value.replace("/", "\\")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    if any(ord(c) < 32 for c in value) or "%" in value or "$" in value:
        return None
    if value.startswith("\\\\.\\"):
        return None
    drive, tail = ntpath.splitdrive(value)
    if not drive or not tail.startswith("\\"):
        return None
    if not re.fullmatch(r"[a-zA-Z]:", drive) and not re.fullmatch(r"\\\\[^\\]+\\[^\\]+", drive):
        return None
    # Alternate streams, wildcards, and Win32-trimmed components need filesystem
    # semantics we cannot recover here. Do not silently classify these as allowed.
    if any(c in tail for c in ':*?"<>|'):
        return None
    if any(part not in {"", ".", ".."} and part.endswith((".", " ")) for part in tail.split("\\")):
        return None
    return ntpath.normcase(ntpath.normpath(value))


def _check(value: str, rule: dict) -> bool | None:
    operator, expected = rule["operator"], rule["value"]
    if operator == "equals":
        return value == expected
    if operator == "contains":
        return expected in value
    if operator == "url_host_not_in":
        try:
            if any(ord(c) < 33 for c in value):
                return None
            parsed = urlsplit(value)
            host = _host(parsed.hostname or "")
            if parsed.scheme.lower() not in {"http", "https"} or host is None:
                return None
            return host not in {_host(v) for v in expected}
        except ValueError:
            return None
    path = _absolute_windows(value)
    if path is None:
        return None
    for allowed in expected:
        root = _absolute_windows(allowed)
        try:
            if root is not None and ntpath.commonpath([path, root]) == root:
                return False
        except ValueError:  # Different drives.
            pass
    return True


def evaluate(record: Artifact, rules: list[dict]) -> list[dict]:
    if record.state != "complete" or record.method != "tools/call":
        return []
    params = (record.obj or {}).get("params")
    arguments = params.get("arguments") if isinstance(params, dict) else None
    findings = []
    for rule in rules:
        if rule["tool"] != record.tool:
            continue
        try:
            value = _pointer(arguments, rule["argument"])
            matched = _check(value, rule) if isinstance(value, str) else None
        except (KeyError, IndexError):
            matched = None
        if matched is not False:
            findings.append(
                {
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "status": "policy-match" if matched else "not-evaluated",
                    "argument": rule["argument"],
                    "description": rule["description"],
                }
            )
    return findings
