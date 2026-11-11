"""Bounded carving of literal JSON-RPC artifacts, never a proof of transmission."""

from __future__ import annotations

import base64
import bisect
import hashlib
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from itertools import chain
from typing import Any

LEGACY_MCP_METHODS = frozenset(
    "initialize tools/list tools/call resources/list resources/read resources/subscribe "
    "resources/unsubscribe resources/templates/list prompts/list prompts/get "
    "completion/complete logging/setLevel sampling/createMessage roots/list elicitation/create "
    "tasks/get tasks/result tasks/list tasks/cancel notifications/initialized "
    "notifications/cancelled notifications/progress notifications/message "
    "notifications/tools/list_changed notifications/resources/list_changed "
    "notifications/resources/updated notifications/prompts/list_changed "
    "notifications/roots/list_changed notifications/elicitation/complete "
    "notifications/tasks/status".split()
)

# Keep legacy methods for analysis of older memory images. The 2026-07-28
# protocol uses stateless discovery and subscriptions; tasks are an extension.
MODERN_MCP_METHODS = frozenset(
    "server/discover subscriptions/listen tasks/update "
    "notifications/subscriptions/acknowledged notifications/tasks".split()
)
MCP_METHODS = LEGACY_MCP_METHODS | MODERN_MCP_METHODS


def _version_label(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None


def _modern_request_version(params: object) -> str:
    """Only trust the explicit version together with the capabilities envelope."""
    if not isinstance(params, dict):
        return ""
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return ""
    version = meta.get("io.modelcontextprotocol/protocolVersion")
    capabilities = meta.get("io.modelcontextprotocol/clientCapabilities")
    if _version_label(version) and isinstance(capabilities, dict):
        return version
    return ""


def _legacy_initialize(params: object) -> bool:
    # LSP also has an initialize request, but its parameters do not contain
    # the MCP protocolVersion/capabilities/clientInfo combination.
    return (
        isinstance(params, dict)
        and _version_label(params.get("protocolVersion"))
        and isinstance(params.get("capabilities"), dict)
        and isinstance(params.get("clientInfo"), dict)
    )


def _modern_response(result: object) -> bool:
    if not isinstance(result, dict):
        return False
    kind = result.get("resultType")
    if (
        kind == "complete"
        and isinstance(result.get("supportedVersions"), list)
        and bool(result["supportedVersions"])
        and all(_version_label(version) for version in result["supportedVersions"])
        and isinstance(result.get("capabilities"), dict)
    ):
        return True
    if kind == "input_required" and (
        isinstance(result.get("inputRequests"), dict) or isinstance(result.get("requestState"), str)
    ):
        return True
    meta = result.get("_meta")
    server = meta.get("io.modelcontextprotocol/serverInfo") if isinstance(meta, dict) else None
    return (
        kind in {"complete", "input_required", "task"}
        and isinstance(server, dict)
        and isinstance(server.get("name"), str)
        and isinstance(server.get("version"), str)
    )


def _patterns(encoding: str) -> tuple[re.Pattern, re.Pattern]:
    def literal(text: str) -> bytes:
        return re.escape(text.encode(encoding))

    space = rb"[ \t\r\n]*" if encoding == "utf-8" else rb"(?:[ \t\r\n]\x00)*"
    anchor = literal('"jsonrpc"') + space + literal(":") + space + literal('"2.0"')
    start = literal("{") + space + literal('"')
    return re.compile(anchor), re.compile(start)


PATTERNS = {encoding: _patterns(encoding) for encoding in ("utf-8", "utf-16-le")}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-JSON number: {value}")


def strict_loads(text: str) -> Any:
    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("JSON number is outside the supported finite float range")
        return number

    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=finite_float,
    )


def _valid_id(value: Any) -> bool:
    # bool is an int subclass, but not a JSON-RPC request identifier.
    return type(value) in (str, int)


def _lsp_workspace_params(params: object) -> bool:
    if not isinstance(params, dict):
        return False
    meta = params.get("_meta")
    has_capabilities = isinstance(params.get("capabilities"), dict) or (
        isinstance(meta, dict)
        and isinstance(meta.get("io.modelcontextprotocol/clientCapabilities"), dict)
    )
    if not has_capabilities:
        return False
    root = "rootUri" in params and (params["rootUri"] is None or isinstance(params["rootUri"], str))
    folders = "workspaceFolders" in params and (
        params["workspaceFolders"] is None or isinstance(params["workspaceFolders"], list)
    )
    return root or folders


@dataclass(frozen=True)
class Classification:
    kind: str
    mcp: bool
    protocol_hint: str
    reasons: tuple[str, ...]


def classify_with_evidence(
    obj: Any, *, content_length_frame: bool = False
) -> Classification | None:
    if not isinstance(obj, dict) or obj.get("jsonrpc") != "2.0":
        return None
    reasons = ["jsonrpc-2.0"]
    if content_length_frame:
        reasons.append("content-length-frame")
    if "method" in obj:
        if not isinstance(obj["method"], str) or "result" in obj or "error" in obj:
            return None
        if "params" in obj and not isinstance(obj["params"], (dict, list)):
            return None
        if "id" in obj and not _valid_id(obj["id"]):
            return None
        kind = "request" if "id" in obj else "notification"
        params = obj.get("params")
        method = obj["method"]
        if method == "initialize":
            legacy = _legacy_initialize(params)
            modern = bool(_modern_request_version(params))
            workspace = _lsp_workspace_params(params)
            if legacy:
                reasons.append("mcp-legacy-initialize-envelope")
            if modern:
                reasons.append("mcp-versioned-meta-envelope")
            if workspace:
                reasons.append("lsp-workspace-params")
            if (legacy or modern) and workspace:
                reasons.append("conflicting-initialize-signals")
                return Classification(kind, False, "ambiguous", tuple(reasons))
            if legacy or modern:
                return Classification(kind, True, "mcp-candidate", tuple(reasons))
            # The framing alone is not proof of LSP: HTTP and nonstandard
            # clients may also leave Content-Length headers in memory.
            framed_initialize = (
                content_length_frame
                and isinstance(params, dict)
                and isinstance(params.get("capabilities"), dict)
            )
            if framed_initialize:
                reasons.append("initialize-capabilities-with-content-length")
            if workspace or framed_initialize:
                return Classification(kind, False, "lsp-candidate", tuple(reasons))
            return Classification(kind, False, "generic-json-rpc", tuple(reasons))
        known_method = method in MCP_METHODS
        modern = bool(_modern_request_version(params))
        if known_method:
            reasons.append("known-mcp-method")
        if modern:
            reasons.append("mcp-versioned-meta-envelope")
        mcp = known_method or modern
        return Classification(
            kind, mcp, "mcp-candidate" if mcp else "generic-json-rpc", tuple(reasons)
        )
    if ("result" in obj) == ("error" in obj):
        return None
    if "id" not in obj or not (_valid_id(obj["id"]) or obj["id"] is None):
        return None
    if "error" in obj:
        error = obj["error"]
        if not isinstance(error, dict):
            return None
        if type(error.get("code")) is not int or not isinstance(error.get("message"), str):
            return None
    result = obj.get("result")
    mcp_shape = isinstance(result, dict) and any(
        isinstance(result.get(key), list) for key in ("tools", "content", "resources", "prompts")
    )
    modern_shape = _modern_response(result)
    if mcp_shape:
        reasons.append("mcp-response-list-shape")
    if modern_shape:
        reasons.append("mcp-modern-response-shape")
    mcp = mcp_shape or modern_shape
    return Classification(
        "response", mcp, "mcp-candidate" if mcp else "generic-json-rpc", tuple(reasons)
    )


def classify(obj: Any) -> tuple[str, bool] | None:
    """Compatibility helper for callers that only need request kind and MCP candidacy."""
    classification = classify_with_evidence(obj)
    return (classification.kind, classification.mcp) if classification else None


@dataclass
class Artifact:
    address: int
    encoding: str
    raw: bytes
    state: str
    kind: str
    obj: dict | None = None
    mcp: bool = False
    protocol_hint: str = "unclassified"
    classification_reasons: tuple[str, ...] = ()
    pid: int = 0
    region_start: int = 0
    region_kind: str = ""
    target_os: str = ""
    relation: str = "not-applicable"
    candidate_addresses: list[int] = field(default_factory=list)
    candidate_count: int = 0
    findings: list[dict] = field(default_factory=list)

    @property
    def method(self) -> str:
        return (self.obj or {}).get("method", "")

    @property
    def request_id(self) -> str | int | None:
        return (self.obj or {}).get("id")

    @property
    def tool(self) -> str:
        params = (self.obj or {}).get("params")
        if self.method == "tools/call" and isinstance(params, dict):
            name = params.get("name")
            return name if isinstance(name, str) else ""
        return ""

    @property
    def protocol_version(self) -> str:
        """Explicitly declared version; never infer it from the method name."""
        params = (self.obj or {}).get("params")
        modern = _modern_request_version(params)
        if modern:
            return modern
        if self.method == "initialize" and _legacy_initialize(params):
            return params["protocolVersion"]
        return ""

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()

    def to_dict(self) -> dict:
        result = {
            "pid": self.pid,
            "target_os": self.target_os,
            "region_start": self.region_start,
            "region_kind": self.region_kind,
            "virtual_address": self.address,
            "encoding": self.encoding,
            "state": self.state,
            "kind": self.kind,
            "mcp_candidate": self.mcp,
            "protocol_hint": self.protocol_hint,
            "classification_reasons": list(self.classification_reasons),
            "declared_protocol_version": self.protocol_version,
            "request_id": self.request_id,
            "method": self.method,
            "tool": self.tool,
            "message": self.obj,
            "raw_base64": base64.b64encode(self.raw).decode("ascii"),
            "raw_sha256": self.sha256,
            "byte_length": len(self.raw),
            "relation": self.relation,
            "candidate_virtual_addresses": self.candidate_addresses,
            "candidate_address_count": self.candidate_count,
            "candidate_addresses_truncated": self.candidate_count > len(self.candidate_addresses),
            "findings": self.findings,
        }
        if self.region_kind in {"vad", "vma"}:
            # Preserve the Windows JSONL field; Linux must not claim a VAD address.
            result[f"{self.region_kind}_start"] = self.region_start
        return result


@dataclass
class ScanStats:
    bytes_read: int = 0
    unreadable_bytes: int = 0
    anchor_limit_hits: int = 0
    candidate_limit_hits: int = 0
    regions_scanned: int = 0
    invalid_regions: int = 0


def _object_end(data: bytes, start: int, step: int, limit: int) -> int | None:
    """Respect quoted braces, escapes, arrays and a bounded nesting depth."""
    stack: list[int] = []
    quoted = escaped = False
    for pos in range(start, min(len(data), start + limit) - step + 1, step):
        char = data[pos] if step == 1 else int.from_bytes(data[pos : pos + 2], "little")
        if char == 0:
            return None
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
            continue
        if char == 34:
            quoted = True
        elif char in (123, 91):
            stack.append(char)
            if len(stack) > 128:
                return None
        elif char in (125, 93):
            if not stack or stack.pop() != {125: 123, 93: 91}[char]:
                return None
            if not stack:
                return pos + step
    return None


CONTENT_LENGTH_HEADER = re.compile(
    rb"(?:Content-Type: [^\r\n]{1,128}\r\n)?"
    rb"Content-Length: ([0-9]+)\r\n"
    rb"(?:Content-Type: [^\r\n]{1,128}\r\n)?\r\n$",
    re.IGNORECASE,
)


def _content_length_frame(data: bytes, start: int, length: int) -> bool:
    # Only report a header directly before the recovered bytes and agreeing
    # with their exact byte count. Do not infer a transport from this alone.
    header = data[max(0, start - 512) : start]
    match = CONTENT_LENGTH_HEADER.search(header)
    return bool(match and int(match.group(1)) == length)


def _carve_buffer(
    data: bytes, base: int, maximum: int, partial: bool, stats: ScanStats
) -> Iterator[Artifact]:
    for encoding, (anchors, starts_pattern) in PATTERNS.items():
        step = 1 if encoding == "utf-8" else 2
        anchor_matches = anchors.finditer(data)
        first_match = next(anchor_matches, None)
        if first_match is None:
            # Typical memory windows have no JSON-RPC anchor. Avoid collecting
            # thousands of unrelated object starts in those windows.
            continue
        starts = [m.start() for m in starts_pattern.finditer(data)]
        parsed: dict[int, Artifact | None] = {}
        complete: dict[int, Artifact] = {}
        unmatched: list[int] = []
        for count, match in enumerate(chain((first_match,), anchor_matches)):
            if count >= 20000:
                stats.anchor_limit_hits += 1
                break
            anchor = match.start()
            low = bisect.bisect_left(starts, max(0, anchor - maximum + 1))
            high = bisect.bisect_right(starts, anchor)
            limited = high - low > 64
            if limited:
                low = high - 64
            found = False
            for index in range(high - 1, low - 1, -1):
                start = starts[index]
                if (anchor - start) % step:
                    continue
                if start not in parsed:
                    parsed[start] = None
                    end = _object_end(data, start, step, maximum)
                    if end is not None and end > anchor:
                        raw = data[start:end]
                        try:
                            obj = strict_loads(raw.decode(encoding, errors="strict"))
                            classification = classify_with_evidence(
                                obj,
                                content_length_frame=_content_length_frame(data, start, len(raw)),
                            )
                        except (ValueError, UnicodeError, RecursionError):
                            classification = None
                        if classification:
                            parsed[start] = Artifact(
                                base + start,
                                encoding,
                                raw,
                                "complete",
                                classification.kind,
                                obj,
                                classification.mcp,
                                classification.protocol_hint,
                                classification.reasons,
                            )
                record = parsed[start]
                if record and record.address + len(record.raw) > base + anchor:
                    complete[start] = record
                    found = True
                    break
            if not found:
                if limited:
                    stats.candidate_limit_hits += 1
                unmatched.append(anchor)
        yield from complete.values()
        if partial:
            ranges = sorted((start, start + len(rec.raw)) for start, rec in complete.items())
            range_starts = [start for start, _ in ranges]
            for anchor in unmatched:
                index = bisect.bisect_right(range_starts, anchor) - 1
                if index >= 0 and anchor < ranges[index][1]:
                    continue
                end = min(len(data), anchor + min(maximum, 512))
                end -= (end - anchor) % step
                for pos in range(anchor, end, step):
                    if data[pos : pos + step] == b"\0" * step:
                        end = pos
                        break
                raw = data[anchor:end]
                if raw:
                    # Raw fragment only: no guessed ID, arguments, or repaired JSON.
                    yield Artifact(
                        base + anchor,
                        encoding,
                        raw,
                        "fragment",
                        "fragment",
                        protocol_hint="fragment",
                    )


def scan_chunks(
    chunks: Iterable[tuple[int, bytes]],
    *,
    max_object_bytes: int = 65536,
    include_partial: bool = False,
    stats: ScanStats | None = None,
) -> Iterator[Artifact]:
    """Carve contiguous virtual bytes, flushing at gaps and mapping boundaries.

    Keep two windows so a late jsonrpc member and a chunk-spanning object survive.
    No bytes are invented for unreadable pages. Addresses are process virtual addresses.
    """
    if not 256 <= max_object_bytes <= 4 * 1024 * 1024:
        raise ValueError("max_object_bytes must be between 256 and 4194304")
    stats = stats if stats is not None else ScanStats()
    pending = b""
    base = 0
    seen: set[tuple[int, str]] = set()

    def emit(final: bool) -> Iterator[Artifact]:
        safe_end = base + len(pending) if final else base + len(pending) - max_object_bytes
        for record in _carve_buffer(pending, base, max_object_bytes, include_partial, stats):
            key = record.address, record.encoding
            if record.address < safe_end and key not in seen:
                seen.add(key)
                yield record

    for address, data in chunks:
        if not data:
            continue
        if pending and address != base + len(pending):
            yield from emit(True)
            pending = b""
        if not pending:
            base = address
        pending += data
        yield from emit(False)
        keep = 2 * max_object_bytes
        if len(pending) > keep:
            base += len(pending) - keep
            pending = pending[-keep:]
    if pending:
        yield from emit(True)


def correlate(records: list[Artifact]) -> None:
    """ID matches are candidates, never inferred sessions or verified executions."""
    groups: dict[tuple, list[Artifact]] = defaultdict(list)
    for record in records:
        record.candidate_addresses = []
        record.candidate_count = 0
        if record.state != "complete" or record.request_id is None:
            record.relation = "not-applicable"
            continue
        groups[(record.pid, type(record.request_id), record.request_id)].append(record)
    for group in groups.values():
        requests = [r for r in group if r.kind == "request"]
        responses = [r for r in group if r.kind == "response"]

        def identities(items: list[Artifact]) -> set[str]:
            # Do not collapse distinct numeric lexemes through float rounding.
            # Different JSON formatting is conservatively considered ambiguous.
            return {r.raw.decode(r.encoding) for r in items}

        ambiguous = len(identities(requests)) > 1 or len(identities(responses)) > 1
        request_addresses = sorted({r.address for r in requests})
        response_addresses = sorted({r.address for r in responses})
        for record in group:
            opposite = response_addresses if record.kind == "request" else request_addresses
            record.candidate_count = len(opposite)
            # Bound repeated address lists; the individual artifacts are retained.
            record.candidate_addresses = opposite[:256]
            record.relation = (
                "ambiguous-id" if ambiguous else "candidate-only" if opposite else "unpaired"
            )


def relevant_records(records: list[Artifact], include_rpc: bool = False) -> list[Artifact]:
    """Retain generic responses only when MCP-shaped or sharing a process/typed ID."""
    ids = {
        (r.pid, type(r.request_id), r.request_id)
        for r in records
        if r.mcp and r.kind == "request" and r.request_id is not None
    }
    return [
        r
        for r in records
        if include_rpc
        or r.mcp
        or r.protocol_hint == "ambiguous"
        or r.state == "fragment"
        or (r.kind == "response" and (r.pid, type(r.request_id), r.request_id) in ids)
    ]
