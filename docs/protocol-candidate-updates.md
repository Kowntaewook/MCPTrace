# MCP candidate classification and anchor-free scan fast path

- Adds 2026-07-28 candidate methods and explicitly declared request-version metadata.
- Retains legacy initialization support but requires the legacy MCP parameter shape to avoid classifying generic LSP initialize requests as MCP.
- Recognizes selected new response structures.
- Skips collecting JSON object-start offsets for windows without a JSON-RPC anchor.
- Does not change process memory boundaries, backtracking limits or raw evidence preservation.

Classification is heuristic and not full MCP schema validation. A method alone cannot establish protocol version, transmission, execution, or session identity.

## MCP/LSP evidence in the next update

`initialize` is shared by MCP and LSP. `clientInfo` and `capabilities` are
shared too, so the legacy MCP hint requires a date-shaped `protocolVersion`
alongside them. LSP `rootUri` or `workspaceFolders` together with
`initialize` and a capabilities object is a separate workspace
signal. When a recovered `initialize` object has both the MCP version envelope
and LSP workspace fields, its `protocol_hint` is `ambiguous` and it is not
counted as an MCP candidate. A matching `Content-Length` frame is recorded
only when its declared byte length equals the exact recovered JSON bytes.
Framing is supporting context, not a protocol verdict by itself.
These choices follow the [LSP 3.18 initialize fields](https://github.com/microsoft/language-server-protocol/blob/gh-pages/_specifications/lsp/3.18/general/initialize.md),
the [LSP framing definition](https://github.com/microsoft/language-server-protocol/blob/gh-pages/_specifications/lsp/3.18/specification.md),
and the [MCP stdio transport definition](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/stdio.mdx).

TreeGrid adds `ProtocolHint` and `ClassificationReasons`; JSONL adds
`protocol_hint` and `classification_reasons`. Reasons are observed structural
signals, not a confidence score. Ambiguous objects remain visible by default;
LSP and generic JSON-RPC objects are visible with `--include-rpc`.
Unpaired response objects cannot inherit a
protocol label solely from a matching numeric request ID.

Regression cases cover shared `initialize` fields, LSP workspace fields,
conflicting envelopes, matching and incorrect Content-Length headers, and
MCP-shaped content behind a Content-Length header. The historical v0.3.0 RAM
reports remain measurements of the released classifier; they are not rerun
measurements of this change.

The earlier scan optimization was measured in the
[v0.3.0 Windows RAM comparison](windows-memory-benchmark.md). This new
classification change has not been rerun on those physical RAM images. The
local process-memory controls and unit tests above do not establish a
Windows RAM recovery rate or scanner runtime for this change.
Two further paused Linux process-memory snapshots with the current classifier
and an independent exact-wire probe are documented in the
[cross-runtime validation report](cross-runtime-memory-validation.md).
