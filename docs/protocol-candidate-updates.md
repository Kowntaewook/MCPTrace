# MCP candidate classification and anchor-free scan fast path

- Adds 2026-07-28 candidate methods and explicitly declared request-version metadata.
- Retains legacy initialization support but requires the legacy MCP parameter shape to avoid classifying generic LSP initialize requests as MCP.
- Recognizes selected new response structures.
- Skips collecting JSON object-start offsets for windows without a JSON-RPC anchor.
- Does not change process memory boundaries, backtracking limits or raw evidence preservation.

Classification is heuristic and not full MCP schema validation. A method alone cannot establish protocol version, transmission, execution, or session identity.

The optimization has not yet been measured on the original Windows RAM images. The published baseline is from older code and must not be interpreted as a benchmark for this branch. Run identical-image runtime/peak-memory benchmarks and general JSON-RPC negative controls before merging.
