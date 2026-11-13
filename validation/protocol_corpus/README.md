# Paired protocol controls

Run from the repository root:

```sh
python3 validation/protocol_corpus/run.py \
  --baseline v0.3.0 --current HEAD \
  --report /tmp/mcptrace-protocol-comparison.json
```

The runner loads `mcptrace/core.py` at both revisions and scans the exact same
constructed byte buffers. It records the SHA-256 of each buffer, MCP-candidate
flag, and (where available) protocol hint. The cases include UTF-16LE, SSE,
Content-Length, LSP workspace fields, conflicting initialize signals, generic
JSON-RPC, an invalid ID, an unsent MCP-shaped object, and an unrelated response
with a `tools` list. The last two controls demonstrate that a memory candidate
does not prove transmission or protocol origin.

This is a small regression corpus. Its case counts are not precision, recall,
or throughput estimates for real process or physical memory. The stored result
is in [results/2026-11-13-v030-vs-main.json](results/2026-11-13-v030-vs-main.json).
