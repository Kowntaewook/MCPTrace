# Node, .NET, HTTP/SSE process-memory validation (2026-11-11)

## Setup

MCPTrace v0.3.0 (`7d364af`) was tested locally on Ubuntu 24.04 ARM64 (Linux
6.8.0-147-generic) with Node 22.14.0, TypeScript MCP SDK 1.32.1, .NET SDK
10.0.404, and C# MCP SDK 2.3.1. The clients completed tool discovery and four
`echo_marker` calls using distinct synthetic markers. The HTTP server recorded
the JSON-RPC messages it received and sent, including SSE `data:` events in
the Node case. Two separate process-memory snapshots were taken with the
[cross-runtime harness](../validation/cross_runtime/README.md). No GitHub Actions
workflow was run.

| Case | First snapshot | Second snapshot | Second snapshot details |
| --- | ---: | ---: | --- |
| Node SDK, Streamable HTTP with SSE responses | 13/13 | 13/13 | 6 SSE response messages; 20 carved records directly preceded by `data: ` |
| .NET SDK, 2025-11-25 over Streamable HTTP | 7/13 | 8/13 | UTF-8 and UTF-16LE records |
| .NET SDK, 2026-07-28 over Streamable HTTP | 7/12 | 7/12 | `server/discover` response and tool responses recovered; UTF-8 and UTF-16LE records |
| LSP Content-Length control | 2/2 | 2/2 | 0 records classified as MCP; 6 records directly preceded by a Content-Length header |

Fractions are *distinct logged messages present in this one process snapshot*,
not an estimated recovery rate. The second snapshot produced 42 Node, 16
legacy .NET, 15 modern .NET, and 16 LSP artifact records. Every exported raw
sequence in that snapshot was reread byte-for-byte at its reported virtual
address while its process was paused. There were no read errors or scan-limit
hits. No MCP-classified record in these client processes was unmatched to the
controlled HTTP log; this small sample does not establish a false-positive
rate for arbitrary memory.

In the .NET cases, most earlier outbound requests were absent from the paused
client snapshots, while response objects and the last outbound `tools/call`
were present. This experiment cannot determine whether the missing requests
had been reclaimed or were missed by the scanner. The UTF-16LE response records
show that the existing marker search can recover real .NET UTF-16LE JSON-RPC
text. The Node case shows the scanner can start at a JSON object after an SSE
`data: ` prefix when that frame remains in memory. The LSP control shows that
the recovered `initialize` messages were not labeled as MCP.

## Follow-up exact-wire probe (two more snapshots)

The harness now records each complete HTTP JSON payload and searches the same
paused process maps for those exact bytes in UTF-8 and UTF-16LE. It reports a
confirmed scanner miss only when a complete payload is independently present
but its logical message is not carved. Two additional snapshots used this
probe with the current classifier:

| Case | Third snapshot: carved / logged | Fourth snapshot: carved / logged | Exact wire present but not carved |
| --- | ---: | ---: | ---: |
| Node SDK, Streamable HTTP with SSE responses | 13/13 | 13/13 | 0 in both |
| .NET SDK, 2025-11-25 | 7/13 | 7/13 | 0 in both |
| .NET SDK, 2026-07-28 | 8/12 | 7/12 | 0 in both |
| LSP Content-Length control | 2/2 | 2/2 | Not probed |

For every Node and .NET message carved in these snapshots, its exact wire
payload was also found independently; none of the missing .NET requests had an
exact wire payload in the scanned maps. All 89 carved artifact records in each
run were reread at their virtual addresses. Neither run reported a
read error, 256 MiB truncation, anchor or candidate limit hit, or an unmatched
MCP candidate in the controlled traffic. The LSP control remained free of MCP
labels. These results do **not** establish that the missing requests had been
reclaimed: a differently serialized in-memory copy could still have existed.
They also do not establish a general scanner false-negative rate. No encoding
or carving change was justified by these samples.

The Node HTTP server uses the official TypeScript SDK for the Node case. The
.NET cases use the official C# client SDK and a small local HTTP peer; the
2026 discovery and result shapes follow the protocol specification, but this
does not validate interoperability with a production 2026 server. The LSP
control uses real TCP framing with a small purpose-built peer, not an LSP SDK.
Only readable private writable process maps were scanned, with a 256 MiB cap.
This is not a full physical RAM acquisition or Volatility end-to-end run, and
does not cover Windows, UTF-16BE, longer sessions, or broader client samples.

Machine-readable evidence: [first snapshot](../validation/cross_runtime/results/2026-11-11-linux-arm64-run-a.json),
[second snapshot](../validation/cross_runtime/results/2026-11-11-linux-arm64-run-b.json),
[third snapshot with wire probe](../validation/cross_runtime/results/2026-11-11-linux-arm64-wire-probe.json),
[fourth snapshot with wire probe](../validation/cross_runtime/results/2026-11-11-linux-arm64-wire-probe-b.json).
