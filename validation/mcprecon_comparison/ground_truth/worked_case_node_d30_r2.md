# Worked evidence audit: `node-d30-r2`

This is a controlled Node SDK HTTP/SSE experiment, not an incident. The
requested delay was 30 seconds after readiness detection; acquisition was not
synchronized to the final tool call. The [machine-readable case](worked_case_node_d30_r2.json),
[external traffic journal](traffic/node-d30-r2.jsonl), and [numeric replay report](../results/public_replay_2026-11-16/node-d30-r2.json)
identify the same public RAM image by SHA-256.

| Evidence question | Observed result |
| --- | --- |
| What was transmitted? | The external server journal recorded 13 JSON-RPC bodies. Rows 5 and 6 (zero-based) are a `tools/call` request with ID 2 and its SSE response. |
| What exact wire bytes remained in readable client memory? | Eight of the 13 bodies, including the ID 2 response. The ID 2 request's UTF-8 wire body and its UTF-16LE encoding were not found in the scanned client VMAs. Other in-memory serializations were not excluded. |
| What did MCPTrace extract? | Eight distinct logged messages in 14 byte-verified records. The ID 2 response was reported as `unpaired`; no matching request artifact was extracted. |
| What did the pinned MCPRecon CLI extract? | One of the eight exact-wire-present messages from the derived client-byte stream. This is the published CLI in one configuration, not the paper's whole workflow. |

For one copy of the ID 2 response, MCPTrace reported client PID `4361`, VMA
start `0x2a845000`, process virtual address `0x2a99cd19`, UTF-8 byte length
`91`, and SHA-256
`e9bb1671e80a5ee0b24cdfd5a3a09e856d57bcb9d987412a7e492dcdc0e12e73`.
The replay reread those 91 bytes through Volatility from the original image
and matched them to the exact JSON body in external traffic row 6. The SSE
`data:` framing prefix is outside this body hash. A second copy of the same
response existed at another address; the address above is an illustrative
artifact, not a unique event location.

The scan summary reported `77,991,936` bytes read from client VMAs and
`11,742,543,872` unreadable bytes in the enumerated virtual ranges, with no
scan limit hit. The unreadable figure describes sparse or inaccessible
**virtual address ranges**, not the physical RAM image size. It prevents an
unqualified claim that a missing request was absent from all client memory.
In this controlled fixture, the independent server log establishes that the
ID 2 request was transmitted. Without that log, the byte-verified response
would show that a response-shaped object occupied that image address; it would
not by itself prove when a request was sent, accepted, or executed.

Run `replay_public.py run --run-id node-d30-r2` as documented in the
[ground-truth guide](README.md). The command checks the case metadata,
independent wire-byte presence, output bytes reread at the process virtual
address, and capture-level counts; it adds `worked_case_verified: true` to
the numeric report only if all checks pass.
