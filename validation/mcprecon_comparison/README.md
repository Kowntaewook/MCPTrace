# MCPRecon comparison on archived HTTP/SSE RAM captures

This is a **controlled comparison of message recovery in one synthetic SDK
fixture**, not a claim about general detection accuracy or overall tool
superiority. MCPRecon was known prior work for MCPTrace: the project had
already analyzed the authors' public `sample.vmem` in
[`docs/real-memory-validation.md`](../../docs/real-memory-validation.md).
The related study is [*With or Without Logs: Memory Forensic Reconstruction
of Model Context Protocol (MCP) Activity in Agentic LLM Systems*](https://dfrws.org/presentation/with-or-without-logs-reconstructing-model-context-protocol-activity-from-volatile-memory/).
This experiment runs the [published MCPRecon CLI](https://github.com/BiTLab-BaggiliTruthLab/MCPRecon/blob/4811d04e6c6a522759ade5e2f3fef37d33c6c27e/tool/mcprecon.py)
on MCPTrace's independently logged RAM fixture.

## Inputs and method

- MCPRecon commit `4811d04e6c6a522759ade5e2f3fef37d33c6c27e`, Git blob
  `5f03a84bc855a69173eedf5a8963c32509a468b5`, default keywords and
  16 KiB window, `--emit-raw` only to verify output bytes. Its source was
  downloaded outside this repository and checked against the pinned Git blob.
- MCPTrace `ded4c00235f5c41222f72e8529f3dbd617bc3c9f`. Its saved
  client-PID exports from the
  [27-image HTTP/SSE rerun](../linux_x64_http_ram/README.md) were verified
  against each image, export, and separate server traffic log by SHA-256.
  The original experiment already reread all 626 artifacts at their reported
  process virtual addresses. The initial comparison used those archived exports;
  a later pinned-code rerun independently repeated the scan on all 27 images
  and reread its new artifacts (see the rerun report below).
- The 27 captures cover Node and two .NET HTTP protocol conditions, each at
  0, 5, and 30 seconds, three fresh client processes per delay. The same VM
  was reused. The server traffic log provides 342 transmitted messages;
  independent probes found exact wire payloads for 251 in the current client
  process's readable VMAs.
- Logical messages were matched by canonical JSON equality with the separate
  traffic log. Repeated in-memory copies count once per transmitted message.
  The match is a *fixture-specific observation*, not proof that any particular
  memory copy was transmitted. Messages without exact wire bytes in the
  client's readable memory are excluded from the conditional denominator.

Two MCPRecon runs were made on each image:

1. **Whole ELF RAM:** its native raw-file workflow on the full QEMU dump.
   This is an exploratory output and **not a controlled comparison** with
   MCPTrace's single-client process scan. MCPRecon can see server and stale VM
   copies. Indeed, 68 truth messages found in whole-RAM output were absent as
   exact wire bytes from the current client's readable VMAs. The
   [whole-image numeric report](results/2026-11-14-http-ram-rerun.json) keeps
   this result separate; its unmatched records are not labeled false positives.
2. **Client readable bytes:** Volatility 3 reread exactly the same client PID
   VMAs as the original independent probe. Contiguous readable chunks were
   concatenated and 64 KiB of NUL bytes inserted at gaps and VMA boundaries.
   The extracted byte count, unreadable byte count, and VMA count matched the
   original probe for every image. A second pass checked every one of the 342
   traffic rows: UTF-8 and UTF-16LE exact-wire presence in the derived stream
   matched the original independent probe message by message. MCPRecon scanned
   this **derived byte stream**, which changes physical layout, file offsets, and potentially
   session grouping. The [client-only numeric report](results/2026-11-14-http-ram-rerun-client.json)
   is the closer byte-scope comparison, but it is not MCPRecon's native
   whole-image workflow.

## Observed client-byte result

| Client condition | Captures | Sent | Exact wire in client VMAs | MCPTrace matched | MCPRecon matched |
| --- | ---: | ---: | ---: | ---: | ---: |
| Node 22, TypeScript SDK, HTTP/SSE | 9 | 117 | 112 | 112 | 49 |
| .NET 10, 2025-11-25 | 9 | 117 | 71 | 71 | 68 |
| .NET 10, 2026-07-28 | 9 | 108 | 68 | 68 | 67 |
| **Total** | **27** | **342** | **251** | **251** | **184** |

The [archived-output accounting audit](results/2026-11-15-archived-breakdown.json)
separates **carving** from each tool's **MCP label**. MCPTrace ran with
`--include-rpc`, and MCPRecon's default CLI did not use `--mcp-only`. The table
above therefore counts logged logical messages whose JSON objects were carved,
regardless of their classifier labels. A label comparison is a different
measurement, and the two classifiers do not have identical rules:

| Measure on the derived client-byte streams | MCPTrace | MCPRecon |
| --- | ---: | ---: |
| Distinct logged messages carved, any label | 251 | 184 |
| Distinct logged messages with at least one MCP-labeled copy | 233 | 94 |
| All carved artifact records | 626 | 315 |
| MCP-labeled artifact records | 583 | 192 |

All **251** messages in the exact-wire-present denominator had a UTF-8 copy;
**108** also had a UTF-16LE copy, and **none** existed only as UTF-16LE. Thus
UTF-16LE-only presence does not explain the 251-versus-184 carving difference
in this fixture. The other **91** transmitted messages had no exact wire bytes
in the current client's readable VMAs. Neither client-scoped output matched
any of those 91 by canonical JSON equality; this does not rule out partial or
differently represented objects in other memory locations.

| Requested delay after readiness | Sent | Exact wire present | MCPTrace carved | MCPRecon carved |
| --- | ---: | ---: | ---: | ---: |
| 0 s | 114 | 86 | 86 | 63 |
| 5 s | 114 | 86 | 86 | 64 |
| 30 s | 114 | 79 | 79 | 57 |

The readiness poll was not synchronized to the exact final call, and these
small groups cannot establish a time-decay curve. The audit also found that
the **184** exact-wire-present logical messages matched by MCPRecon in native
whole-RAM mode were exactly the same **184** found in the derived client-byte
streams, capture by capture. Its additional 68 whole-RAM truth matches lacked
exact wire bytes in the *current client's readable VMAs* and cannot be
attributed to that client from the raw offset alone.

The [pinned MCPTrace rerun](results/2026-11-15-mcptrace-rerun.json) reconstructed
all 27 archived images, checked each SHA-256, scanned the original client PID
with commit `ded4c002`, and reread all 626 new artifacts from their reported
process virtual addresses. All 27 new JSONL exports reproduced the saved
exports byte-for-byte; 251 of 251 exact-wire-present logical messages were
carved, with zero scan limits hit. The rerun report contains counts and hashes
only. The separate [accounting audit](results/2026-11-15-archived-breakdown.json)
recomputes the encoding, label, and delay counts from hash-checked traffic and
MCPTrace exports plus the retained MCPRecon outputs. It records the latter's
SHA-256 values for future comparison.

MCPRecon emitted 315 records from the derived client streams. Every record's
raw bytes matched the reported offset in that stream. All 315 records matched
a logical message in the traffic log. This does **not** measure specificity:
these are positive, purpose-built client captures, with no non-MCP control in
this comparison. A file offset in the packed stream also does not provide the
original PID and virtual address that MCPTrace exports.

For the 67 truth messages present in client memory but absent from MCPRecon's
default output, 63 were in the Node cases: 9 `initialize` requests and 54
responses. The remaining four were three .NET `notifications/initialized` and
one .NET `server/discover`. On one Node capture, increasing MCPRecon's window
from 16 KiB to 64 KiB and 1 MiB did not change its 6-of-13 match count.
Inspection of that run's wire payloads and the published `carve_json()` shows
that its nearest-opening-brace rule can select a nested object when the
`jsonrpc` key follows other objects. This is a **specific failure mechanism in
the tested serialization**, not a universal claim about MCPRecon.

## Reproduction

The raw RAM and traffic logs remain outside Git. The [public evidence
release](https://github.com/Kowntaewook/MCPTrace/releases/tag/evidence-http-ram-2026-11-14)
contains the 27 RAM assets; the original external traffic logs and MCPTrace
exports are retained in the private local evidence bundle. The numeric JSON
reports do not contain raw messages, memory bytes, SSH material, or process
addresses.

Run from the MCPTrace repository root, with the separate evidence bundle next
to the repository and the exact MCPRecon source in a separate local directory:

```sh
zstd -d -c ../MCPTrace-evidence-private-2026-11-14/assets/mcptrace-node-d0-r1-ram.elf.zst \
  > ../MCPTrace-evidence-private-2026-11-14/node-d0-r1-ram.elf

PYTHONPATH=. .venv/bin/python validation/mcprecon_comparison/run.py \
  --evidence ../MCPTrace-evidence-private-2026-11-14 \
  --mcprecon ../isdfs-mcprecon-baseline-2026-11-14/mcprecon.py \
  --symbols ../MCPTrace-evidence-private-2026-11-14/symbols \
  --cache ../MCPTrace-evidence-private-2026-11-14/cache \
  --client-only \
  --report validation/mcprecon_comparison/results/2026-11-14-http-ram-rerun-client.json

PYTHONPATH=. .venv/bin/python validation/mcprecon_comparison/rerun_mcptrace.py \
  --evidence ../MCPTrace-evidence-private-2026-11-14 \
  --symbols ../MCPTrace-evidence-private-2026-11-14/symbols \
  --cache ../MCPTrace-evidence-private-2026-11-14/cache \
  --vol .venv/bin/vol \
  --checkpoint ../MCPTrace-evidence-private-2026-11-14/mcptrace-rerun-checkpoint.json \
  --report validation/mcprecon_comparison/results/2026-11-15-mcptrace-rerun.json

PYTHONPATH=. .venv/bin/python validation/mcprecon_comparison/analyze_existing.py \
  --evidence ../MCPTrace-evidence-private-2026-11-14 \
  --report validation/mcprecon_comparison/results/2026-11-15-archived-breakdown.json
```

The matching Linux kernel ISF is the SHA-256-pinned file in the [HTTP RAM
validation input list](../linux_x64_http_ram/README.md). The runner verifies
each archive and reconstructed image SHA-256, original traffic/export hashes,
and the client VMA read counts before recording the result. The published
MCPRecon source is executed locally; private JSONL outputs stay in the
evidence directory.

## Paper interpretation

The tested condition supports a narrow statement: **in this 27-capture
fixture, MCPTrace recovered all 251 exact-wire-present client messages,
while MCPRecon's default CLI recovered 184 from a derived stream of the same
readable client bytes**. It does not establish general recall, precision,
runtime superiority, or performance on other hosts and capture conditions.
The tools' original workflows and provenance outputs differ. A paper should
report both the scope-matched and whole-image runs and keep those differences
explicit.

## Non-MCP controls (2026-11-15)

Four preserved process-memory captures from the [real-host validation](../real_host/README.md)
were rescanned: LSP and ordinary JSON-RPC clients on macOS and Linux. The
capture and separate traffic-log SHA-256 values were checked against the
original reports. For MCPRecon, the capture headers were removed and
noncontiguous memory chunks were separated with 64 KiB of NUL bytes. MCPTrace
was rerun directly over the captured chunks; its 43 artifact records and zero
MCP candidates matched the saved reports.

| Control group | Captures | Logged non-MCP messages | MCPTrace MCP-labeled records | MCPRecon MCP-labeled records |
| --- | ---: | ---: | ---: | ---: |
| macOS and Linux LSP, JSON-RPC | 4 | 8 | 0 of 43 | 0 of 43 |

Both tools carved all eight logged logical messages. MCPRecon's 43 output
records were verified at their offsets in the derived streams. The
[captured-control numeric report](results/2026-11-15-negative-controls.json)
contains counts and hashes only. Four purpose-built controls do not establish
a population false-positive rate.

The [constructed protocol corpus](../protocol_corpus/README.md) provides
eight explicitly non-MCP-origin cases, including hard negatives. Both tools
marked **one of eight** as MCP: a generic JSON-RPC response whose `result`
contains a `tools` list. This is a protocol-origin counterexample to treating
MCP-shaped bytes as proof of MCP transport. The [constructed-control report](results/2026-11-15-constructed-controls.json)
also shows MCPRecon did not carve the UTF-16LE LSP case, while MCPTrace carved
it without an MCP label. These tiny constructed buffers are useful boundary
tests, not field accuracy estimates.
