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
  process virtual addresses. MCPTrace was **not rerun** for this comparison.
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
   original probe for every image. MCPRecon scanned this **derived byte
   stream**, which changes physical layout, file offsets, and potentially
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
