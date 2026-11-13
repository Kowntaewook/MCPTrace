# No-Windows validation and case reporting (2026-11-13)

## Paired controlled-buffer comparison

The same 16 constructed buffers were scanned with the v0.3.0 core and the
post-release main core (`c259ed2`). The released version matched the expected
**MCP-candidate flag** in 15/16 cases; the current core matched in 16/16 and
matched the expected protocol hint in 16/16. The changed case has both an MCP
version envelope and an LSP workspace signal: v0.3.0 marked it MCP, while the
current core reports it as ambiguous. This is a regression result on chosen
controls, not a general classification accuracy measurement.

Both versions mark one unrelated JSON-RPC response containing a `tools` list
as an MCP candidate. The label is deliberately a *candidate*: the response
shape alone cannot prove it came from MCP. A deliberately unsent MCP-shaped
control is also found by both versions. The scanner cannot infer whether a
memory-resident object crossed a transport. Neither control should be counted
as a verified transmitted MCP message.

Full inputs, buffer hashes, per-case observations, and revision IDs:
[machine-readable paired result](../validation/protocol_corpus/results/2026-11-13-v030-vs-main.json).
Reproduction command: [protocol corpus guide](../validation/protocol_corpus/README.md).

## Case report

`python -m mcptrace.report` accepts one or more per-process JSONL exports.
For each artifact it checks base64 decoding, raw-byte length and SHA-256,
parsed message consistency, PID, target OS, and virtual address. The resulting
JSON names the source export and its file hash, gives artifact addresses and
classification reasons, counts protocol hints, and surfaces reported scan
limits, unreadable bytes, errors, and skipped processes. It omits raw message
bytes, arguments, and reconstructed conversation content. A successful export
check does not verify the original RAM acquisition. The report never assigns
timestamps from memory address or export row order.

This report format takes the *idea* of a manifest and per-parser status from
[ARTINEX](https://github.com/WHS4-Erelem/LLM_Forensic_Parser), which targets
LLM-service artifacts in Windows disk images. MCPTrace targets protocol
candidates in memory. No ARTINEX code is reused.

## Physical-memory status

The existing [cross-runtime validation](cross-runtime-memory-validation.md)
used paused Linux ARM64 process-memory snapshots, not Volatility on an x86-64
physical RAM image. A separate [Linux x86-64 physical RAM experiment](../validation/linux_x64_positive/README.md)
now exercises Volatility 3 2.28.2 and MCPTrace end to end on a QEMU ELF dump.
The controlled Python stdio client/server exchanged 6 outbound and 5 inbound
messages, retained the exact bytes, and held one deliberately unsent control.
All 11 exchanged messages and the unsent control were recovered as distinct
logical objects; the default scan produced 62 artifact records from copies and
alternate serializations. All 62 exported byte sequences were reread at the
reported process virtual addresses. Repeated scans of the same image produced
identical JSONL. No record was semantically unmatched to the controlled set.

The default client scan reported **2 candidate backtracking limit hits** and
unreadable VMA bytes. With a 4 KiB maximum object size, the same image yielded
the same 62 address/hash artifacts and no candidate limit hits. This setting
would exclude larger objects, so it is not a universal fix. The experiment
uses deliberately retained bytes and a purpose-built peer, not an official
MCP SDK; its 11/11 result is not general recovery recall. The unsent control
shows why recovered RAM objects cannot establish transmission.

[Machine-readable numeric result](../validation/linux_x64_positive/results/2026-11-13-qemu-ubuntu.json)
contains the image and symbol hashes, per-process scan summaries, and scoring
denominators. Raw RAM and message exports are not committed.
