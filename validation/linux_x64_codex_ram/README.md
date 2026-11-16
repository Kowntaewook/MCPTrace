# Codex CLI as a second live MCP host in Linux physical RAM

This follow-up uses **Codex CLI 0.159.3 for Linux x64** as an MCP host distinct
from MCP Inspector. The real CLI initializes a stdio MCP server, requests
`tools/list`, and calls `echo_marker` with a synthetic marker. An independent
stdio proxy records the exact JSON messages in both directions. A local,
deterministic Responses endpoint supplies the model's one tool-call decision;
it is **not a live language-model evaluation**. The endpoint then holds the
Codex process alive after the successful tool result while QEMU captures the
guest's whole physical RAM twice. Volatility scans only the Codex PID. No
account credential or external model API is used in the guest.

## Observed result, 2026-11-16

| Capture | Logged MCP messages | Exact wire bodies present in readable Codex VMAs | Logged messages carved | Logged messages with MCP label | Address-verified artifact records | MCP-labeled records |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| First | 7 | 5 | 5 | 5 | 6 | 6 |
| Later, same PID | 7 | 5 | 5 | 5 | 6 | 6 |

The captures used the **same one tool exchange and the same client PID**; the
image timestamps are 123 seconds apart. They are two observations of retention,
not two independent tool-call trials. The traffic journal was unchanged across
each acquisition. The five exact wire bodies found at either capture include
the client's `initialize`, `notifications/initialized`, `tools/list`, and
`tools/call`, plus the server's `tools/call` result. The server's `initialize`
and `tools/list` response bodies were not found as exact wire bytes in the
Codex PID's readable VMAs at either capture. Thus **5/5 present bodies were
carved and MCP-labeled**, with zero confirmed scan misses in this conditional
scope; 5/7 is not a tool detection rate. A semantic copy could still exist
without its original serialized wire bytes.

All six exported artifact records in each capture were reread byte-for-byte
from the reported process virtual address in that image. None was unmatched
to the independent journal. Neither scan hit a limit. The scorer also reports
about 296 MB of unreadable bytes in sparse Codex VMAs; absence is assessed only
in readable memory. See the [first](results/2026-11-16-codex-pilot.json) and
[later](results/2026-11-16-codex-delayed.json) numeric reports for individual
message hashes, encoding probes, artifact counts, and image/archive hashes.

## Acquisition and reproduction

- The guest was Ubuntu Minimal 24.04 AMD64 with kernel 6.8.0-146-generic, in
  QEMU 11.1.3 `q35`/TCG with two vCPUs and **1024 MiB** guest RAM. It reused
  the verified logical guest disk from the [Inspector full-RAM experiment](../linux_x64_real_host_ram/README.md).
- The official `@openai/codex@0.159.3-linux-x64` npm tarball passed its
  registry SHA-512 integrity check. The extracted Linux executable SHA-256 was
  `8bf204b36a2f6dd0dab73aa2f639892e67ef9ac8befccb4a05b1496ebf25c479`.
  The peer uses the official TypeScript MCP SDK 1.32.1 and the
  [stdio byte logger](../real_host/stdio_proxy.mjs).
- [model_fixture.py](model_fixture.py) provides only the synthetic tool call
  and holds the second model response until a release file appears.
  [run_guest.sh](run_guest.sh) configures an isolated `CODEX_HOME` and launches
  the CLI and local endpoint. `mcp_optional_startup_grace_ms=0` waits for MCP
  tool discovery before the model request on this slower emulated VM.
- For each capture, [the capture runner](../linux_x64_real_host_ram/capture.py)
  used QMP `stop`, `dump-guest-memory` with `paging=false`, and `cont`, then
  Volatility 3 2.28.2 `linux.mcptrace.MCPTrace --pid 2566 --include-rpc --dump`.
  [The scorer](../linux_x64_real_host_ram/score.py) validates independent
  UTF-8/UTF-16LE exact-wire presence, artifact addresses, and classification.
  The same Ubuntu kernel ISF as the Inspector full-RAM experiment was used.

Both 1,090,652,227-byte ELF images were compressed with zstd, reconstructed
through a separate stream, and checked against their full-image SHA-256 and
archive SHA-256 values. The two archives, traffic logs, Codex output, guest
disk overlay, and temporary SSH material remain **private**. Numeric reports
contain no raw message bodies. The peer server, tool call decision, single
host version, and one process per transport limit the result to this controlled
stdio scenario. Existing LSP and ordinary JSON-RPC controls belong to the
separate Inspector experiment; no new control or HTTP Codex run is claimed
here. This experiment does not estimate detection across apps or ordinary
agent use.

The [six-capture evidence manifest and reviewer replay guide](../linux_x64_real_host_ram/ground_truth/README.md)
checks the retained Codex journals and archive hashes against these public
reports. The original Codex JSON-RPC `params._meta` includes runtime session,
turn, and window identifiers, so its exact wire journals remain private. A
redacted copy would not be byte-identical to the messages searched in RAM.
The later [fresh-process repeat study](../linux_x64_repeat/README.md) adds two
separate Codex tool exchanges and same-VM non-MCP controls; these are distinct
from this original two-image observation of one exchange.
