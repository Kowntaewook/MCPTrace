# Live MCP Inspector in Linux x86-64 physical RAM

This experiment connects a **packaged, independent MCP host** to the existing
Volatility 3 physical-RAM workflow. The host is MCP Inspector `mcpdo` 2.15.0,
not a purpose-built SDK client. A separate server using the official TypeScript
MCP SDK 1.32.1 logs actual HTTP JSON/SSE payloads; a separate stdio proxy logs
newline-delimited JSON bytes. After discovery, `tools/list`, and a successful
`echo_marker` tool call, the host daemon stays alive while QEMU saves the
guest's **whole physical RAM** as ELF. MCPTrace then scans only that daemon's
Linux PID through Volatility 3. The LSP and ordinary JSON-RPC controls use the
same VM, acquisition, plugin, and address-verification path, each with its own
live client PID. These are **four new images**, not the earlier ARM64 process
snapshots or the 27-image SDK comparison specimens.

## Observed result (2026-11-15)

| Guest client | Captures | Logged | Exact wire present in client VMAs | Carved logged messages | Logged messages with MCP label | Address-verified artifact records | MCP-labeled records |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| MCP Inspector / HTTP with SSE | 1 | 9 | 4 | 4 | 3 | 11 | 10 |
| MCP Inspector / stdio | 1 | 9 | 5 | 5 | 5 | 5 | 5 |
| LSP / `Content-Length` TCP | 1 | 2 | 2 | 2 | 0 | 8 | 0 |
| Ordinary JSON-RPC / TCP | 1 | 2 | 2 | 2 | 0 | 4 | 0 |

All 28 artifact records were reread byte-for-byte at their reported process
virtual addresses. Each of the 22 traffic messages has a separately recorded
raw JSON body; the independent UTF-8/UTF-16LE probe found 13 exact wire bodies
in the relevant readable client VMAs, and all 13 were carved. No capture hit a
scan limit or had an artifact unmatched to that capture's traffic journal.
The nine MCP host messages not found as exact wire bytes are **not established
scanner misses**. The HTTP `initialize` response was carved but labeled
`generic-json-rpc`, so carving all present messages does **not** mean that all
were classified as MCP. The LSP and ordinary JSON-RPC controls had zero MCP
labels in these single captures. This is not a population false-positive rate.
Each scan also reported unreadable bytes in sparse client VMAs, as the
per-capture reports show; zero confirmed misses applies only to exact wire
bytes independently found in readable client memory.

The [numeric summary](results/2026-11-15-summary.json) independently checked
all four private compressed archives against their recorded SHA-256 values,
reconstructed each stream, and confirmed its full-image hash and length.
Per-capture numeric reports are [HTTP](results/2026-11-15-inspector-http.json),
[stdio](results/2026-11-15-inspector-stdio.json),
[LSP](results/2026-11-15-lsp-control.json), and
[ordinary JSON-RPC](results/2026-11-15-jsonrpc-control.json).

## Inputs and acquisition

- Ubuntu Minimal 24.04 AMD64 cloud image dated 2026-11-07, SHA-256
  `af34b3230db47ac2159b500adaef438b5cb4da875139997b8797f9643e1743d3`.
  The guest booted `linux-image-6.8.0-146-generic` and
  `linux-modules-6.8.0-146-generic`, revision `6.8.0-146.146`. The matching
  Linux Volatility ISF SHA-256 is
  `18dd41722ad7d3b411d442065e6fafa3c177960e3e19ea484b391dfb1526e55b`.
- QEMU 11.1.3, `q35`, TCG, two vCPUs, 1536 MiB RAM, virtio disk/network,
  `-cpu max,-la57`, and a Unix QMP socket. QMP `stop`,
  `dump-guest-memory` with `paging=false`, and `cont` acquired each ELF image.
  The guest VM was reused; the scanned client PID was fresh for each condition.
- Official Linux x64 Node 22.23.4 archive, SHA-256
  `1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce`,
  checked against Node's `SHASUMS256.txt`. The server uses the lock in
  [`validation/cross_runtime`](../cross_runtime/package-lock.json), including
  `@modelcontextprotocol/sdk` 1.32.1. The packaged Inspector is 2.15.0;
  its resolved Linux install lock is [retained here](inspector/package-lock.json).
- Host Volatility 3 2.28.2 and MCPTrace source identical to commit
  `ded4c00235f5c41222f72e8529f3dbd617bc3c9f` under `mcptrace/` and
  `plugins/`. Each run used `linux.mcptrace.MCPTrace --pid PID --include-rpc
  --dump`. Including generic JSON-RPC in the export is necessary to measure
  carving and MCP classification separately.

The HTTP server records each actual JSON body and SSE `data:` payload outside
the Inspector daemon. The stdio proxy records both directions outside the
daemon and forwards them to an official-SDK stdio server. The LSP control uses
actual `Content-Length` framing over a TCP socket and records the JSON body
bytes plus their digest. The generic JSON-RPC control likewise records its TCP
request and response. For each capture, the traffic journal's SHA-256 was
unchanged before and after QMP acquisition. The scorer verifies each logged
raw body, probes exact UTF-8 and UTF-16LE wire bytes in the selected client's
readable VMAs independently of MCPTrace, validates the plugin's exported raw
bytes at the reported PID/VMA/virtual address, and compares distinct logical
JSON messages to the journal. Multiple copies are artifact records, not
additional transmitted messages.

## Reproduction and data boundary

Boot a fresh Ubuntu VM with a NoCloud `cidata` seed attached as a virtio drive,
a temporary SSH key, QMP, and forwarded guest SSH. Install and boot the exact
kernel above. Install the pinned Node archive, run `npm ci` for the SDK fixture
and the [Inspector lock](inspector/package-lock.json), and transfer the
`validation/cross_runtime` and `validation/real_host` scripts. With a fresh
`MCP_INSPECTOR_DAEMON_DIR` per transport, run `mcpdo connect` using HTTP or
stdio, then `tools/list` and `tools/call echo_marker`. The `client-ready.json`
must identify the live `mcpdod` PID; the LSP/JSON-RPC controls write their own
PID files. Use a fresh private capture directory for each case:

```sh
PYTHONPATH=. .venv/bin/python validation/linux_x64_real_host_ram/capture.py \
  --case inspector-http --qmp PRIVATE/qmp.sock \
  --ssh-key PRIVATE/guest-key --known-hosts PRIVATE/known_hosts \
  --guest-ready /home/ubuntu/experiment/runs/http/client-ready.json \
  --guest-traffic /home/ubuntu/experiment/runs/http/traffic.jsonl \
  --private-dir PRIVATE/captures/http \
  --symbols PRIVATE/symbols --cache PRIVATE/cache --vol .venv/bin/vol \
  --report validation/linux_x64_real_host_ram/results/2026-11-15-inspector-http.json

PYTHONPATH=. .venv/bin/python validation/linux_x64_real_host_ram/summarize.py \
  --results validation/linux_x64_real_host_ram/results \
  --private-captures PRIVATE/captures \
  --report validation/linux_x64_real_host_ram/results/2026-11-15-summary.json
```

The capture runner stores the full ELF image only until scoring and verified
compression finish. Original RAM archives, traffic logs, SSH keys, and raw
JSONL exports remain outside Git. The numeric reports contain hashes, counts,
and method names; raw message bytes are private. The compressed images may
contain ephemeral guest keys, daemon tokens, or other runtime state and were
**not uploaded**. Their original traffic journals are also required to
recompute the conditional matches; a public report alone cannot do that.

The four original **synthetic traffic journals** have since been content-audited
and released byte-for-byte with a six-capture hash manifest and private replay
instructions in [ground truth](ground_truth/README.md). The RAM archives and
raw scanner exports remain private, so the four image-level results still
cannot be independently recomputed from public files alone. The two Codex
traffic journals remain private because their wire bodies include session
metadata.

There was one capture per condition and no synchronized call-to-acquisition
delay measurement. The purpose-built peer server and controls, reused VM, and
single Inspector host family prevent a general host or field detection-rate
claim. MCPRecon was not run on these four new images; its 27-image comparison
remains [separate](../mcprecon_comparison/README.md).
