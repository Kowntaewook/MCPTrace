# Real MCP host process-memory validation (2026-11-14)

This experiment ran the [official MCP Inspector `mcpdo` client](https://github.com/modelcontextprotocol/inspector/tree/main/clients/mcpdo) v2.15.0 on macOS 27.2 ARM64 and Ubuntu 24.04 ARM64. Each client connected to a local server built with the official TypeScript MCP SDK 1.32.1, listed tools, and called `echo_marker` with a synthetic value. One fresh client daemon used Streamable HTTP, and another used stdio, on each OS. The server or a separate stdio byte proxy journaled actual JSON-RPC traffic before memory analysis. LSP and ordinary JSON-RPC TCP clients served as non-MCP controls.

**Scope:** These are live *process virtual memory* captures. The macOS capture came from an opt-in addon inside the isolated client process; Linux used `/proc/<pid>/mem` while the client was stopped. This is not a physical RAM image, a Volatility end-to-end run, or an estimate of field detection rate. The macOS capture sampled resident private writable pages while the host remained active, so it is not atomic. The Linux scan covered readable private writable maps up to 256 MiB. The final eight captures had zero reported read errors and no 256 MiB truncation.

## Result

| OS / case | Logged messages | Exact wire payloads in scanned memory | Logical messages carved | MCP candidate records | Confirmed scan misses |
| --- | ---: | ---: | ---: | ---: | ---: |
| macOS / Inspector HTTP | 9 | 3 | 3 | 3 | 0 |
| macOS / Inspector stdio | 9 | 7 | 7 | 14 | 0 |
| Linux / Inspector HTTP | 9 | 4 | 4 | 11 | 0 |
| Linux / Inspector stdio | 9 | 8 | 8 | 17 | 0 |
| macOS / LSP `Content-Length` control | 2 | Not probed | 2 | 0 | Not probed |
| macOS / generic JSON-RPC control | 2 | 2 | 2 | 0 | 0 |
| Linux / LSP `Content-Length` control | 2 | Not probed | 2 | 0 | Not probed |
| Linux / generic JSON-RPC control | 2 | 2 | 2 | 0 | 0 |

The independent wire check searched the same captured bytes for complete UTF-8 and UTF-16LE wire payloads. Every complete wire payload found in these snapshots was carved. Other logged messages were absent as *exact wire bytes*; a differently serialized copy might still have been present. `0` is therefore a count of confirmed scan misses in these specific captures, not a general false-negative rate. The LSP journal recorded logical messages and real TCP framing but did not retain exact wire bodies, so its wire-presence and miss fields are unprobed. Both LSP and generic JSON-RPC controls were carved without an MCP label. In the Linux HTTP capture, six artifact records were directly preceded by an SSE `data: ` prefix. All Linux artifact records were independently reread at their reported virtual addresses while their processes were stopped. No final case had an unmatched MCP candidate or a scan-limit hit.

The Inspector client is an independent, packaged MCP host, while the peer server and controls are purpose-built for this test. A separate VS Code connection on macOS also exchanged real HTTP MCP discovery and tool-list traffic, but no VS Code process-memory result is included here. These controlled samples do not establish behavior for other hosts, versions, workloads, swap, unreadable maps, Windows, or full-machine acquisition.

Machine-readable reports: [macOS HTTP](results/2026-11-14/macos-http.json), [macOS stdio](results/2026-11-14/macos-stdio.json), [Linux HTTP](results/2026-11-14/linux-http.json), [Linux stdio](results/2026-11-14/linux-stdio.json), [macOS LSP](results/2026-11-14/macos-lsp-negative.json), [macOS JSON-RPC](results/2026-11-14/macos-jsonrpc-negative.json), [Linux LSP](results/2026-11-14/linux-lsp-negative.json), and [Linux JSON-RPC](results/2026-11-14/linux-jsonrpc-negative.json). Reports contain counts, hashes, protocol labels, and method names; no memory bytes or marker values are committed.

## Acquisition and replay

Install Node 22.23.4, `npm ci --prefix validation/cross_runtime`, and `@modelcontextprotocol/inspector@2.15.0` in a separate temporary directory. Set `MCP_INSPECTOR_DAEMON_DIR` and `MCP_STORAGE_DIR` to fresh private directories for each case. Start `node validation/cross_runtime/node_fixture.mjs server WORKDIR PORT` for HTTP. Connect with `mcpdo connect --transport http --era legacy http://127.0.0.1:PORT/mcp`, then run `tools/list` and `tools/call echo_marker` through that named connection. For stdio, connect to `node validation/real_host/stdio_proxy.mjs LOG validation/cross_runtime/stdio_server.mjs`; the proxy journals newline-delimited bytes and forwards them to the SDK server. Run `lsp_control.mjs` and `jsonrpc_control.mjs` separately as non-MCP clients.

On Linux, pass the Inspector daemon PID, independent traffic journal, report path, and a **private** capture path to:

```bash
sudo env PYTHONPATH=. python3 -m validation.real_host.scan_linux_pid \
  --pid PID --traffic TRAFFIC.jsonl --case CASE \
  --capture PRIVATE.capture --report REPORT.json
```

On macOS, compile `mac_self_snapshot.c` as a Node N-API addon with `clang -O2 -bundle -undefined dynamic_lookup -I NODE_INCLUDE -o PRIVATE.node`. Load `mac_snapshot_preload.cjs` in an isolated client through `NODE_OPTIONS=--require=...`, set `MCPTRACE_SNAPSHOT_REQUEST` and `MCPTRACE_SNAPSHOT_ADDON`, and write a request JSON object containing the intended daemon `pid` and private `output` path. The addon captures only resident private writable pages of **its own process**, with a 256 MiB output cap. Score the binary and independent journal with:

```bash
PYTHONPATH=. python3 -m validation.real_host.scan_mach_capture \
  --capture PRIVATE.capture --traffic TRAFFIC.jsonl \
  --case CASE --report REPORT.json
```

Both capture writers emit little-endian `(virtual_address:uint64, length:uint32, bytes)` records. Treat captures and traffic journals as sensitive. The eight original captures and wire journals are retained locally outside the repository; the four Linux captures are in one lossless archive. Its SHA-256 is `2bdd41c2cbad15045e77073be11f7ff170e1bcd990b2220ead9cab66b2895413`. Each uncompressed capture was separately checked against the `snapshot_sha256` in its report. Raw files were not uploaded.
