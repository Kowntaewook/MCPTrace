# Local cross-runtime process-memory validation

This harness runs real MCP clients and checks what MCPTrace can carve from their
live Linux process memory. It does not collect physical RAM or run the Volatility
plugin. It uses no GitHub Actions.

## Cases

- Node 22 with the official TypeScript SDK 1.32.1: SDK client and server exchange
  Streamable HTTP requests. The server returns SSE responses.
- .NET 10 with the official C# SDK 2.3.1: one client pins the 2025-11-25
  protocol, and one pins 2026-07-28. A minimal local HTTP peer returns JSON
  responses for these clients. The modern discovery response follows the
  [2026 specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/discover.mdx).
  The peer is not the official server SDK.
- LSP control: a Node TCP client and server exchange Content-Length-framed
  `initialize` request/response messages, including `clientInfo`,
  `capabilities`, `rootUri`, and `workspaceFolders`.

The HTTP server logs the exact logical JSON objects it receives or sends.
The scanner pauses each client with SIGSTOP, scans readable private writable
maps via `/proc/<pid>/mem`, and independently rereads each carved byte sequence
at its virtual address. It counts distinct logical messages separately from
memory copies. The 256 MiB scan cap and any unreadable pages are reported.

## Run on Linux

Requires Python 3.10+, Node 22+, .NET 10 SDK, and permission for a parent
process to read its child processes' `/proc/<pid>/mem`. From the repository root:

```bash
npm ci --prefix validation/cross_runtime
dotnet restore validation/cross_runtime/dotnet/Client.csproj --locked-mode
dotnet build validation/cross_runtime/dotnet/Client.csproj -c Release \
  -o /tmp/mcptrace-dotnet-client --no-restore
PYTHONPATH=. python3 validation/cross_runtime/run.py \
  --node "$(command -v node)" \
  --dotnet "$(command -v dotnet)" \
  --dotnet-client /tmp/mcptrace-dotnet-client/Client.dll \
  --workdir /tmp/mcptrace-validation-run-001 \
  --report /tmp/mcptrace-validation-report.json
```

Use a new `--workdir` for each run. Omit `--dotnet` and `--dotnet-client` to
run only the Node MCP and LSP control cases. The report includes per-message
matches and framing evidence. Test marker strings are synthetic; the report
does not include process dumps.

Measured results and limitations: [cross-runtime validation report](../../docs/cross-runtime-memory-validation.md).
