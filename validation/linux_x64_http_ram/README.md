# Node and .NET HTTP/SSE in Linux x86-64 physical RAM

This local experiment extends the earlier [process-memory validation](../cross_runtime/README.md)
to QEMU guest physical RAM and the Volatility 3 MCPTrace plugin. It uses the
existing pinned fixtures: Node 22.14.0 with the official TypeScript MCP SDK
1.32.1, and .NET 10.0.404 with the official C# MCP client SDK 2.3.1.
The Node case uses official client and server SDKs. The two .NET protocol
cases use the official C# client with the existing purpose-built local HTTP
peer, which is **not** an official C# server implementation.

The server process records each actual HTTP JSON body or SSE `data:` payload
with its direction and framing. Each client completes discovery and four
`echo_marker` calls, writes a readiness file, and remains alive for the RAM
capture. The server log is outside the scanned client process. The host pauses
QEMU, saves an ELF physical RAM image, resumes QEMU, and runs the Linux MCPTrace
Volatility plugin against **only that client PID**. Every exported artifact is
reread at the reported process virtual address. An independent probe searches
the same readable client VMAs for full exact wire payloads as UTF-8 and
UTF-16LE. A payload present in RAM but absent from MCPTrace's logical messages
is a confirmed scan miss for this controlled fixture.

## Reproduction inputs

- Ubuntu Minimal 24.04 AMD64 [2026-11-07 image](https://cloud-images.ubuntu.com/minimal/daily/noble/20261107/noble-minimal-cloudimg-amd64.img), SHA-256 `af34b3230db47ac2159b500adaef438b5cb4da875139997b8797f9643e1743d3`.
- QEMU 11.1.3 with `q35`, TCG, two vCPUs, 2048 MiB RAM, virtio disk and
  network, and `-cpu max,-la57`. The CPU option avoids five-level paging,
  which did not work with this Volatility setup in the earlier
  [Linux positive control](../linux_x64_positive/README.md).
- Ubuntu `linux-image-6.8.0-146-generic` and
  `linux-modules-6.8.0-146-generic`, revision `6.8.0-146.146`, installed from
  the Ubuntu archive and booted. Matching [community Volatility ISF](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/Ubuntu/amd64/6.8.0/146/generic/Ubuntu_6.8.0-146-generic_6.8.0-146.146_amd64.json.xz), SHA-256 `18dd41722ad7d3b411d442065e6fafa3c177960e3e19ea484b391dfb1526e55b`.
- Node 22.14.0 Linux x64 [official archive](https://nodejs.org/dist/v22.14.0/),
  SHA-256 `69b09dba5c8dcb05c4e4273a4340db1005abeafe3927efda2bc5b249e80437ec`,
  verified against Node's `SHASUMS256.txt`.
- .NET SDK 10.0.404 installed with Microsoft's
  [official installation script](https://learn.microsoft.com/dotnet/core/tools/dotnet-install-script).
  The minimal guest also needs `libicu74`.
- Host Volatility 3 2.28.2 with the MCPTrace source on `PYTHONPATH`.

Create a guest directory containing `validation/cross_runtime/node_fixture.mjs`,
its `package.json` and lock file, and the `dotnet/` project. Run `npm ci`,
`dotnet restore --locked-mode`, and `dotnet build -c Release --no-restore`
there. The host also needs a QMP socket, SSH forwarding to the guest, a
temporary SSH key, the matching ISF, and writable cache/output directories.
Then run from the repository root:

```sh
PYTHONPATH=. python3 validation/linux_x64_http_ram/run.py \
  --qmp <qmp-socket> --ssh-key <temporary-private-key> \
  --known-hosts <temporary-known-hosts> \
  --guest-fixture <guest-fixture-dir> --guest-node <guest-node-binary> \
  --guest-dotnet <guest-dotnet-binary> \
  --guest-dotnet-client <guest-built-Client.dll> \
  --guest-runs <guest-runs-dir> --vol <host-vol-executable> \
  --symbols <host-symbol-dir> --cache <host-cache-dir> \
  --output <host-output-dir> --cases node dotnet-legacy dotnet-modern \
  --delays 0 5 30 --repetitions 3
```

The delays begin when the host detects the client's readiness file, not at the
exact end of the last call. Each per-run score records an upper bound from
client launch to detection. Each capture starts a fresh client; the guest VM
is reused. The runner deletes each RAM image after scoring, so multi-GiB dumps
do not accumulate. Raw RAM, traffic logs, exported message bytes, and temporary
SSH material stay outside the repository. Only content-minimized numeric
results are committed.

## Measured result (2026-11-14)

| Client | Captures | Transmitted messages | Exact wire payloads in client RAM | Logical messages carved | Confirmed scan misses |
| --- | ---: | ---: | ---: | ---: | ---: |
| Node 22 / SDK 1.32.1, HTTP with SSE responses | 9 | 117 | 117 | 117 | 0 |
| .NET 10 / SDK 2.3.1, protocol 2025-11-25 | 9 | 117 | 66 | 66 | 0 |
| .NET 10 / SDK 2.3.1, protocol 2026-07-28 | 9 | 108 | 70 | 70 | 0 |
| **Total** | **27** | **342** | **253** | **253** | **0** |

Each client was captured three times at each 0, 5, and 30 second delay after
host readiness detection. The Node server delivered 54 responses as SSE events
across nine runs. In the .NET cases, 108 wire payloads also existed as exact
UTF-16LE text; all of these messages were already counted among the 253 with
UTF-8 copies, so they are not additional distinct messages. The 253 logical
messages produced 655 artifact records at different virtual addresses. Every
record was reread byte-for-byte at its exported address, and none was
semantically unmatched to the server's traffic log. No run reported a scan
limit or candidate backtracking limit hit. The independent wire probe and
MCPTrace both read 55.5–101.2 MB of resident client VMA bytes per run;
inaccessible portions of large sparse VMAs were reported separately.

The other 89 transmitted messages did not have their **exact wire payload** in
the readable client VMAs at acquisition time. Their absence does not prove
that no differently serialized or partial copy existed. The host's readiness
poll gave client-launch-to-detection upper bounds of 2.83–6.94 seconds; the
nominal 0-second captures were therefore not synchronized to the exact final
call. The test reuses one VM with fresh client processes and one synthetic
server fixture, so it does not estimate general recovery or false-negative
rates. The .NET peer does not validate interoperability with an official C#
server. See the [machine-readable numeric result](results/2026-11-14-qemu-http-sdk.json)
for each RAM image hash, capture delay, wire count, and scan summary.

An exact wire payload absent from readable client memory is **not** a
confirmed scanner miss. Normal SDK objects may retain the same logical message
in another serialization. A carved memory object alone does not establish
transmission or tool execution; the separate server log is the transmission
ground truth in this fixture.
