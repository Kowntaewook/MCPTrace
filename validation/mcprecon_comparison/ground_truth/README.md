# Public synthetic wire ground truth for the 27-image comparison

The 27 `traffic/*.jsonl` files are **byte-for-byte copies** of the independent
server's original JSON-body journals from the preserved Node/.NET HTTP/SSE
experiment. They contain 342 transmitted JSON-RPC messages. Each line has the
direction, framing (`json` or SSE `data:`), parsed message, and base64 of the
**exact JSON body bytes**. SSE framing bytes are not part of `wire_base64`.
`manifest.json` gives the capture ID, image SHA-256, client PID, message count,
and original traffic-log SHA-256. The traffic hashes match the previously
published [27-capture manifest](../../linux_x64_http_ram/results/2026-11-14-qemu-http-sdk-rerun.json).

These are synthetic `echo_marker` calls, not user conversations. Before copying,
[`prepare_truth.py`](../prepare_truth.py) checked all 342 decoded wire bodies
against their parsed messages, the saved traffic hashes, a fixed field/string
allowlist, and run-specific synthetic marker patterns. The reviewed bodies
contained no personal email, local user path, credential, or private key, and
their only URL is the public JSON Schema draft-07 identifier. The publication
review applies to **these exact traffic logs**; it does not clear raw RAM,
scanner exports, or later capture journals for release.

## Recompute from the released RAM

1. Get the 27 image assets from the
   [research evidence release](https://github.com/Kowntaewook/MCPTrace/releases/tag/evidence-http-ram-2026-11-14).
   Reconstruct an image according to
   [`linux_x64_http_ram`](../../linux_x64_http_ram/README.md). Its SHA-256 must
   match this directory's `manifest.json`. Retain the base image while
   rebuilding patch images. Process one image at a time to limit disk use.
2. Use the pinned MCPTrace source in this repository, Volatility 3 2.28.2,
   the matching Linux ISF listed in the HTTP-RAM guide, and the
   [MCPRecon CLI at commit `4811d04`](https://github.com/BiTLab-BaggiliTruthLab/MCPRecon/tree/4811d04e6c6a522759ade5e2f3fef37d33c6c27e).
   The replay verifies MCPRecon's source Git blob and the image/ISF hashes.
3. Audit the public truth, then run one image. Use private scratch directories:

```sh
PYTHONPATH=. .venv/bin/python validation/mcprecon_comparison/replay_public.py audit

PYTHONPATH=. .venv/bin/python validation/mcprecon_comparison/replay_public.py run \
  --run-id node-d0-r1 --image /PRIVATE/node-d0-r1-ram.elf \
  --symbols /PRIVATE/symbols --cache /PRIVATE/cache \
  --vol .venv/bin/vol --mcprecon /PRIVATE/mcprecon.py \
  --work-dir /PRIVATE/replay-work \
  --report /PRIVATE/reports/node-d0-r1.json
```

Repeat `run` for each manifest ID and its matching image, then aggregate:

```sh
PYTHONPATH=. .venv/bin/python validation/mcprecon_comparison/replay_public.py aggregate \
  --reports /PRIVATE/reports --report /PRIVATE/replayed-totals.json
```

For a serial replay of all 27 assets, use the wrapper below. It verifies each
asset against the published archive digest, verifies each reconstructed image,
and retains only numeric JSON reports. It streams the compressed base into
each patch reconstruction, so the base and a later raw image do not have to
coexist on disk. Valid reports are reused if the process is interrupted. The
asset directory must contain the downloaded base `.zst` and all 26
`.patch.tar` files.

```sh
PYTHONPATH=. .venv/bin/python validation/mcprecon_comparison/replay_all_public.py \
  --assets /PRIVATE/release-assets --symbols /PRIVATE/symbols \
  --cache /PRIVATE/cache --vol .venv/bin/vol \
  --mcprecon /PRIVATE/mcprecon.py --reports /PRIVATE/reports \
  --scratch /PRIVATE/replay-scratch
```

The `run` command scans the original image with MCPTrace for the published
client PID, independently probes exact UTF-8/UTF-16LE wire-byte presence in
that process, verifies each MCPTrace artifact at its virtual address, and
packs the same readable VMA bytes for MCPRecon. It verifies each MCPRecon
record at its packed-stream offset. The derived stream inserts NUL separators
at VMA gaps; this is a controlled **client-byte** comparison, not MCPRecon's
native whole-image workflow. Temporary raw exports and packed bytes are removed
after scoring; the report contains counts and hashes only.

Across the 27 captures, the expected audit totals are 342 sent, 251 with exact
wire bytes in readable client memory, 251 carved by MCPTrace, and 184 carved by
MCPRecon's default CLI on the derived client stream. The two scanners' MCP
labels are separate measurements: 233 and 94 logged messages, respectively.
These conditional fixture counts are not field detection rates. A message not
found as exact wire bytes might persist in a different serialization.
