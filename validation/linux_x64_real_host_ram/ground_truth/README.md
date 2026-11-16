# Live-host Linux RAM evidence: truth and replay boundary

This directory maps the four Inspector/control captures and two Codex captures
to their original image, archive, traffic, export, and numeric-report hashes.
It does **not** contain a physical-RAM image. The [27-image MCPRecon comparison](../../mcprecon_comparison/ground_truth/README.md)
has a separate public RAM release and complete public wire truth.

## What a reader can check now

[`manifest.json`](manifest.json) identifies all six image hashes and public
reports. Exact, byte-identical external traffic journals for Inspector HTTP,
Inspector stdio, LSP, and ordinary JSON-RPC are in [`traffic/`](traffic/).
The manifest pins the scanner source commit and Volatility version used for
the original analysis. The four public journals contain 22 synthetic JSON
bodies: 18 MCP-host messages and four control
messages. `wire_base64` and `raw_base64` encode the original JSON bodies; SSE
`data:` and LSP `Content-Length` framing bytes are excluded. The source
journals were checked against the public per-message SHA-256 values and an
exact field/string allowlist before copying. No raw Volatility export or RAM
bytes were copied here.

The two Codex captures contain seven messages each, but they are **two
observations of one exchange in the same PID**, not 14 independent messages.
Their original stdio journals contain runtime session/turn/window IDs in
`params._meta`; they remain private. Their per-message hashes, direction,
method, and scoring flags are in the public [first](../../linux_x64_codex_ram/results/2026-11-16-codex-pilot.json)
and [later](../../linux_x64_codex_ram/results/2026-11-16-codex-delayed.json)
numeric reports. A redacted or reconstructed journal would no longer be the
exact wire bytes in those RAM captures, so this directory does not present
one as a full replay input.

The six raw RAM archives are private. The reused guest contains ephemeral SSH
host material, Inspector daemon state, and potentially other process state.
Publishing an unreviewed RAM image would disclose more than the synthetic
MCP traffic. Therefore, **no outside reader can yet independently recompute
these six image-level claims from public files alone**. The public wire logs
and hashes improve auditability but do not close that gap.

The author restored and rescanned all six original archives on 2026-11-16
using the replay command below. Image and journal hashes, every measured score
field, and each per-message presence/carving/classification flag matched the
published reports; the [numeric replay summary](replay_2026-11-16.json) records
the result. This is an author rerun, **not** independent external reproduction.

## Private verification and reviewer handoff

The original archives, journals, and scanner exports are retained under the
two private sibling evidence directories. [`prepare_public.py`](prepare_public.py)
checks all six journals and exports against the published reports, verifies
archive SHA-256 and restored ELF SHA-256 as a stream, and regenerates the four
safe public journals and manifest:

```sh
PYTHONPATH=. .venv/bin/python \
  validation/linux_x64_real_host_ram/ground_truth/prepare_public.py \
  --real-private ../MCPTrace-real-host-ram-private-2026-11-15 \
  --codex-private ../MCPTrace-codex-host-ram-private-2026-11-16 \
  --verify-archives
```

[`replay.py`](replay.py) accepts one **original** archive and the corresponding
traffic journal. It reconstructs the image in a private temporary directory,
runs the current MCPTrace source through Volatility, independently probes exact
UTF-8/UTF-16LE wire presence, verifies exported bytes at their process virtual
addresses, and compares its numeric result with the published per-image report.
It excludes only the scorer's changed prose `limitations` field from the
comparison. It deletes the temporary raw image and exports after the run. Example for an
Inspector case after a reviewer has legitimately obtained the original image:

```sh
PYTHONPATH=. .venv/bin/python \
  validation/linux_x64_real_host_ram/ground_truth/replay.py \
  --case inspector-http --archive /PRIVATE/http/ram.elf.zst \
  --symbols /PRIVATE/symbols --cache /PRIVATE/cache --vol .venv/bin/vol \
  --scratch /PRIVATE/scratch --output /PRIVATE/inspector-http-replayed.json
```

For a Codex case, use `--case codex-first` or `--case codex-later` and add
`--traffic /PRIVATE/traffic.jsonl`. The private journal is essential for exact
wire comparison. The reviewer also needs the matching [Linux kernel symbol
file](../README.md) and enough scratch space for one restored ELF image plus
at least 256 MiB (about 1.9 GiB for Inspector and 1.4 GiB for Codex). The
author reran all six sequentially after clearing disposable pip cache to
obtain scratch space. The original capture runs and their address checks are
also recorded in the linked numeric reports.

Before handing raw RAM to a person, review its non-MCP contents and agree on
a private transfer method and retention/deletion terms. A reviewer can instead
independently rerun the **fully public 27-image comparison** without receiving
these six private images. Neither route should be described as public
reproduction of these six image-level results until their original images and
all necessary truth are actually available to that reader.
