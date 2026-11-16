# Reviewer handoff for 20 independent Linux full-RAM repeats

This guide covers the **20 planned** images in the two-phase Inspector,
Codex CLI, LSP, and ordinary JSON-RPC experiment. The exploratory Inspector
HTTP timing pilot is excluded. The [reviewer manifest](reviewer_manifest.json)
lists each run's case, timing, PID, private archive slot and relative path,
compressed and restored hashes and lengths, public report, and traffic hash.
It contains no RAM or original Codex wire bytes.

## Files needed

The reviewer checks out this research branch with the pinned scanner source
(`ded4c00235f5c41222f72e8529f3dbd617bc3c9f` for `mcptrace/` and
`plugins/`) and installs Volatility 3 **2.28.2** plus this project's Python
dependencies. The guest kernel was Ubuntu 6.8.0-146-generic; supply its
matching Linux ISF in the Volatility symbol directory, or rebuild it as
described in the [original Linux RAM method](../../linux_x64_real_host_ram/README.md).

The restricted evidence handoff needs exactly:

- Ten `ram.elf.zst` files under a first capture root, with one subdirectory
  named for each `initial` run ID in the manifest.
- Ten `ram.elf.zst` files under a second capture root, with one subdirectory
  named for each `second` run ID.
- The original `traffic.jsonl` in each of the **four Codex** run directories.

The **16 non-Codex** journals are already public under [`traffic/`](traffic/).
No original scanner export, VM disk, SSH key, or original non-Codex private
journal is required to rerun the 20 image-level scores. The twenty compressed
archives total 4,759,544,561 bytes (about 4.43 GiB). Keep at least 2 GiB of
additional scratch space for one restored image and scanner output; 8 GiB
free is a practical minimum if copying all archives into a new location.

## Independent replay

With the two private capture roots available locally, run from the repository
root:

```sh
PYTHONPATH=. .venv/bin/python \
  validation/linux_x64_repeat/ground_truth/replay_all.py \
  --first-captures /PRIVATE/first/captures \
  --second-captures /PRIVATE/second/captures \
  --symbols /PRIVATE/symbols --cache /PRIVATE/vol-cache \
  --vol .venv/bin/vol --scratch /PRIVATE/scratch \
  --checkpoint /PRIVATE/replay-progress.json \
  --output /PRIVATE/replay-result.json
```

`--checkpoint` stores only numeric/hash progress in the private area after
each verified image. Rerunning the same command checks the checkpoint against
the public reports and resumes unfinished images. For a one-image check, add
`--run-id inspector-http-r2-fast` and omit `--checkpoint`; this produces
`complete_primary_replay: false`. Omit `--run-id` for the full claim. The script
checks each original archive against its public digest and size, streams a
fresh ELF reconstruction, checks the original traffic byte hashes, launches a
new Volatility MCPTrace scan on the recorded client PID, probes exact UTF-8
and UTF-16LE presence in readable client memory, rereads every exported
artifact at its virtual address, and compares **every measured field and
per-message flag** with the published report. A fresh temporary image and
scanner export are deleted after each run. Only numeric and hash results are
written to `--output`.

The full result should say `complete_primary_replay: true`,
`replayed_images: 20`, and `all_scores_match: true`, with totals of **116
logged, 90 exact-wire-present, 90 carved, 68 MCP-labeled, and 264 exported
artifact records**. A differing field causes the script to stop without
writing a complete result. The author-run result is linked from the [experiment
README](../README.md); a reviewer must run the command independently to make
an independent-reproduction claim.

## Access boundary

The RAM archives may contain temporary VM key material and other process
state. The original Codex journals contain runtime session, turn, and window
identifiers. They are **not public**. Before granting access to a named
reviewer, inspect the non-MCP contents and agree on a private transfer or
supervised execution method, who may retain a copy, and when it will be
deleted. Those recipient-specific arrangements are not yet made. The public
manifest and this guide do not authorize uploading or sending the private
files. The earlier six live-host images have a [separate reviewer guide](../../linux_x64_real_host_ram/ground_truth/README.md).
