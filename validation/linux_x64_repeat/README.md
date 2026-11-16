# Independent-process Linux live-host RAM repeats

This 2026-11-16 follow-up adds **10 primary full-RAM captures**: one early and
one at least 90-second delayed capture for each of five cases. Each capture
uses a fresh client PID and a new exchange in the same reused Ubuntu x86-64
QEMU VM. A separate Inspector HTTP timing pilot is retained but excluded from
the primary totals. The hosts are MCP Inspector `mcpdo` 2.15.0 over HTTP and
stdio and Codex CLI 0.159.3 over stdio; non-MCP controls are LSP and ordinary
JSON-RPC TCP clients. The model response for Codex is a deterministic local
fixture, not an external model or ordinary agent workload.

## Observed results

Each cell after the age is **sent / exact wire present in readable client
VMAs / carved / MCP-labeled**. Age is the guest-side completion marker's file
mtime measured just before QMP stop; it is not the exact time between the last
network byte and the RAM snapshot.

| Client | Early image, age and counts | Delayed image, age and counts |
| --- | --- | --- |
| Inspector HTTP/SSE | 18.340 s; 9 / 9 / 9 / 8 | 101.209 s; 9 / 4 / 4 / 3 |
| Inspector stdio | 1.251 s; 9 / 9 / 9 / 8 | 103.534 s; 9 / 5 / 5 / 5 |
| LSP TCP control | 1.289 s; 2 / 2 / 2 / 0 | 93.333 s; 2 / 2 / 2 / 0 |
| Ordinary JSON-RPC TCP control | 1.295 s; 2 / 2 / 2 / 0 | 103.838 s; 2 / 2 / 2 / 0 |
| Codex CLI stdio | 1.603 s; 7 / 5 / 5 / 5 | 93.526 s; 7 / 5 / 5 / 5 |

Across the **10 primary images**, 58 separately logged message observations
had 45 exact wire bodies in the selected clients' readable VMAs. All 45
logical messages were carved; 34 had an MCP-labeled copy. The six MCP-host
images account for 50 sent, 37 present, 37 carved, and 34 MCP-labeled. Four
control images account for eight sent, eight present, eight carved, and **zero
MCP labels**. All 141 artifact records were reread at their reported process
virtual addresses. Every archive and restored image matched its published
hash; traffic was unchanged during capture, and there were no confirmed scan
misses, unmatched artifact records, or scan-limit hits. The [numeric summary](results/2026-11-16-repeat-summary.json)
contains each image's PID, hashes, timing, and counts.

An exploratory [Inspector HTTP pilot](results/2026-11-16-inspector-http-r1-delayed.json)
was captured 97.211 seconds after its completion marker: 9 sent, 4 present,
4 carved, and 3 MCP-labeled. It was run while the orchestration was being
checked, so its result is **not** in the 10-image primary totals. The early
Inspector HTTP/stdio snapshots retained more exact wire bodies than their
separate delayed-process snapshots. Because these are different processes and
exchanges, this observation does not isolate elapsed time as the cause. The
same valid legacy `initialize` response shape was carved but not MCP-labeled
in each HTTP image and the early stdio image. The controls produced no MCP
labels in these specific snapshots; neither result estimates a field error
rate.

## Acquisition and verification

The guest booted Ubuntu Minimal 24.04 with kernel 6.8.0-146-generic and the
matching Volatility Linux ISF documented in the [original physical-RAM
experiment](../linux_x64_real_host_ram/README.md). It used a fresh QCOW2
overlay backed by the preserved Codex guest disk, QEMU 11.1.3 `q35`/TCG, two
vCPUs, 1024 MiB RAM, `-cpu max,-la57`, virtio disk/network, and a QMP Unix
socket. The installed Node 22.23.4, SDK 1.32.1 fixture, Inspector 2.15.0,
and Codex CLI 0.159.3 were reused. Volatility 3 was 2.28.2; the `mcptrace/`
and `plugins/` scanner source matches commit
`ded4c00235f5c41222f72e8529f3dbd617bc3c9f`. All new Inspector runs use
memory-only credential storage; no external account sign-in was involved.
The guest disk, temporary SSH material, raw traffic, and all RAM archives
remain private.

[`guest_case.sh`](guest_case.sh) starts one real host or TCP control in its own
guest run directory, records exact messages from an independent peer/proxy,
and leaves the client alive. Inspector starts a fresh daemon and Codex uses a
fresh `CODEX_HOME` per run. [`run_case.py`](run_case.py) transfers that script,
waits for the planned early or delayed condition, runs the existing
[`capture.py`](../linux_x64_real_host_ram/capture.py) QMP/Volatility/score
pipeline, adds timing metadata, and then stops that client. The marker file
age is measured on the same guest clock immediately before QMP stop. The
scorer separately verifies each JSON body's UTF-8/UTF-16LE exact presence,
logical carving, MCP label, and byte export at its process virtual address.

Example, with a separately booted guest, private key, socket, symbols, and
scratch location:

```sh
PYTHONPATH=. .venv/bin/python validation/linux_x64_repeat/run_case.py \
  --case inspector-stdio --run-id inspector-stdio-r1-fast \
  --marker RPT_STDIO_A_20261116 --min-age-seconds 0 \
  --private-root /PRIVATE/repeats --ssh-key /PRIVATE/guest-key \
  --known-hosts /PRIVATE/known_hosts --qmp /PRIVATE/qmp.sock \
  --symbols /PRIVATE/symbols --cache /PRIVATE/cache --vol .venv/bin/vol \
  --report validation/linux_x64_repeat/results/2026-11-16-inspector-stdio-r1-fast.json

PYTHONPATH=. .venv/bin/python validation/linux_x64_repeat/summarize.py \
  --private-root /PRIVATE/repeats
```

The example names describe the recorded run; a new replay must use a **new
run ID and output path** because the runner refuses to overwrite evidence.
[`summarize.py`](summarize.py) streams and re-hashes all 11 private compressed
archives and reconstructed ELF images, checks the retained journals and raw
exports against the public numeric reports, checks distinct PIDs and image
hashes, and verifies the primary/pilot grouping.

The [nine public non-Codex wire journals](ground_truth/README.md) contain 53
byte-identical synthetic JSON bodies, including the pilot. The two Codex
journals remain private because original wire messages include runtime
session/turn/window identifiers. All 11 full-RAM archives remain private;
public files alone cannot reproduce their image-level scores. Reviewer
transfer requires a separate restricted-access handoff, as in the [six-image
evidence guide](../linux_x64_real_host_ram/ground_truth/README.md).

## Interpretation boundary

These are controlled observations in one reused VM, two MCP host families,
one synthetic tool, two transports, and two planned time ranges. The guest
RAM size differs from the earlier 1536 MiB Inspector captures. The existing
Codex pilot's two images were of the same exchange; these two new Codex runs
are separate processes/exchanges. The results establish repeatability under
these conditions but do not estimate detection or false-positive rates across
apps, workloads, or real-world memory lifetimes. MCPRecon was not run on these
new images, so the 27-image 251-versus-184 comparison remains separate.
