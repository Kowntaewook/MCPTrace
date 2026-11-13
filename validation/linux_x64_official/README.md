# Official SDK Linux x86-64 RAM experiment

This local experiment runs `mcp==1.26.0` in a QEMU Ubuntu x86-64 guest. The
official Python SDK client connects to an official `FastMCP` stdio server and
completes initialization, tool discovery, and four tool calls. The client keeps
no deliberate message or frame journal. A **separate proxy process** forwards
the actual newline-delimited bytes and records them as ground truth. Only the
SDK client PID is scanned in physical guest RAM.

The host acquires a separate RAM image at 0, 5, and 30 seconds **after it
detects the workload readiness file**, with three fresh client processes per
delay. The readiness poll adds unmeasured latency; each per-run report records
an upper bound from client launch to detection. Each image
is analyzed with Volatility 3 and MCPTrace. `score.py` checks that every exported
artifact can be reread at its reported virtual address, then independently
looks for each exact UTF-8 and UTF-16LE wire payload across readable client
VMAs. An exact payload present in RAM but absent from MCPTrace output is a
confirmed scan miss for this fixture. An absent exact wire payload does not
rule out other serialized copies or partial messages.

## Inputs

- Ubuntu Minimal 24.04 AMD64 [2026-11-07 image](https://cloud-images.ubuntu.com/minimal/daily/noble/20261107/noble-minimal-cloudimg-amd64.img), SHA-256 `af34b3230db47ac2159b500adaef438b5cb4da875139997b8797f9643e1743d3`.
- QEMU 11.1.3, 1536 MiB guest, two vCPUs, `q35`, TCG, virtio disk and network,
  and `-cpu max,-la57`. The `-la57` setting prevents five-level paging, which
  did not work with this Volatility setup in the earlier [positive control](../linux_x64_positive/README.md).
- Ubuntu `linux-image-6.8.0-146-generic` and
  `linux-modules-6.8.0-146-generic`, revision `6.8.0-146.146`, installed from
  `archive.ubuntu.com` and booted. Matching [community Volatility ISF](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/Ubuntu/amd64/6.8.0/146/generic/Ubuntu_6.8.0-146-generic_6.8.0-146.146_amd64.json.xz), SHA-256 `18dd41722ad7d3b411d442065e6fafa3c177960e3e19ea484b391dfb1526e55b`.
- Guest Python 3.12 with `mcp==1.26.0`; host Volatility 3 2.28.2.

The guest uses a cloud-init NoCloud seed ISO with a newly generated SSH key.
Copy `client.py`, `proxy.py`, and `server.py` to one guest directory. Install
`mcp==1.26.0` in a guest virtual environment, and create a writable guest runs
directory. Start QEMU with a QMP Unix socket and SSH port forwarding. The
capture script requires the guest's Python, fixture, and runs paths, plus the
host's Volatility executable, symbol directory, cache, and output paths:

```sh
PYTHONPATH=. python3 validation/linux_x64_official/run.py \
  --qmp <qmp-socket> --ssh-key <temporary-private-key> \
  --known-hosts <temporary-known-hosts> \
  --guest-fixture <guest-fixture-dir> --guest-python <guest-venv-python> \
  --guest-runs <guest-runs-dir> --vol <host-vol-executable> \
  --symbols <host-symbol-dir> --cache <host-cache-dir> \
  --output <host-output-dir> --delays 0 5 30 --repetitions 3
```

The script pauses the guest for each QMP `dump-guest-memory` capture and
resumes it immediately afterward. It deletes each 1.5 GiB RAM image after
scoring; raw wire logs, memory exports, and temporary SSH material stay outside
the repository.

## Measured result (2026-11-14)

| Delay after host readiness detection | Captures | Transmitted wire messages | Exact UTF-8 wire payloads in client RAM | Logical messages carved | Confirmed scan misses |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0 s | 3 | 39 | 11 | 11 | 0 |
| 5 s | 3 | 39 | 11 | 11 | 0 |
| 30 s | 3 | 39 | 10 | 10 | 0 |
| **Total** | **9** | **117** | **32** | **32** | **0** |

The 32 carved messages produced 50 artifact records because some existed at
multiple memory addresses. All 50 records were reread at their reported
virtual addresses, and none contained an unlogged logical message. Each scan
reported 8.0–9.1 MB of unreadable VMA bytes but no candidate or global scan
limit hit. No exact UTF-16LE wire payload was present in this Python client
fixture. The other 85 transmitted messages had no **exact wire payload** in
the readable client VMAs at capture time; this does not establish that every
representation of those messages was absent or that MCPTrace would miss them
if present. There was no client-side frame journal, but normal SDK and Python
objects could retain copies.

The host detected the readiness file 6.15–7.53 seconds after client launch;
these are upper bounds on readiness-to-detection latency. Thus the nominal
0-second group is not a capture at the exact end of the last call. All three
delay groups reused one VM but started fresh client processes. This small
controlled fixture cannot establish a general recovery rate or a time-decay
curve. See the [machine-readable numeric result](results/2026-11-14-qemu-ubuntu-sdk.json)
for every capture hash, timing, and scan count. Recovered memory objects alone
cannot prove transmission or tool execution; the separate proxy log provides
transmission ground truth in this experiment.
