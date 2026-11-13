# Local Linux x86-64 RAM positive control

This experiment runs a purpose-built Python client and server in a QEMU Ubuntu
x86-64 guest. They exchange newline-delimited MCP-shaped JSON-RPC over stdio;
the client retains exact sent and received bytes and one deliberately unsent
control. The Mac host captures **physical guest RAM** with QEMU QMP, then runs
Volatility 3 and MCPTrace on the ELF dump. No Windows PC or GitHub Actions are
needed. This is a deliberately easy retained-message positive case, not an
official MCP SDK interoperability test.

## Reproduction inputs

- Ubuntu Minimal 24.04 AMD64 [daily image dated 2026-11-07](https://cloud-images.ubuntu.com/minimal/daily/noble/20261107/noble-minimal-cloudimg-amd64.img), SHA-256 `af34b3230db47ac2159b500adaef438b5cb4da875139997b8797f9643e1743d3`.
- QEMU 11.1.3 with a 1536 MiB guest, 2 vCPUs, virtio disk/network, and
  **`-cpu max,-la57`**. The `-la57` flag matters: with QEMU's default `max`
  CPU, this kernel enabled five-level paging and Volatility 2.28.2's
  `linux.pslist` returned no processes on the acquired image.
- The image initially booted kernel `6.8.0-149-generic`. The guest installed
  Ubuntu's official `linux-image-6.8.0-146-generic` and
  `linux-modules-6.8.0-146-generic` packages, both revision `6.8.0-146.146`,
  then booted that kernel. This build has a matching [community-generated
  Volatility ISF](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/Ubuntu/amd64/6.8.0/146/generic/Ubuntu_6.8.0-146-generic_6.8.0-146.146_amd64.json.xz).
  The ISF SHA-256 is `18dd41722ad7d3b411d442065e6fafa3c177960e3e19ea484b391dfb1526e55b`.
  Volatility's identified banner matched the guest's active kernel build.
- Python 3.13 on the Mac host with pinned `volatility3==2.28.2` and the
  repository source on `PYTHONPATH`.

The VM used a cloud-init NoCloud seed ISO with a temporary SSH key. The seed,
private key, guest disk, RAM image, raw JSONL, and full ground truth stay outside
the repository. Use a new key and seed for a rerun. The QEMU command must
include `-qmp unix:<socket>,server=on,wait=off` so the capture script can pause
the VM. Acquire after `workload.py --ready <path>` has written its readiness
file. The script keeps the client and server alive until stopped.

## Analysis commands

Run from the repository root with a virtual environment containing MCPTrace:

```sh
python3 validation/linux_x64_positive/capture_qmp.py \
  --socket <qmp-socket> --output <ram.elf>

vol --cache-path <writable-cache-dir> -s <symbols-dir> \
  -f <ram.elf> linux.pslist.PsList

PYTHONPATH=. vol --cache-path <writable-cache-dir> -s <symbols-dir> \
  -p plugins -f <ram.elf> -o <exports-dir> \
  --save-config <config.json> linux.mcptrace.MCPTrace \
  --pid <client-pid> <server-pid> --dump
```

Repeat the final scan on the **same image** with another output directory.
Use `score.py` with the image, ISF directory, writable cache, saved config,
readiness/ground-truth JSON, both exports, both repeat exports, and a report
path. It compares the exact controlled messages, rejects a PID/image mismatch,
checks repeated export equality, and independently rereads every artifact at
its exported process virtual address within the reported VMA. Do not publish
the raw image or JSONL from a real case.

The [measured numeric report](results/2026-11-13-qemu-ubuntu.json) records the
QEMU capture SHA-256, kernel banner, source hashes, findings, and scan limits.
The default 64 KiB object bound produced two candidate backtracking limit hits
in the client, despite recovering all controls. A same-image rerun with
`--max-object-bytes 4096` produced **the same 62 `(virtual_address,
raw_sha256)` artifacts** and zero candidate limit hits. The smaller bound is
only suitable for messages below that size; it is not a general default.
