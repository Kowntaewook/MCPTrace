# ISDFS 2027 manuscript draft

`mcptrace_isdfs2027.tex` is an English IEEE conference draft by Taewook Kwon,
Gyeongbuk Software Meister High School. It is **not submitted**. The current
compiled PDF is six US-letter pages in IEEEtran's 10-point conference format.

The comparison uses the pinned public MCPRecon CLI, 27 archived Linux physical
RAM captures, four preserved non-MCP process captures, and constructed protocol
cases. Numeric reports and reproduction notes are in
[`validation/mcprecon_comparison`](../../validation/mcprecon_comparison/README.md).
The pinned MCPTrace scan was rerun on all 27 reconstructed RAM images: all new
exports reproduced the archived exports byte-for-byte, and all 626 new artifact
records were reread at their reported process virtual addresses. The primary
251-versus-184 comparison counts carved JSON-RPC messages regardless of each
tool's MCP label; the label counts are reported separately.
An additional [four-image Linux physical-RAM experiment](../../validation/linux_x64_real_host_ram/README.md)
ran the packaged MCP Inspector host over HTTP and stdio with LSP and ordinary
JSON-RPC controls. Nine exact-wire-present Inspector messages were all carved;
eight received an MCP label. Both controls had zero MCP-labeled records. This
experiment is separate from the 27-image MCPRecon comparison.
The 27-image comparison has [public synthetic wire logs and a client-byte
replay procedure](../../validation/mcprecon_comparison/ground_truth/README.md)
in this public research branch, alongside the already released RAM archives.
The [27-image serial replay](../../validation/mcprecon_comparison/results/public_replay_2026-11-16/README.md)
reproduced the comparison counts. The separate four live-host/control RAM
images and their traffic journals remain private; readers cannot independently
recompute those four image-level truth matches from the public bundle.
The manuscript's [worked image-to-wire case](../../validation/mcprecon_comparison/ground_truth/worked_case_node_d30_r2.md)
uses one archived Node capture to distinguish a verified response artifact
from an exact-wire-absent request. The MCPRecon discussion acknowledges that
its published method already retains PID, VMA, and offset provenance; the
251-versus-184 figure is limited to its pinned public CLI on derived client
bytes.

Compile with Tectonic and inspect the resulting pages before submission:

```sh
tectonic --outdir output/pdf paper/isdfs2027/mcptrace_isdfs2027.tex
```

Before submission, review all claims and references, obtain any required
author or school approval, check the current ISDFS instructions, and request
an independent rerun of the published 27-image comparison when feasible.
