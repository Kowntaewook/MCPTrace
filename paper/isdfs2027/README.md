# ISDFS 2027 manuscript draft

`mcptrace_isdfs2027.tex` is an English IEEE conference draft by Taewook Kwon,
Gyeongbuk Software Meister High School. It is **not submitted**. The current
compiled PDF is five US-letter pages in IEEEtran's 10-point conference format.

The comparison uses the pinned public MCPRecon CLI, 27 archived Linux physical
RAM captures, four preserved non-MCP process captures, and constructed protocol
cases. Numeric reports and reproduction notes are in
[`validation/mcprecon_comparison`](../../validation/mcprecon_comparison/README.md).
The external traffic logs and raw memory images are separate evidence; readers
cannot independently recompute every truth match from this repository alone.

Compile with Tectonic and inspect the resulting pages before submission:

```sh
tectonic --outdir output/pdf paper/isdfs2027/mcptrace_isdfs2027.tex
```

Before submission, review all claims and references, obtain any required
author or school approval, check the current ISDFS instructions, and consider
publishing a sanitized truth manifest that permits independent rescoring.
