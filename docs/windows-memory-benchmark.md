# Windows RAM benchmark

Measured on 2026-10-27 with MCPTrace 0.2.0 at commit
`d59f51e118480cb3be08ef96b04f94d8328bcc89`.
[Actions run](https://github.com/Kowntaewook/MCPTrace/actions/runs/40472181802).

Three fresh Windows Server 2022 jobs each ran two independent MCP SDK stdio sessions:
one with ground-truth logging but no retained-frame list (`natural`), and one with
the same logging plus an explicit retained-frame list (`retained`). Each session
completed 64 echo tool calls and logged 133 distinct logical messages, including
initialization, notification, and tool discovery. One deliberately unsent JSON
control was held in each retained client. No messages were injected into RAM images.

The eight payload patterns include ASCII, Korean/emoji, quotes/backslashes/newlines,
a 2 KiB string, repeated text with distinct sequence numbers, and whitespace. This
is a bounded SDK fixture, not a sample of real users' conversations or attacks.

## Recovery

| Capture | Condition | Messages / 133 | Tool pairs / 64 | Best same-PID pairs | Exported records |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | natural | 66 | 21 | 14 | 173 |
| 1 | retained | 133 | 64 | 64 | 299 |
| 2 | natural | 58 | 19 | 14 | 150 |
| 2 | retained | 133 | 64 | 64 | 273 |
| 3 | natural | 55 | 15 | 12 | 162 |
| 3 | retained | 133 | 64 | 64 | 282 |

| Condition | Pooled messages | Mean messages (range) | Pooled tool pairs | Mean tool pairs (range) |
| --- | ---: | ---: | ---: | ---: |
| natural | 179/399 (44.9%) | 59.7 (55-66) | 55/192 | 18.3 (15-21) |
| retained | 399/399 (100.0%) | 133.0 (133-133) | 192/192 | 64.0 (64-64) |

**Captures 2 and 3 are `completed_with_limits`: one process in each reported 4 and 3
candidate-backtracking limit events, respectively. Capture 1 had no limit events.
The means and pooled counts include all three captures; limited results were not discarded.**
These counters are search events, not a count of distinct missing messages. The aggregate
does not identify which mode contained the limited process, so the events are not attributed
to either mode. No process-read errors, skipped targets, invalid regions, anchor limits,
record budgets, or byte budgets were observed.

Message and pair counts combine both endpoints within one capture and deduplicate
logical messages. Matching normalizes parsed JSON objects; incoming SDK ground truth
is reserialized, not a byte-for-byte pipe capture. Exported raw bytes are separately
verified against the memory image. Same-image scan repeats are not additional recovery observations.
There are three independent observations per mode: 399 expected messages and 192
expected tool-call pairs in total. A pair counted in the endpoint union may have
its request and response in different processes. Per-capture best same-PID pair
counts remain available in the aggregate JSON.

All **1,339 exported records / 562,402 bytes** passed native
address/length/SHA-256/VAD-bound checks. Repeat scans produced byte-identical JSONL for
each image. The RAM hash remained unchanged and deletion completed for all captures.
The three retained runs recovered all three deliberately unsent controls. Across
2,480 evaluable directional candidate links, incorrect and unverifiable links were
both zero. All remaining exported records matched the logged fixture messages;
there were no unmatched records in this small controlled set.

Unsent controls are not traffic. Unmatched artifacts are not automatically labeled
false positives. Known directional candidate-link comparisons include duplicate
memory copies and are not a count of unique tool calls or proven sessions.

## Runtime and scan scope

| Capture | CLI scan 1 (s) | Scan 2 (s) | Scan 3 (s) | VADs | Read MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 54.121 | 54.476 | 53.954 | 576 | 184.09 |
| 2 | 54.380 | 53.883 | 54.171 | 576 | 211.58 |
| 3 | 53.803 | 53.360 | 53.318 | 576 | 201.85 |

Across nine scans: mean **53.94 s**, median **53.95 s**, range
**53.32-54.48 s**. Per-capture scan medians are
54.12 s, 54.17 s, 53.36 s. These nine scans are nested within three images,
not nine independent acquisition experiments.

| Capture | Acquisition (s) | Symbols/info (s) | Native verification (s) | Full pipeline (s) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 39.56 | 117.41 | 10.38 | 427.56 |
| 2 | 38.53 | 116.74 | 11.41 | 428.10 |
| 3 | 39.40 | 178.97 | 10.35 | 487.87 |

Each of the three images was scanned three times by separate CLI processes using
the same symbol cache, four endpoint PIDs, and default plugin limits. Any exhausted
search limit is retained in the counters and
marked `completed_with_limits`, never presented as a complete scan. Timing includes
startup, Volatility automagic, selected-process scanning, JSON rendering, and JSONL
export. Acquisition, initial symbol preparation, output comparison, image hashing,
and native byte verification are excluded from CLI timing. Acquisition, initial
symbol preparation, and native verification have their own reported durations.
The image was hashed and inspected before the first scan. These are not cold-cache
or full-image/all-process throughput measurements.

All three runners reported `Windows-2022Server-10.0.20348-SP0`, 4 logical CPUs,
17,174,360,064 bytes of physical RAM (approximately 16 GiB), Python
`3.12.10`, MCP SDK `1.26.0`, and Volatility `2.28.2`.
Each sparse image had a logical size of 20,401,094,656 bytes. The
image includes physical-address holes; this is not the size of scanned process data.
Workload-ready to capture-start delay was 0.054-0.093 s.
These are shared hosted runners, not a dedicated hardware performance guarantee.

## Reproduction and evidence

The [benchmark procedure](../validation/windows_positive/BENCHMARK.md) documents the
fixed sample size, workload, commands, and interpretation. The
[workflow](../.github/workflows/windows-memory-benchmark.yml) runs the three fresh
VM captures on demand. The machine-readable result is
[windows-memory-benchmark-2026-10-27.json](benchmarks/windows-memory-benchmark-2026-10-27.json).

Only allowlisted measurement counts, timings, version/environment information,
image hashes, and validation flags are published. Full RAM images and message
contents are not included. RAM was deleted after analysis, so reproduction means
running the capture harness again rather than reanalyzing these exact images.
The aggregate rejects missing/failed captures, duplicate image hashes, and mismatched
source versions or workload settings. No failed run is silently dropped.

## Initial attempt and counter correction

The [initial three-capture attempt](https://github.com/Kowntaewook/MCPTrace/actions/runs/40470688699)
at commit `b4524239bd2c1be12b4c83803fd76908e5a3f833` failed its incomplete-scan gate.
Per-process limit diagnostics were not preserved in that first aggregate, so the
exact gate inputs for those images cannot be reconstructed from the published files.
No recovery or timing values from that failed attempt are included in the final
three-capture measurement.

A local reproduction using all 133 SDK messages exposed premature limit accounting:
all 133 messages were found, yet 228 candidate-limit events were reported. The
counter incremented when the preceding window contained more than 64 object starts,
even if a valid message was found before search exhaustion. The counter now increments
only when that bounded search fails without examining the older candidates. Search
bounds and extraction logic remain unchanged. UTF-8/UTF-16LE regression cases verify
the correction, and the existing truly exhausted-backtrack test still passes.

The harness now preserves diagnostics before evaluating limits. Benchmark mode can
measure default-limit output with an explicit `completed_with_limits` status and
published limit counters; read errors or missing endpoints still fail. Strict
positive validation continues rejecting limited scans by default. All three fresh
VM captures were rerun at the corrected commit; they are not selectively chosen
successful members of the original attempt.

The 135-test suite and Ruff checks passed. The existing public Linux MCP sample was
also rescanned after the counter correction: both JSONL exports were byte-identical
to the earlier result, retaining all 41 records. This is a regression check, not an
independent Linux recovery benchmark; the sample's inferred physical-layout caveat
remains as described in [the Linux validation report](real-memory-validation.md).

## Limits

These statistics describe three captures of one Python SDK/stdin-stdout fixture.
Ground-truth logging changes memory, and explicitly retained frames are a favorable
control. Memory acquisition takes time; it is not an atomic snapshot. No deliberate
post-call delay or extra memory-pressure workload was introduced. Results may vary
with residency, acquisition, workload, and runtime state; this experiment does not
separate those causes.

This benchmark does not establish general recall/precision, attack detection,
Windows 11 or Linux performance, other client/SDK compatibility, HTTP/SSE support,
or survival over longer collection delays. The earlier
[8-call positive validation](windows-positive-memory-validation.md) used a different
workload size and should not be compared as a controlled before/after experiment.
