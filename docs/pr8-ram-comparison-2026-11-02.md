# PR #8: Same-image Windows RAM regression and performance comparison

Date: 2026-11-02. [Workflow run](https://github.com/Kowntaewook/MCPTrace/actions/runs/41390552201).

Compared the pre-PR main commit `1c582831d2d237f185689b3544f4370c70abcd81`
with candidate commit `772909a0924112a71dd51145220adb6fd909ba2b`
on each of **three independently acquired Windows Server 2022 RAM images**.
The production code changes after this candidate benchmark were formatting and
benchmark documentation/workflow changes, not modifications to the MCP carver.

Each fresh Windows runner generated actual Python MCP SDK 1.26.0 traffic over
stdio, with 64 tool calls (133 logical messages) per natural/retained condition,
and acquired physical RAM via WinPmem. The two revisions analyzed the **same
unchanged image** on each runner. The paired scan order was baseline, candidate,
candidate, baseline after the existing positive scan and symbol setup.
Each version ran twice per capture. Both variants used Volatility 3 2.28.2.

## Exact-image recovery comparison

| Capture | Natural messages, baseline / PR (of 133) | Natural tool pairs, baseline / PR (of 64) | Retained messages, baseline / PR (of 133) | Records with identical PID/address/raw hash |
| --- | ---: | ---: | ---: | ---: |
| 1 | 65 / 65 | 21 / 21 | 133 / 133 | 464 |
| 2 | 61 / 61 | 13 / 13 | 133 / 133 | 456 |
| 3 | 34 / 34 | 7 / 7 | 133 / 133 | 371 |
| **Pooled** | **160 / 160 (of 399)** | **41 / 41 (of 192)** | **399 / 399 (of 399)** | **1,291** |

The candidate and baseline produced identical PID/address/raw SHA-256
fingerprint sets on every capture. All exported bytes were independently
re-read and verified against their native Volatility Windows process layers.
No incorrect candidate links or unmatched records were observed in this fixture.
Each capture had **one process with a candidate search-limit event** in both
variants. Limited scans were retained and not presented as exhaustive.

## Runtime and process memory

Each row below summarizes two timed runs for each variant on that same image.

| Capture | CLI time, baseline median (s) | CLI time, PR median (s) | Difference PR - baseline (s) | Peak working set median, baseline (MiB) | Peak working set median, PR (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 53.05 | 52.38 | -0.67 | 105.54 | 105.11 |
| 2 | 50.94 | 50.38 | -0.56 | 101.71 | 102.25 |
| 3 | 38.73 | 39.57 | +0.85 | 104.66 | 106.08 |
| **All six runs median** | **50.94** | **50.38** | **-0.56** | **104.66** | **104.92** |

The measured runtime differences change direction across captures; the
observed 0.56-second pooled median reduction is **not sufficient to establish
a reliable speed-up**. The small and inconsistent working-set differences
do not establish a memory improvement. The process peak working set
(`psutil.peak_wset`) is not private Python heap or system-wide RAM usage.

## Scope and interpretation

- Three independent memory acquisitions; **two repeated scans per revision on
  each image**. Repeats are timing samples, not independent recovery observations.
- The natural condition recovered **160/399 (40.1%)** messages and **41/192
  (21.4%)** tool-call pairs in each revision. The retained-frame condition
  recovered **399/399** messages and **192/192** tool pairs in each revision.
- This is a **controlled SDK/stdio fixture**, not general MCP recall, attack
  detection precision, or a benchmark of the 2026-07-28 SDK.
- The exact image used for each pair is identified by its recorded SHA-256;
  each ephemeral RAM image was hashed before/after analysis and deleted.
- Raw memory, recovered message contents, process identifiers, and file paths
  were not uploaded. The workflow publishes only allowlisted numeric metrics.
- Cache and shared-host variability remain possible despite the balanced
  ABBA scan order. The prior 2026-10-27 benchmark used **different images**
  and must not be treated as a controlled before/after comparison.

## Reproduction

The manual [paired comparison workflow](../.github/workflows/pr-ram-comparison.yml)
uses the existing [Windows positive-memory harness](../validation/windows_positive/run.py)
and [paired comparison module](../validation/windows_positive/compare_variants.py).

The fixed pre-PR baseline checkout, pinned MCP SDK, three fresh RAM acquisitions,
bounded scans, native byte verification, and cleanup are all part of the job.
The workflow uses manual dispatch to avoid automatically capturing RAM on every PR.
