# Repeated Windows RAM benchmark

The benchmark uses three independently acquired Windows Server 2022 VM images.
Each VM runs two official Python MCP SDK stdio client/server pairs: `natural`
(ground-truth logging without a separate retained-frame list) and `retained`
(the same logging plus a retained-frame list and one deliberately unsent control).

Each pair completes 64 echo tool calls, cycling through the existing eight payload
patterns with a unique sequence and request ID. Initialization, notification, and
tool discovery bring the ground truth to 133 distinct logical messages per mode
per capture. The three-capture denominator is 399 messages and 192 tool-call pairs
per mode. These sample counts are fixed before execution.

Each capture is analyzed three times by separate MCPTrace CLI processes. All four
selected endpoint PIDs are scanned together. Exported JSONL must be byte-identical
across the three scans. One set of exports is independently re-read through native
Volatility Windows process layers to check bytes, SHA-256, addresses, and VAD bounds.
The original RAM image is hashed before and after analysis, then deleted.

CLI timing includes process startup, Volatility automagic, scanning, JSON rendering,
and JSONL export. It excludes acquisition, initial `windows.info`/symbol preparation,
export comparison, and native byte verification. The image has already been hashed
and inspected before the first scan; no scan is claimed to be a cold-cache result.
Repeated scans measure timing/repeatability, not additional independent recovery
samples. Runtime covers four selected processes, not all processes in the RAM image.

## Reproduce

Use a fresh administrative Windows VM for each replica. Install the repository and
`validation/windows_positive/requirements.txt`, then run from the repository root:

```powershell
python validation/windows_positive/run.py --workdir C:\MCPBenchmark\work --reportdir C:\MCPBenchmark\report --tool-calls 64 --scan-repeats 3 --report-scan-limits
python validation/windows_positive/benchmark.py summarize --reportdir C:\MCPBenchmark\report --replica 1 --output benchmark-1.json
```

Repeat in two other fresh VMs using replicas 2 and 3, then aggregate all three files:

```powershell
python validation/windows_positive/benchmark.py aggregate benchmark-1.json benchmark-2.json benchmark-3.json --output benchmark.json
```

The GitHub Actions `Windows memory benchmark` workflow performs the three captures.
It uploads only allowlisted counts, durations, environment/version information, image
hashes, and validation flags. RAM, recovered messages, ground truth, process IDs,
and arbitrary log text are excluded. Failed or missing captures cannot be silently
dropped from the three-capture aggregate. Read errors and missing endpoints remain
failures. `--report-scan-limits` allows bounded-search results to be measured, but
marks them `completed_with_limits`, preserves every limit counter, and sets
`full_endpoint_scans=false`; the aggregate reports how many captures were limited.
The normal positive-validation command still rejects limited scans by default.

## Interpretation

Recovery counts deduplicate messages within each capture and combine both endpoints.
Candidate links remain candidates; unsent controls are counted separately from logged
traffic. Mean/min/max describe only these three captures. Logging changes memory,
and retained frames are a favorable control. No general recall, detection precision,
latency/pressure survival curve, or Windows 11/Linux benchmark is established by
this Windows Server 2022 SDK/stdio experiment.
