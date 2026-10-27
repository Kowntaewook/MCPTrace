# MCPTrace

A Volatility 3 plugin for extracting MCP/JSON-RPC message candidates from Windows x64 and Linux x86-64 memory dumps. Preserves message content, process IDs, virtual addresses, and SHA-256 hashes, with optional JSONL export.

## Installation

Requires Python 3.10+. Run in an activated virtual environment:

```sh
git clone https://github.com/Kowntaewook/MCPTrace.git
cd MCPTrace
python -m pip install .
```

## Usage

Run from the repository root. Choose the plugin matching the **dump's OS** and replace the example paths and PIDs.

**Windows**

```sh
vol -f windows.raw windows.pslist.PsList
mkdir output-windows
vol -p plugins -f windows.raw -o output-windows windows.mcptrace.MCPTrace --pid 4242 --dump
```

**Linux**

Place ISF symbols matching the dump's kernel build in `symbols/linux/` first.

```sh
vol -s symbols -f linux.lime linux.pslist.PsList
mkdir output-linux
vol -p plugins -s symbols -f linux.lime -o output-linux linux.mcptrace.MCPTrace --pid 4242 --dump
```

- Omit `--pid` to scan all processes, or pass multiple PIDs: `--pid 4242 5252`.
- `--dump` exports per-process JSONL files to the directory specified by `-o`.
- Use `vol -p plugins windows.mcptrace.MCPTrace -h` (or the Linux equivalent) for all options.

## Benchmark

Windows Server 2022, Python MCP SDK over stdio: **3 independent RAM captures**,
64 tool calls / 133 messages per condition per capture. Results combine both endpoints.

| Condition | Messages / 133: mean (range) | Tool pairs / 64: mean (range) |
| --- | ---: | ---: |
| No retained-frame list | 59.7 (55-66) | 18.3 (15-21) |
| Retained-frame control | 133.0 (133-133) | 64.0 (64-64) |

CLI median: **53.95 s** (53.32-54.48 s, 9 scans of 4 endpoint processes).
Acquisition and initial symbol setup are excluded; scans are not cold-cache measurements.

**2/3 captures hit candidate search limits** (4 and 3 events); these limited results are included.
Ground-truth logging affects memory, and retained frames are a favorable control.
This is fixture-specific recovery, not general recall. [Methodology and full results](docs/windows-memory-benchmark.md).
