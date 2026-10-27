# MCPTrace

MCPTrace is a **Volatility 3 plugin for extracting MCP/JSON-RPC message candidates
from Windows and Linux memory dumps**. It examines process memory for requests,
responses, notifications, tool names, and call arguments, then records the recovered
content together with its location in memory.

The project focuses on evidence that an analyst can inspect and verify. Each artifact
retains its original bytes, process ID, virtual address, encoding, length, and SHA-256
hash. Results can be exported as JSONL for further analysis or comparison with other
logs. MCPTrace operates on an acquired memory image and does not require an LLM or
an external AI API.

## Features

- Extract UTF-8 and UTF-16LE JSON-RPC artifacts from readable process memory.
- Identify MCP-related methods and response shapes, including `tools/call` names and arguments.
- Preserve original bytes and addresses for later verification against the image.
- Suggest request/response relationships using the same PID and typed request ID.
- Apply optional, analyst-defined rules to tool arguments, such as path or URL checks.
- Export artifacts and per-process summaries, including unreadable bytes, errors, and search limits.

The current analysis targets are **Windows x64** and **Linux x86-64**. The plugin
name refers to the operating system in the memory image, independently of the OS
used to run Volatility.

## How it works

MCPTrace uses Volatility's process enumeration and address translation. On Windows,
it walks process **Virtual Address Descriptors (VADs)**; on Linux, it walks **Virtual
Memory Areas (VMAs)**. These mappings define which process address ranges are examined.
The two adapters share the same message-carving, correlation, policy, and export code.

Within readable ranges, the scanner searches for literal JSON-RPC version markers
and locates candidate JSON objects around them. It handles nested objects, escaped
characters, braces inside strings, and messages spanning contiguous read chunks.
JSON with duplicate keys or unsupported identifiers is rejected rather than silently
reinterpreted. MCP relevance is determined from known method names, response shapes,
and associated request IDs; it is not full MCP schema validation.

Missing memory is kept missing. The reader does not fill gaps with zeroes or join
bytes across separate VADs/VMAs. With `--include-partial`, unparsed fragments can be
shown separately, without inventing missing IDs or arguments. Large unmapped ranges
can be skipped using page-table information, and unreadable address ranges remain
visible in the scan statistics.

Correlation is deliberately conservative. A numeric ID such as `1` is distinct from
the string ID `"1"`, and messages in different processes are not automatically linked.
Multiple distinct representations associated with an ID are marked as ambiguous.
Candidate relationships do not reconstruct a session, message direction, or execution
timeline on their own.

## Installation

Requires **Python 3.10+**. Installation includes the pinned framework dependency,
`volatility3==2.28.2`. Keep the repository's `plugins/` directory available: the Python
package is installed with pip, while `-p plugins` loads the Volatility adapters.

```sh
git clone https://github.com/Kowntaewook/MCPTrace.git
cd MCPTrace
python -m venv .venv
```

Activate the environment for your shell:

- Windows PowerShell: `.\.venv\Scripts\Activate.ps1`
- Linux/macOS shell: `source .venv/bin/activate`

Then install MCPTrace:

```sh
python -m pip install .
```

## Usage

Run the following examples from the repository root with the virtual environment
active. Replace the image paths and PIDs with your evidence and target processes.
MCP clients and servers may run in separate processes, so inspect both where relevant.

**Windows**

Check that Volatility can interpret the image and enumerate its processes before
running MCPTrace. Windows symbol preparation may require network access.

```sh
vol -f windows.raw windows.info.Info
vol -f windows.raw windows.pslist.PsList
mkdir output-windows
vol -p plugins -f windows.raw -o output-windows windows.mcptrace.MCPTrace --pid 4242 5252 --dump
```

**Linux**

Place ISF symbols matching the dump's **exact kernel build** in `symbols/linux/`.
If `linux.pslist.PsList` cannot resolve its kernel or layer requirements, resolve
the image/symbol setup before interpreting MCPTrace output.

```sh
vol -s symbols -f linux.lime linux.pslist.PsList
mkdir output-linux
vol -p plugins -s symbols -f linux.lime -o output-linux linux.mcptrace.MCPTrace --pid 4242 --dump
```

- Omit `--pid` to scan all processes, or pass multiple PIDs: `--pid 4242 5252`.
- `--dump` exports per-process JSONL files to the directory specified by `-o`.
- Use `vol -p plugins windows.mcptrace.MCPTrace -h` (or the Linux equivalent) for all options.

For a JSON rendering of the full result table, put the global `-r json` option before
the plugin name. This is separate from the per-process JSONL exports produced by `--dump`.

```sh
vol -p plugins -f windows.raw -r json windows.mcptrace.MCPTrace --pid 4242 > findings.json
```

## Common options

| Option | Purpose |
| --- | --- |
| `--pid 4242 5252` | Select process IDs; omit to examine all processes enumerated by the adapter. |
| `--dump` | Export displayed artifacts and scan summaries as JSONL using the global `-o` directory. |
| `--include-partial` | Include raw, unparsed fragments without reconstructing missing fields. |
| `--include-rpc` | Also display generic JSON-RPC candidates without confirmed MCP relevance. |
| `--policy PATH` | Apply local rules to tool arguments; see the [Windows](examples/policy.json) and [Linux](examples/policy-linux.json) examples. |
| `--suspicious-only` | Show policy matches and summaries; requires a nonempty policy. |
| `--max-records N` | Bound candidate records per process before filtering; default: `10000`. |
| `--max-object-bytes N` | Bound the size of one complete JSON object; default: `65536` bytes. |
| `--max-bytes N` | Bound attempted address-range bytes per process; `0` means unlimited. |

Policy findings describe matches against the rules supplied by the analyst. A match
does not establish malicious activity. Review the example paths, hosts, and tool names
before applying them to a different case.

## Reading the output

A file such as `mcptrace.pid-4242.jsonl` contains a metadata record, artifact records,
and a final scan summary. The metadata identifies the process, target OS, and address
space. Artifact records preserve both the parsed message and the exact recovered bytes.

| Fields | Meaning |
| --- | --- |
| `pid`, `virtual_address`, `region_start` | Process and location of the evidence. Addresses are process virtual addresses, not image file offsets. |
| `message`, `method`, `tool`, `request_id` | Parsed message content and selected fields, when available. |
| `raw_base64`, `byte_length`, `raw_sha256` | Original bytes, their length, and SHA-256 for verification. |
| `state`, `encoding` | Whether the record is complete or a fragment, and how its bytes are encoded. |
| `relation`, `candidate_virtual_addresses` | Candidate counterpart locations and whether the relationship is ambiguous. |
| `findings` | Results of optional argument-policy checks. |

To verify an artifact, decode `raw_base64`, check its length and hash, and re-read
that range through the corresponding process memory layer. Reformatting `message`
as JSON may change whitespace or escaping, so use the preserved bytes for an exact
comparison. Different memory copies remain separate evidence records.

Read the scan summary alongside the artifacts. It reports scanned regions, readable
and unreadable bytes, invalid regions, skipped processes, errors, and limit events.
Unreadable bytes can include unused reserved address space. A result with no messages
does not prove that MCP activity never occurred.

## Benchmark

The benchmark used **three fresh Windows Server 2022 VM captures**. Each VM ran two
client/server pairs using the official Python MCP SDK over stdio. Actual traffic was
exchanged before physical RAM was acquired with WinPmem; test messages were not
injected into the resulting image.

Each condition completed **64 tool calls and 133 logical messages**, including
initialization, a notification, and tool discovery. Payloads included ASCII,
Korean/emoji, escaped characters, whitespace, and a 2 KiB string. The conditions were:

- **No retained-frame list:** record ground truth at the SDK send/receive boundary,
  without keeping a separate list of serialized frames.
- **Retained-frame control:** record the same ground truth and keep serialized frames
  in memory. Also retain one deliberately unsent MCP-shaped JSON object per capture.

Recovery counts combine the client and server within each capture and deduplicate
logical messages. The table reports the mean and range across the three captures.

| Condition | Messages / 133: mean (range) | Tool pairs / 64: mean (range) |
| --- | ---: | ---: |
| No retained-frame list | 59.7 (55-66) | 18.3 (15-21) |
| Retained-frame control | 133.0 (133-133) | 64.0 (64-64) |

The no-retained-frame runs recovered 66, 58, and 55 messages, with 21, 19, and 15
complete tool request/response pairs. Pooled across captures, that is **179/399
messages** and **55/192 pairs**. The retained control recovered 133 messages and
64 pairs in each capture. A pair found across both endpoints is not necessarily
present in full within one process.

**Two of three captures reached candidate search limits**, reporting 4 and 3
backtracking-limit events. Those runs are explicitly marked `completed_with_limits`
and remain included in the table. The events are not a count of unique missing
messages. No process-read errors, skipped targets, or record/byte-budget limits were
observed in the final three captures.

Each image was analyzed three times, giving **nine CLI scans of four selected
endpoint processes**. Runtime had a median of **53.95 seconds**, a mean of
**53.94 seconds**, and a range of **53.32-54.48 seconds**. The runners reported
4 logical CPUs and approximately 16 GiB of RAM.

Timing includes CLI startup, Volatility automagic, process scanning, JSON rendering,
and JSONL export. It excludes acquisition, initial symbol preparation, and separate
byte verification. Images were already hashed and inspected before scanning, so
these are not cold-cache or all-process/full-image throughput measurements.

All **1,339 exported records / 562,402 bytes** passed native process-layer checks of
their bytes, hashes, virtual addresses, and VAD boundaries. Repeated scans produced
byte-identical JSONL, image hashes remained unchanged, and temporary RAM images were
deleted after analysis. No incorrect links were observed among 2,480 evaluable
directional candidate links; this count includes links between memory copies.

The three deliberately unsent controls were also recovered. This demonstrates an
important interpretation limit: an MCP-shaped object can exist in memory without
having been transmitted. Logs, cached values, and examples must be considered when
assessing the evidence.

Both conditions include logging that changes memory, and retained frames are a
favorable control. These results describe a small SDK fixture, **not general recall,
precision, or attack-detection performance**. The workload is different from the
earlier 8-call positive validation, so the two results are not a controlled before/after
comparison. Full measurements, per-capture statistics, and reproduction instructions
are in the [benchmark report](docs/windows-memory-benchmark.md) and
[machine-readable results](docs/benchmarks/windows-memory-benchmark-2026-10-27.json).

## Validation and implementation findings

The benchmark exposed a premature limit-counter increment: a local stream containing
133 valid SDK messages was fully recovered but produced 228 candidate-limit events.
The counter now increments only when bounded backtracking fails after older candidates
are excluded. The search bound itself is unchanged, and genuine limit events remain
visible in the output. Initial failed attempts and the correction are documented in
the benchmark report.

The measured implementation passed **135 automated tests**, Ruff checks, and CI on
Windows and Ubuntu with Python 3.10 and 3.12. Tests cover parsing, exact-byte preservation,
memory gaps, typed-ID correlation, platform adapters, exports, and benchmark reporting.

An existing public Linux MCP sample was also rescanned after the counter correction.
Both JSONL exports remained byte-identical and retained all 41 artifacts. That sample
uses an inferred physical-memory layout because its VMware metadata was unavailable;
it is a conditional validation result, not a Linux recovery-rate benchmark. Details
are recorded in the [Linux RAM validation report](docs/real-memory-validation.md).

## Scope and limitations

MCPTrace currently carves plaintext UTF-8/UTF-16LE JSON-RPC artifacts. It does not
reassemble Python/V8 heap objects, decrypt application data, recover swapped-out
content, or infer bytes missing from the dump. Literal version markers and bounded
object/search sizes also mean some valid representations can be missed.

Analysis is limited to processes and mappings exposed by Volatility's selected
`pslist` and process-memory layers. Hidden processes, evidence outside those mappings,
and unreadable pages require other analysis methods. ARM and 32-bit targets are not
currently supported.

The controlled benchmark covers Windows Server 2022, one Python SDK version, and
stdio traffic. It does not establish the same recovery behavior for Windows 11,
Claude Desktop or other clients, different transports, or delayed collection under
additional memory pressure. Complete JSON and candidate ID matches alone do not
prove transmission, tool execution, session membership, or compromise.

## Further documentation

- [Validation scope and procedures](docs/validation.md)
- [Windows positive MCP traffic validation](docs/windows-positive-memory-validation.md)
- [Windows 11 public-image validation](docs/windows-memory-validation.md)
- [Repeated benchmark procedure](validation/windows_positive/BENCHMARK.md)
