"""Official SDK client with no frame journal or retained-message list."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import sys
import time
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(args) -> None:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    proxy = Path(__file__).with_name("proxy.py")
    server = Path(__file__).with_name("server.py")
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            str(proxy),
            "--run-id",
            args.run_id,
            "--log",
            str(output / "wire.jsonl"),
            "--server",
            str(server),
        ],
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            listed = await session.list_tools()
            if "echo_marker" not in {tool.name for tool in listed.tools}:
                raise RuntimeError("official server did not advertise echo_marker")
            del listed
            for sequence in range(args.tool_calls):
                text = f"CONTROL_{args.run_id}_{sequence}"
                result = await session.call_tool(
                    "echo_marker",
                    {"run_id": args.run_id, "sequence": sequence, "text": text},
                )
                if result.isError:
                    raise RuntimeError("tool call failed")
                value = result.structuredContent
                if value is None:
                    value = json.loads(result.content[0].text)
                if (value["run_id"], value["sequence"], value["text"]) != (
                    args.run_id,
                    sequence,
                    text,
                ):
                    raise RuntimeError("tool response did not match request")
                del result, value, text
            metadata = {
                "run_id": args.run_id,
                "client_pid": os.getpid(),
                "tool_calls_completed": args.tool_calls,
                "ready_ns": time.time_ns(),
                "mcp_sdk": importlib.metadata.version("mcp"),
                "frame_journal_in_client": False,
                "wire_log_process": "separate stdio proxy",
            }
            (output / "ready.json").write_text(json.dumps(metadata), encoding="utf-8")
            deadline = time.monotonic() + args.hold_seconds
            while not (output / "stop").exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("capture did not finish before workload deadline")
                await anyio.sleep(0.05)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tool-calls", type=int, default=4)
    parser.add_argument("--hold-seconds", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.tool_calls <= 32:
        parser.error("--tool-calls must be between 1 and 32")
    anyio.run(run, args)


if __name__ == "__main__":
    main()
