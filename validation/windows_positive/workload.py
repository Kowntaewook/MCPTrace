"""Real SDK stdio traffic, with explicit natural and retained-frame controls."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP


class Journal:
    def __init__(self, path, retain):
        self.stream = path.open("x", encoding="utf-8")
        self.retain = retain
        self.frames = []
        self.count = 0

    def record(self, direction, item):
        if isinstance(item, Exception):
            raise item
        # Outgoing uses the SDK stdio writer's serialization. Incoming is a
        # reserialization of the parsed SDK message, not a wire-byte recording.
        raw = item.message.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
        row = {
            "index": self.count,
            "direction": direction,
            "observed_ns": time.time_ns(),
            "message": json.loads(raw),
        }
        self.stream.write(json.dumps(row, ensure_ascii=True) + "\n")
        self.stream.flush()
        self.count += 1
        if self.retain:
            self.frames.append(raw)


class LoggedStream:
    def __init__(self, stream, journal, direction):
        self.stream, self.journal, self.direction = stream, journal, direction

    async def send(self, item):
        await self.stream.send(item)
        self.journal.record(self.direction, item)

    async def receive(self):
        item = await self.stream.receive()
        self.journal.record(self.direction, item)
        return item

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.receive()
        except anyio.EndOfStream as exc:
            raise StopAsyncIteration from exc

    async def __aenter__(self):
        await self.stream.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self.stream.__aexit__(*args)

    async def aclose(self):
        await self.stream.aclose()


def server(run_id):
    app = FastMCP(f"MCPTrace validation {run_id}")

    @app.tool()
    def echo_marker(run_id: str, sequence: int, text: str) -> dict:
        """Return synthetic test input and the PID of the actual server."""
        return {"run_id": run_id, "sequence": sequence, "text": text, "server_pid": os.getpid()}

    app.run(transport="stdio")


async def client(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    journal = Journal(output / "ground-truth.jsonl", args.mode == "retained")
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).resolve()), "server", "--run-id", args.run_id],
    )
    retained_decoys = []
    try:
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(
                LoggedStream(reader, journal, "server-to-client"),
                LoggedStream(writer, journal, "client-to-server"),
            ) as session:
                await session.initialize()
                tools = await session.list_tools()
                if "echo_marker" not in {tool.name for tool in tools.tools}:
                    raise RuntimeError("The real MCP server did not advertise echo_marker")
                samples = [
                    "hello",
                    "한글 🧪",
                    'quote" slash\\ newline\n{braces}',
                    "X" * 2048,
                    "duplicate text",
                    "duplicate text",
                    "spaces   and\ttabs",
                    "last message",
                ]
                server_pid = None
                for sequence in range(args.tool_calls):
                    text = samples[sequence % len(samples)]
                    result = await session.call_tool(
                        "echo_marker",
                        {"run_id": args.run_id, "sequence": sequence, "text": text},
                    )
                    if result.isError:
                        raise RuntimeError("MCP tool returned an error")
                    obj = result.structuredContent
                    if obj is None:
                        obj = json.loads(result.content[0].text)
                    if (obj["run_id"], obj["sequence"], obj["text"]) != (
                        args.run_id,
                        sequence,
                        text,
                    ):
                        raise RuntimeError("MCP response differs from the actual request")
                    server_pid = int(obj["server_pid"])
                    del result, obj
                if args.mode == "retained":
                    # This is deliberately NOT sent. It measures the distinction
                    # between JSON-shaped memory evidence and actual traffic.
                    decoy = {
                        "jsonrpc": "2.0",
                        "id": 900001,
                        "method": "tools/call",
                        "params": {
                            "name": "echo_marker",
                            "arguments": {"run_id": args.run_id, "sequence": -1, "text": "UNSENT"},
                        },
                    }
                    raw = json.dumps(decoy, separators=(",", ":")).encode()
                    retained_decoys.append(raw)
                    # Store escaped bytes on disk to avoid mistaking this for a
                    # second transport recording when inspecting the fixture.
                    (output / "unsent-controls.json").write_text(
                        json.dumps([base64.b64encode(raw).decode()]), encoding="utf-8"
                    )
                    del decoy, raw
                metadata = {
                    "mode": args.mode,
                    "run_id": args.run_id,
                    "client_pid": os.getpid(),
                    "server_pid": server_pid,
                    "tool_calls_completed": args.tool_calls,
                    "logged_messages": journal.count,
                    "retained_transport_frames": len(journal.frames),
                    "retained_unsent_controls": len(retained_decoys),
                    "ready_ns": time.time_ns(),
                    "logging": "SDK send/receive boundary; incoming messages reserialized",
                }
                ready = output / "ready.json"
                temp = output / "ready.tmp"
                temp.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
                temp.replace(ready)
                deadline = time.monotonic() + args.hold_seconds
                while not (output / "stop").exists():
                    if time.monotonic() > deadline:
                        raise TimeoutError("Capture did not finish before workload deadline")
                    await anyio.sleep(0.1)
    finally:
        journal.stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["server", "client"])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=["natural", "retained"], default="natural")
    parser.add_argument("--hold-seconds", type=int, default=900)
    parser.add_argument("--tool-calls", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.tool_calls <= 512:
        parser.error("--tool-calls must be between 1 and 512")
    if args.role == "server":
        server(args.run_id)
    elif args.output is None:
        parser.error("client requires --output")
    else:
        anyio.run(client, args)


if __name__ == "__main__":
    main()
