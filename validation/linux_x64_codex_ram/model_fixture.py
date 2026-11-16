"""Controlled local Responses endpoint for a Codex CLI MCP memory experiment.

Only a synthetic model response is served. The endpoint waits after observing
the real MCP tool result so the Codex client remains alive for RAM acquisition.
"""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def event_payload(item: dict) -> bytes:
    response = {
        "id": "resp_fixture", "object": "response", "created_at": 1,
        "status": "completed", "model": "fixture-model", "output": [item],
        "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3},
    }
    events = [
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]
    return b"".join(
        ("event: " + event["type"] + "\n" + "data: "
         + json.dumps(event, separators=(",", ":")) + "\n\n").encode()
        for event in events
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--marker", required=True)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    marker = args.marker

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/v1/responses":
                self.send_error(404)
                return
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            request = json.loads(body)
            outputs = [x for x in request.get("input", [])
                       if x.get("type") == "function_call_output"
                       and x.get("call_id") == "call_fixture"]
            if outputs:
                (run_dir / "model-tool-output.json").write_text(json.dumps(outputs))
                if marker not in json.dumps(outputs):
                    self.send_error(422, "MCP tool result did not contain marker")
                    return
                (run_dir / "model-tool-result-observed").write_text("ok\n")
                while not (run_dir / "release-model-response").exists():
                    time.sleep(0.1)
                item = {
                    "id": "msg_fixture", "type": "message", "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": "Fixture complete.",
                                 "annotations": []}],
                }
            else:
                (run_dir / "model-request-monotonic-ns").write_text(
                    str(time.monotonic_ns()))
                (run_dir / "model-request-tools.json").write_text(
                    json.dumps(request.get("tools", [])))
                item = {
                    "id": "fc_fixture", "type": "function_call", "status": "completed",
                    "call_id": "call_fixture", "name": "echo_marker",
                    "namespace": "mcp__mcptrace_probe",
                    "arguments": json.dumps({"marker": marker}),
                }
            payload = event_payload(item)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    HTTPServer(("127.0.0.1", 18765), Handler).serve_forever()


if __name__ == "__main__":
    main()
