"""Official Python MCP SDK server used by the no-retention RAM experiment."""

from __future__ import annotations

import argparse

from mcp.server.fastmcp import FastMCP


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    app = FastMCP(f"MCPTrace RAM control {args.run_id}")

    @app.tool()
    def echo_marker(run_id: str, sequence: int, text: str) -> dict:
        """Return the supplied synthetic marker."""
        return {"run_id": run_id, "sequence": sequence, "text": text}

    app.run(transport="stdio")


if __name__ == "__main__":
    main()
