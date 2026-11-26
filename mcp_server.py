"""Standalone Model Context Protocol (MCP) Server over stdio (JSON-RPC 2.0).

Connect directly from Claude Desktop, VS Code Copilot, Cursor, or a local LLM
running on your RTX 4090 — zero third-party packages required.

Usage:
    python mcp_server.py

All logs go to stderr so stdout remains a clean JSON-RPC 2.0 stream.
"""
from __future__ import annotations

import json
import sys

from app import create_runtime


def main() -> None:
    cfg, _engine, mcp = create_runtime()
    print(
        f"[intuneguard-mcp] Ready (mode={'live' if cfg.is_live else 'synthetic'}, "
        f"require_rfc={cfg.require_rfc_for_writes})",
        file=sys.stderr,
        flush=True,
    )

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
            continue

        response = mcp.handle_jsonrpc(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
