"""Minimal stdio MCP for testing the Fanout module.

Implements just enough of the MCP protocol — ``initialize``,
``tools/list``, ``tools/call`` — to drive the Fanout end-to-end without
depending on FastMCP. The single tool, ``echo``, returns its input plus
the value of ``$ECHO_SECRET`` so tests can verify per-identity secret
isolation (each child process gets its own ``ECHO_SECRET`` value).

Framing: newline-delimited JSON, per the MCP spec for stdio transport.
Run as a script: ``python -m tests.fakes.echo_mcp`` or
``python tests/fakes/echo_mcp.py``.

Pure stdlib; no third-party deps. This file must remain importable as
both a script and a module so the test runner and Fanout can both
spawn it.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any


def _read_secret() -> str:
    """Return the per-process secret marker.

    Prefers ``$ECHO_SECRET_FILE`` (Fanout production pattern: token written
    to a file by the parent, env var holds the path). Falls back to
    ``$ECHO_SECRET`` (direct env-value, used by simpler tests).
    """
    path = os.environ.get("ECHO_SECRET_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return "<no secret file>"
    return os.environ.get("ECHO_SECRET", "<no secret>")


def _ok(msg_id: object, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle(request: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    msg_id = request.get("id")

    if method == "initialize":
        return _ok(
            msg_id,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "echo", "version": "0.0.0"},
            },
        )

    if method == "tools/list":
        return _ok(
            msg_id,
            {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo back the input plus the value of $ECHO_SECRET",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                            "required": ["text"],
                        },
                    }
                ]
            },
        )

    if method == "tools/call":
        params = request.get("params", {})
        if params.get("name") != "echo":
            return _err(msg_id, -32601, f"unknown tool: {params.get('name')!r}")
        text = params.get("arguments", {}).get("text", "")
        # Include the per-identity secret marker so tests can assert
        # isolation. Two ways to receive the secret:
        #   ECHO_SECRET_FILE — file path (the Fanout-style production pattern)
        #   ECHO_SECRET      — direct env value (simpler test-only pattern)
        secret = _read_secret()
        return _ok(
            msg_id,
            {"content": [{"type": "text", "text": f"echo:{text}|secret:{secret}"}]},
        )

    return _err(msg_id, -32601, f"unknown method: {method!r}")


def main() -> int:
    # Newline-delimited JSON-RPC. Read until EOF.
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            request: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            # Real MCP servers MUST NOT write to stdout for non-protocol
            # output — log to stderr and skip.
            print(f"echo_mcp: invalid JSON on stdin: {line!r}", file=sys.stderr)
            continue
        response = handle(request)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
