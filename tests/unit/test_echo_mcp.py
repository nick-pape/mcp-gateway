"""Verify the test-fake echo MCP works end-to-end as a subprocess.

This test spawns the fake MCP, sends it newline-delimited JSON-RPC over
stdin, reads responses on stdout, and confirms the protocol behaviors
the Fanout will rely on:

- ``initialize`` returns server info
- ``tools/list`` advertises ``echo``
- ``tools/call`` echoes input plus the per-process ``ECHO_SECRET``

The real Fanout (Phase 2) builds on these guarantees.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ECHO_MCP = Path(__file__).resolve().parents[1] / "fakes" / "echo_mcp.py"


async def _spawn_echo(extra_env: dict[str, str] | None = None) -> asyncio.subprocess.Process:
    env = {"PATH": ""}  # minimal env; tests pass everything explicitly
    if extra_env:
        env.update(extra_env)
    return await asyncio.create_subprocess_exec(
        sys.executable,
        str(ECHO_MCP),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )


async def _send(proc: asyncio.subprocess.Process, request: dict[str, Any]) -> dict[str, Any]:
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
    await proc.stdin.drain()
    line = await proc.stdout.readline()
    return json.loads(line.decode("utf-8"))


@pytest.mark.integration
async def test_echo_mcp_initialize() -> None:
    proc = await _spawn_echo()
    try:
        response = await _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert response["id"] == 1
        result = response["result"]
        assert isinstance(result, dict)
        assert result["serverInfo"]["name"] == "echo"
    finally:
        proc.terminate()
        await proc.wait()


@pytest.mark.integration
async def test_echo_mcp_lists_echo_tool() -> None:
    proc = await _spawn_echo()
    try:
        response = await _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        result = response["result"]
        assert isinstance(result, dict)
        tools = result["tools"]
        assert isinstance(tools, list)
        assert {t["name"] for t in tools} == {"echo"}
    finally:
        proc.terminate()
        await proc.wait()


@pytest.mark.integration
async def test_echo_mcp_call_echoes_input_and_secret() -> None:
    proc = await _spawn_echo(extra_env={"ECHO_SECRET": "ironclaw-token"})
    try:
        response = await _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "hello"}},
            },
        )
        result = response["result"]
        assert isinstance(result, dict)
        content = result["content"]
        assert isinstance(content, list)
        assert content[0]["text"] == "echo:hello|secret:ironclaw-token"
    finally:
        proc.terminate()
        await proc.wait()


@pytest.mark.integration
async def test_echo_mcp_per_process_secret_isolation() -> None:
    """Two separate child processes hold different ECHO_SECRET values."""
    proc_a = await _spawn_echo(extra_env={"ECHO_SECRET": "ironclaw-token"})
    proc_b = await _spawn_echo(extra_env={"ECHO_SECRET": "paperless-bot-token"})
    try:
        resp_a = await _send(
            proc_a,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "x"}},
            },
        )
        resp_b = await _send(
            proc_b,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "x"}},
            },
        )
        text_a = resp_a["result"]["content"][0]["text"]
        text_b = resp_b["result"]["content"][0]["text"]
        assert text_a == "echo:x|secret:ironclaw-token"
        assert text_b == "echo:x|secret:paperless-bot-token"
    finally:
        for p in (proc_a, proc_b):
            p.terminate()
            await p.wait()


@pytest.mark.integration
async def test_echo_mcp_unknown_tool_returns_error() -> None:
    proc = await _spawn_echo()
    try:
        response = await _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "not-real", "arguments": {}},
            },
        )
        assert "error" in response
        error = response["error"]
        assert isinstance(error, dict)
        assert error["code"] == -32601
    finally:
        proc.terminate()
        await proc.wait()
