"""stdio child process wrapper with newline-delimited JSON-RPC framing.

Each :class:`ChildProcess` wraps one running stdio MCP subprocess. The
Fanout owns one ``ChildProcess`` per (mcp, identity) tuple. Calls are
serialized per-child via an internal lock — the MCP spec doesn't
prohibit pipelining but most implementations don't expect it.

Framing (per the MCP spec for stdio transport):

- One JSON-RPC message per line, terminated by ``\\n``
- Lines MUST NOT contain embedded newlines
- The server's stderr is reserved for logging and never carries protocol

Defenses against hostile/buggy children:

- ``max_response_bytes`` caps a single response line. Anything bigger
  surfaces as :class:`BackendChildDead`. Without this, a runaway MCP
  emitting unbounded output ballons hub RSS until OOM.
- A closed stdout (child exited mid-call) surfaces as
  :class:`BackendChildDead`, not a hang.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from .exceptions import BackendChildDead


class ChildProcess:
    """Wrap one stdio MCP subprocess with serialized JSON-RPC calls."""

    def __init__(
        self,
        *,
        process: asyncio.subprocess.Process,
        identity: str,
        max_response_bytes: int,
    ) -> None:
        self._process = process
        self._identity = identity
        self._max_response_bytes = max_response_bytes
        self._lock = asyncio.Lock()

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def pid(self) -> int | None:
        return self._process.pid

    @property
    def alive(self) -> bool:
        return self._process.returncode is None

    async def send(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send one JSON-RPC request, return one JSON-RPC response.

        Raises :class:`BackendChildDead` if the child has exited, the
        response exceeds ``max_response_bytes``, or the response can't
        be parsed as JSON.
        """
        async with self._lock:
            if not self.alive:
                raise BackendChildDead(
                    f"child for identity={self._identity!r} has exited "
                    f"(returncode={self._process.returncode})"
                )

            assert self._process.stdin is not None
            assert self._process.stdout is not None

            payload = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
            try:
                self._process.stdin.write(payload)
                await self._process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise BackendChildDead(
                    f"child for identity={self._identity!r} closed stdin during write"
                ) from exc

            try:
                line = await self._process.stdout.readuntil(b"\n")
            except asyncio.IncompleteReadError as exc:
                raise BackendChildDead(
                    f"child for identity={self._identity!r} closed stdout mid-response"
                ) from exc
            except asyncio.LimitOverrunError as exc:
                # Default StreamReader limit (64KiB) tripped before our cap;
                # treat as oversized response.
                raise BackendChildDead(
                    f"child for identity={self._identity!r} response exceeded reader limit"
                ) from exc

            if len(line) > self._max_response_bytes:
                raise BackendChildDead(
                    f"child for identity={self._identity!r} response "
                    f"{len(line)} bytes > max_response_bytes={self._max_response_bytes}"
                )

            try:
                parsed: dict[str, Any] = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BackendChildDead(
                    f"child for identity={self._identity!r} emitted unparseable response"
                ) from exc

            return parsed

    async def send_notification(self, request: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no response read).

        Used for the ``notifications/initialized`` message in the MCP
        handshake — clients send it after ``initialize`` returns; servers
        do not respond.
        """
        async with self._lock:
            if not self.alive:
                raise BackendChildDead(
                    f"child for identity={self._identity!r} has exited "
                    f"(returncode={self._process.returncode})"
                )
            assert self._process.stdin is not None
            payload = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
            try:
                self._process.stdin.write(payload)
                await self._process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise BackendChildDead(
                    f"child for identity={self._identity!r} closed stdin during notify"
                ) from exc

    async def close(self) -> None:
        """Terminate the child process and reap it.

        Idempotent. Best-effort: SIGTERM with a short grace, then SIGKILL.
        """
        if self._process.returncode is not None:
            return
        try:
            self._process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(self._process.wait(), timeout=2.0)
        except TimeoutError:
            self._process.kill()
            await self._process.wait()
