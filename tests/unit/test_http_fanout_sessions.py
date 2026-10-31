"""Session (``Mcp-Session-Id``) tests for :class:`mcp_fanout.HttpFanout`.

A stateful Streamable-HTTP upstream assigns a session on ``initialize`` and
requires it on every later request. ``_StatefulUpstream`` mimics the MCP
TypeScript SDK's stateful server: no session and not ``initialize`` means 400
"Server not initialized"; an unknown session means 404.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from mcp_fanout import HttpFanout, HttpUpstreamFailed

from .test_http_fanout import URL, _initialize_response, _make_fanout, _RecordingTransport


class _PerIdentityBearer:
    """AuthStrategy stub: a distinct bearer per identity (``tok-<identity>``)."""

    name: str = "per_identity_bearer"

    async def auth_header(
        self, *, identity: str, request_context: dict[str, Any]
    ) -> dict[str, str]:
        return {"Authorization": f"Bearer tok-{identity}"}

    async def close(self) -> None:
        return None


class _StatefulUpstream:
    """Session-per-client MCP. Results echo the session and bearer they ran under."""

    def __init__(self) -> None:
        self.sessions: dict[str, str | None] = {}
        self.requests: list[httpx.Request] = []
        self.deleted: list[str | None] = []
        self.forget_every_call: bool = False
        self._opened = 0

    def make_transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)

    def restart(self) -> None:
        self.sessions.clear()

    def posts(self, method: str) -> list[httpx.Request]:
        return [
            r
            for r in self.requests
            if r.method == "POST" and json.loads(r.content)["method"] == method
        ]

    def _handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        sid = request.headers.get("mcp-session-id")
        if request.method == "DELETE":
            self.deleted.append(sid)
            self.sessions.pop(sid or "", None)
            return httpx.Response(200)
        body = json.loads(request.content)
        if sid is not None:
            if sid not in self.sessions:
                return httpx.Response(
                    404,
                    json={
                        "jsonrpc": "2.0",
                        "error": {"code": -32001, "message": "Session not found"},
                        "id": None,
                    },
                )
            if self.forget_every_call and "id" in body:
                self.sessions.clear()
                return httpx.Response(404, json={"error": "Session not found"})
            if "id" not in body:
                return httpx.Response(202)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"session": sid, "auth": request.headers["authorization"]},
                },
            )
        if body.get("method") != "initialize":
            return httpx.Response(
                400,
                json={
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": "Bad Request: Server not initialized"},
                    "id": None,
                },
            )
        self._opened += 1
        new_sid = f"s{self._opened}"
        self.sessions[new_sid] = request.headers.get("authorization")
        return httpx.Response(200, json=_initialize_response(), headers={"mcp-session-id": new_sid})


def _make_session_fanout(
    upstream: _StatefulUpstream, identities: tuple[str, ...] = ("a",)
) -> HttpFanout:
    return HttpFanout(
        mcp_name="finance",
        url=URL,
        auth_strategy=_PerIdentityBearer(),
        identities=list(identities),
        http_client=httpx.AsyncClient(transport=upstream.make_transport()),
    )


_TOOLS_LIST: dict[str, Any] = {"jsonrpc": "2.0", "id": 7, "method": "tools/list"}


async def test_calls_carry_boot_session_id() -> None:
    upstream = _StatefulUpstream()
    fanout = _make_session_fanout(upstream)
    try:
        await fanout.start_eager_or_die()
        result = await fanout.call(identity="a", request=_TOOLS_LIST)
    finally:
        await fanout.close()

    assert result["result"] == {"session": "s1", "auth": "Bearer tok-a"}
    (notification,) = upstream.posts("notifications/initialized")
    assert notification.headers["mcp-session-id"] == "s1"
    assert len(upstream.posts("initialize")) == 1


async def test_session_opened_lazily_per_identity() -> None:
    upstream = _StatefulUpstream()
    fanout = _make_session_fanout(upstream, identities=("a", "b"))
    try:
        await fanout.start_eager_or_die()
        result_b = await fanout.call(identity="b", request=_TOOLS_LIST)
        result_a = await fanout.call(identity="a", request=_TOOLS_LIST)
        again_b = await fanout.call(identity="b", request=_TOOLS_LIST)
    finally:
        await fanout.close()

    # b got its own session under its own bearer; a kept the boot session.
    assert result_b["result"] == {"session": "s2", "auth": "Bearer tok-b"}
    assert result_a["result"] == {"session": "s1", "auth": "Bearer tok-a"}
    assert again_b["result"]["session"] == "s2"
    assert len(upstream.posts("initialize")) == 2


async def test_concurrent_first_calls_open_one_session() -> None:
    upstream = _StatefulUpstream()
    fanout = _make_session_fanout(upstream, identities=("a", "b"))
    try:
        await fanout.start_eager_or_die()
        results = await asyncio.gather(
            *(fanout.call(identity="b", request=_TOOLS_LIST) for _ in range(5))
        )
    finally:
        await fanout.close()

    assert {r["result"]["session"] for r in results} == {"s2"}
    assert len(upstream.posts("initialize")) == 2


async def test_expired_session_reinitializes_and_retries_once() -> None:
    upstream = _StatefulUpstream()
    fanout = _make_session_fanout(upstream)
    try:
        await fanout.start_eager_or_die()
        await fanout.call(identity="a", request=_TOOLS_LIST)
        upstream.restart()
        result = await fanout.call(identity="a", request=_TOOLS_LIST)
    finally:
        await fanout.close()

    assert result["result"]["session"] == "s2"
    sent = [r.headers.get("mcp-session-id") for r in upstream.posts("tools/list")]
    assert sent == ["s1", "s1", "s2"]


async def test_session_expiring_again_after_retry_raises() -> None:
    upstream = _StatefulUpstream()
    fanout = _make_session_fanout(upstream)
    try:
        await fanout.start_eager_or_die()
        upstream.forget_every_call = True
        with pytest.raises(HttpUpstreamFailed, match="404"):
            await fanout.call(identity="a", request=_TOOLS_LIST)
    finally:
        await fanout.close()

    # One retry, not a loop.
    assert len(upstream.posts("tools/list")) == 2


async def test_stateless_upstream_gets_no_session_header() -> None:
    rec = _RecordingTransport(
        [
            (200, _initialize_response()),
            (202, ""),
            (200, {"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}),
        ]
    )
    fanout, _ = _make_fanout(rec.make_transport(), identities=("a", "b"))
    try:
        await fanout.start_eager_or_die()
        await fanout.call(identity="b", request=_TOOLS_LIST)
    finally:
        await fanout.close()

    # No per-identity initialize for b, no session header, no DELETE.
    assert len(rec.requests) == 3
    assert all("mcp-session-id" not in r.headers for r in rec.requests)
    assert all(r.method == "POST" for r in rec.requests)


async def test_upstream_turning_stateless_drops_sessions() -> None:
    upstream = _StatefulUpstream()
    fanout = _make_session_fanout(upstream, identities=("a", "b"))
    try:
        await fanout.start_eager_or_die()
        # Redeployed stateless: initialize no longer returns a session id.
        upstream.restart()
        original = upstream._handler

        def stateless(request: httpx.Request) -> httpx.Response:
            response = original(request)
            response.headers.pop("mcp-session-id", None)
            return response

        upstream._handler = stateless  # type: ignore[method-assign]
        fanout._http = httpx.AsyncClient(transport=httpx.MockTransport(stateless))
        with pytest.raises(HttpUpstreamFailed):
            # The fake still demands sessions, so the call fails, but the
            # fanout must have stopped sending them.
            await fanout.call(identity="b", request=_TOOLS_LIST)
    finally:
        await fanout.close()

    last = upstream.requests[-1]
    assert "mcp-session-id" not in last.headers


async def test_close_deletes_open_sessions() -> None:
    upstream = _StatefulUpstream()
    fanout = _make_session_fanout(upstream, identities=("a", "b"))
    await fanout.start_eager_or_die()
    await fanout.call(identity="b", request=_TOOLS_LIST)
    await fanout.close()

    assert sorted(s or "" for s in upstream.deleted) == ["s1", "s2"]
    assert upstream.sessions == {}
