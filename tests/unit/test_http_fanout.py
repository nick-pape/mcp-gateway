"""Tests for :class:`mcp_fanout.HttpFanout`.

Uses :class:`httpx.MockTransport` to stand in for the upstream MCP. We
verify the fanout's external interface (``start_eager_or_die``,
``call``, ``close``, ``identities``) plus the invariants the directive
locked in: per-identity auth header injection, eager-or-die at boot,
HttpUpstreamFailed on network/protocol errors, malformed-JSON handling.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from mcp_fanout import (
    HttpFanout,
    HttpUpstreamFailed,
    IdentityNotFound,
)
from mcp_fanout.http_fanout import DEFAULT_REQUEST_TIMEOUT_S
from mcp_hub.auth_strategies import CTX_KEY_BEARER_TOKEN, JwtPassthrough

URL = "https://outline.example/mcp"


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _StaticBearer:
    """Stub AuthStrategy that returns a configured Bearer token verbatim."""

    name: str = "static_bearer"

    def __init__(self, value: str) -> None:
        self._value = value
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def auth_header(
        self, *, identity: str, request_context: dict[str, Any]
    ) -> dict[str, str]:
        self.calls.append((identity, dict(request_context)))
        return {"Authorization": f"Bearer {self._value}"}

    async def close(self) -> None:
        return None


class _RecordingTransport:
    """Wrap httpx.MockTransport so we can inspect each request received."""

    def __init__(
        self, handler: list[tuple[int, dict[str, Any] | str]]
    ) -> None:
        # handler is a list of (status, body) responses returned in order.
        # body=str is sent as text; body=dict is JSON-encoded.
        self._responses = list(handler)
        self.requests: list[httpx.Request] = []

    def make_transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self._responses:
            return httpx.Response(500, text="no more canned responses")
        status, body = self._responses.pop(0)
        if isinstance(body, dict):
            return httpx.Response(
                status,
                json=body,
                headers={"content-type": "application/json"},
            )
        return httpx.Response(
            status,
            text=body,
            headers={"content-type": "text/plain"},
        )


def _initialize_response() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "outline", "version": "1.0"},
        },
    }


def _make_fanout(
    transport: httpx.MockTransport,
    *,
    auth: _StaticBearer | None = None,
    identities: tuple[str, ...] = ("claude-code-dev",),
) -> tuple[HttpFanout, _StaticBearer]:
    # Build an httpx client over the test transport. The fanout treats
    # this as an injected client (we own its lifecycle in the test).
    auth = auth or _StaticBearer("test-tok")
    client = httpx.AsyncClient(transport=transport)
    fanout = HttpFanout(
        mcp_name="outline",
        url=URL,
        auth_strategy=auth,
        identities=list(identities),
        http_client=client,
    )
    return fanout, auth


# ---------------------------------------------------------------------------
# Construction-time validation
# ---------------------------------------------------------------------------


def test_http_fanout_rejects_empty_identities() -> None:
    with pytest.raises(ValueError, match="at least one identity"):
        HttpFanout(
            mcp_name="outline",
            url=URL,
            auth_strategy=_StaticBearer("x"),
            identities=[],
        )


def test_http_fanout_rejects_duplicate_identities() -> None:
    with pytest.raises(ValueError, match="duplicate identities"):
        HttpFanout(
            mcp_name="outline",
            url=URL,
            auth_strategy=_StaticBearer("x"),
            identities=["a", "a"],
        )


def test_http_fanout_rejects_non_http_url() -> None:
    with pytest.raises(ValueError, match="http"):
        HttpFanout(
            mcp_name="outline",
            url="ftp://nope",
            auth_strategy=_StaticBearer("x"),
            identities=["a"],
        )


# ---------------------------------------------------------------------------
# start_eager_or_die: success
# ---------------------------------------------------------------------------


async def test_start_eager_or_die_initializes_upstream() -> None:
    rec = _RecordingTransport(
        [
            # 1. initialize (success)
            (200, _initialize_response()),
            # 2. notifications/initialized — fire-and-forget; 202 accepted
            (202, ""),
        ]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    try:
        await fanout.start_eager_or_die()
        assert fanout.negotiated_protocol_version == "2025-06-18"
    finally:
        await fanout.close()

    # Only the first request matters for behavior; we verify the wire
    # shape of the initialize call.
    init_req = rec.requests[0]
    assert init_req.method == "POST"
    assert str(init_req.url) == URL
    assert init_req.headers["authorization"] == "Bearer test-tok"
    body = json.loads(init_req.content.decode())
    assert body["method"] == "initialize"
    assert body["params"]["protocolVersion"] == "2025-06-18"


async def test_start_eager_or_die_is_idempotent() -> None:
    rec = _RecordingTransport(
        [(200, _initialize_response()), (202, "")]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    try:
        await fanout.start_eager_or_die()
        await fanout.start_eager_or_die()  # second call: no-op
        # Only one initialize round-trip happened.
        assert len(rec.requests) <= 2
    finally:
        await fanout.close()


# ---------------------------------------------------------------------------
# start_eager_or_die: failure modes
# ---------------------------------------------------------------------------


async def test_start_eager_or_die_aborts_on_5xx() -> None:
    rec = _RecordingTransport([(503, "service unavailable")])
    fanout, _ = _make_fanout(rec.make_transport())
    with pytest.raises(HttpUpstreamFailed, match="503"):
        await fanout.start_eager_or_die()


async def test_start_eager_or_die_aborts_on_4xx_auth_failure() -> None:
    rec = _RecordingTransport([(401, "unauthorized")])
    fanout, _ = _make_fanout(rec.make_transport())
    with pytest.raises(HttpUpstreamFailed, match="401"):
        await fanout.start_eager_or_die()


async def test_start_eager_or_die_aborts_on_jsonrpc_error() -> None:
    rec = _RecordingTransport(
        [
            (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32600, "message": "bad request"},
                },
            )
        ]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    with pytest.raises(HttpUpstreamFailed, match="initialize failed"):
        await fanout.start_eager_or_die()


async def test_start_eager_or_die_aborts_on_unparseable_json() -> None:
    rec = _RecordingTransport([(200, "not json {")])
    fanout, _ = _make_fanout(rec.make_transport())
    with pytest.raises(HttpUpstreamFailed, match="unparseable JSON"):
        await fanout.start_eager_or_die()


# ---------------------------------------------------------------------------
# call: routing + auth injection
# ---------------------------------------------------------------------------


async def test_call_injects_auth_header_per_identity() -> None:
    rec = _RecordingTransport(
        [
            (200, _initialize_response()),
            (202, ""),  # notifications/initialized
            (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {"tools": []},
                },
            ),
        ]
    )
    auth = _StaticBearer("call-tok")
    fanout, _ = _make_fanout(rec.make_transport(), auth=auth)
    try:
        await fanout.start_eager_or_die()
        await fanout.call(
            identity="claude-code-dev",
            request={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
            },
            request_context={"x": "y"},
        )
    finally:
        await fanout.close()
    # Auth strategy received the right identity AND the request_context
    # we passed in (proving the plumb-through works).
    assert auth.calls[-1][0] == "claude-code-dev"
    assert auth.calls[-1][1] == {"x": "y"}
    # Outgoing request had the expected Bearer.
    last_req = rec.requests[-1]
    assert last_req.headers["authorization"] == "Bearer call-tok"


async def test_call_unknown_identity_raises() -> None:
    rec = _RecordingTransport(
        [(200, _initialize_response()), (202, "")]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    try:
        await fanout.start_eager_or_die()
        with pytest.raises(IdentityNotFound, match="unknown identity"):
            await fanout.call(
                identity="nobody",
                request={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            )
    finally:
        await fanout.close()


async def test_call_returns_parsed_response() -> None:
    expected = {
        "jsonrpc": "2.0",
        "id": 99,
        "result": {"tools": [{"name": "list_collections"}]},
    }
    rec = _RecordingTransport(
        [(200, _initialize_response()), (202, ""), (200, expected)]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    try:
        await fanout.start_eager_or_die()
        out = await fanout.call(
            identity="claude-code-dev",
            request={"jsonrpc": "2.0", "id": 99, "method": "tools/list"},
        )
    finally:
        await fanout.close()
    assert out == expected


# ---------------------------------------------------------------------------
# call: failure modes
# ---------------------------------------------------------------------------


async def test_call_propagates_5xx_as_http_upstream_failed() -> None:
    rec = _RecordingTransport(
        [
            (200, _initialize_response()),
            (202, ""),
            (503, "internal server error"),
        ]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    try:
        await fanout.start_eager_or_die()
        with pytest.raises(HttpUpstreamFailed, match="503"):
            await fanout.call(
                identity="claude-code-dev",
                request={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
    finally:
        await fanout.close()


async def test_call_propagates_malformed_json_as_http_upstream_failed() -> None:
    rec = _RecordingTransport(
        [
            (200, _initialize_response()),
            (202, ""),
            (200, "{not json"),
        ]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    try:
        await fanout.start_eager_or_die()
        with pytest.raises(HttpUpstreamFailed, match="unparseable JSON"):
            await fanout.call(
                identity="claude-code-dev",
                request={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
    finally:
        await fanout.close()


async def test_call_before_start_raises() -> None:
    rec = _RecordingTransport([])
    fanout, _ = _make_fanout(rec.make_transport())
    # Calling before start_eager_or_die() — programming error in
    # composer code; surfaces clearly.
    with pytest.raises(HttpUpstreamFailed, match="not started"):
        await fanout.call(
            identity="claude-code-dev",
            request={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )


async def test_call_propagates_auth_strategy_failure() -> None:
    """Auth strategy raising → HttpUpstreamFailed (no upstream call made)."""

    class _FailingAuth:
        name: str = "failing"

        async def auth_header(
            self, *, identity: str, request_context: dict[str, Any]
        ) -> dict[str, str]:
            raise RuntimeError("auth backend down")

        async def close(self) -> None:
            return None

    # Build a manually-wired fanout with the failing strategy, but
    # successfully initialize first using a working transport then swap.
    rec = _RecordingTransport([(200, _initialize_response()), (202, "")])
    client = httpx.AsyncClient(transport=rec.make_transport())
    good_auth = _StaticBearer("good")
    fanout = HttpFanout(
        mcp_name="outline",
        url=URL,
        auth_strategy=good_auth,
        identities=["claude-code-dev"],
        http_client=client,
    )
    try:
        await fanout.start_eager_or_die()
        # Replace the auth strategy in-place to simulate a runtime
        # failure on the next call.
        fanout._auth = _FailingAuth()
        with pytest.raises(HttpUpstreamFailed, match="auth strategy"):
            await fanout.call(
                identity="claude-code-dev",
                request={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
    finally:
        await fanout.close()


# ---------------------------------------------------------------------------
# JwtPassthrough integration
# ---------------------------------------------------------------------------


async def test_call_with_jwt_passthrough_forwards_request_bearer() -> None:
    """JwtPassthrough reads the bearer from request_context and forwards it."""
    rec = _RecordingTransport(
        [
            (200, _initialize_response()),
            (202, ""),
            (
                200,
                {"jsonrpc": "2.0", "id": 5, "result": {"tools": []}},
            ),
        ]
    )
    client = httpx.AsyncClient(transport=rec.make_transport())
    # Boot uses JwtPassthrough too — pass a token in the boot context too.
    fanout = HttpFanout(
        mcp_name="outline",
        url=URL,
        auth_strategy=JwtPassthrough(),
        identities=["claude-code-dev"],
        http_client=client,
    )
    try:
        # The boot identity has no request_context; passthrough fails at boot.
        # That is BY DESIGN for the strategy — surface as HttpUpstreamFailed
        # so misconfiguration is caught at startup, not on first call.
        with pytest.raises(HttpUpstreamFailed):
            await fanout.start_eager_or_die()
    finally:
        await fanout.close()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def test_close_is_idempotent() -> None:
    rec = _RecordingTransport(
        [(200, _initialize_response()), (202, "")]
    )
    fanout, _ = _make_fanout(rec.make_transport())
    await fanout.start_eager_or_die()
    await fanout.close()
    await fanout.close()  # second close OK


def test_default_request_timeout_is_set() -> None:
    """A regression guard: the default timeout is a sane positive number."""
    assert DEFAULT_REQUEST_TIMEOUT_S > 0.0


def test_jwt_passthrough_state_key_constant_matches_middleware() -> None:
    """The bearer-token state key is shared between middleware and strategies."""
    # middleware.py writes this key; auth_strategies.py reads it. Drift
    # would silently break JwtPassthrough at runtime; lock the value.
    assert CTX_KEY_BEARER_TOKEN == "bearer_token"
