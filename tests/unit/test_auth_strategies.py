"""Tests for HTTP-fanout auth strategies."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from mcp_hub.auth_strategies import (
    CTX_KEY_BEARER_TOKEN,
    AuthStrategy,
    BaoBackedBearer,
    JwtPassthrough,
    NoneStrategy,
    SecretBearer,
)
from mcp_hub.interfaces import (
    ResolvedSecret,
    SecretRef,
    SecretResolutionError,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeBackend:
    """In-memory SecretBackend that records calls."""

    name: str = "fake"

    def __init__(self) -> None:
        self.values: dict[tuple[str, str, str], str] = {}
        self.calls: list[tuple[str, str, str]] = []
        # Per-call as-agent JWT (None for the deputy path). Parallel to calls.
        self.jwts: list[str | None] = []
        self.fail_with: Exception | None = None

    def seed(self, *, mcp: str, identity: str, path: str, value: str) -> None:
        self.values[(mcp, identity, path)] = value

    async def resolve(
        self, *, mcp: str, identity: str, ref: SecretRef, jwt: str | None = None
    ) -> ResolvedSecret:
        self.calls.append((mcp, identity, ref.path))
        self.jwts.append(jwt)
        if self.fail_with is not None:
            raise self.fail_with
        key = (mcp, identity, ref.path)
        if key not in self.values:
            raise SecretResolutionError(
                f"no fake value seeded for {key}"
            )
        return ResolvedSecret(value=self.values[key])

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_bao_backed_bearer_satisfies_protocol() -> None:
    strategy = BaoBackedBearer(
        secret_backend=_FakeBackend(),
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
    )
    assert isinstance(strategy, AuthStrategy)
    assert strategy.name == "secret_bearer"


def test_jwt_passthrough_satisfies_protocol() -> None:
    strategy = JwtPassthrough()
    assert isinstance(strategy, AuthStrategy)
    assert strategy.name == "jwt_passthrough"


# ---------------------------------------------------------------------------
# BaoBackedBearer
# ---------------------------------------------------------------------------


async def test_bao_backed_bearer_emits_authorization_header() -> None:
    backend = _FakeBackend()
    backend.seed(
        mcp="outline",
        identity="claude-code-dev",
        path="services/outline/claude-code-dev",
        value="ot-tok-1",
    )
    strategy = BaoBackedBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
    )
    headers = await strategy.auth_header(
        identity="claude-code-dev", request_context={}
    )
    assert headers == {"Authorization": "Bearer ot-tok-1"}


async def test_bao_backed_bearer_uses_per_identity_path_template() -> None:
    backend = _FakeBackend()
    backend.seed(
        mcp="outline",
        identity="ironclaw",
        path="services/outline/ironclaw",
        value="iron-tok",
    )
    backend.seed(
        mcp="outline",
        identity="paperless-bot",
        path="services/outline/paperless-bot",
        value="paper-tok",
    )
    strategy = BaoBackedBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
    )
    iron = await strategy.auth_header(identity="ironclaw", request_context={})
    paper = await strategy.auth_header(
        identity="paperless-bot", request_context={}
    )
    assert iron["Authorization"] == "Bearer iron-tok"
    assert paper["Authorization"] == "Bearer paper-tok"


async def test_bao_backed_bearer_caches_results_within_ttl() -> None:
    backend = _FakeBackend()
    backend.seed(
        mcp="outline",
        identity="claude-code-dev",
        path="services/outline/claude-code-dev",
        value="t1",
    )
    strategy = BaoBackedBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        cache_ttl_s=300.0,
    )
    # Three calls should result in one backend resolve (cache hits after first).
    for _ in range(3):
        await strategy.auth_header(
            identity="claude-code-dev", request_context={}
        )
    assert len(backend.calls) == 1


async def test_bao_backed_bearer_cache_expires() -> None:
    backend = _FakeBackend()
    backend.seed(
        mcp="outline",
        identity="x",
        path="services/outline/x",
        value="v1",
    )
    # Negative TTL means every call is a miss.
    strategy = BaoBackedBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        cache_ttl_s=-1.0,
    )
    await strategy.auth_header(identity="x", request_context={})
    await strategy.auth_header(identity="x", request_context={})
    assert len(backend.calls) == 2


async def test_bao_backed_bearer_does_not_cache_failures() -> None:
    backend = _FakeBackend()
    # First call: backend fails. Strategy must not cache the failure.
    backend.fail_with = SecretResolutionError("bao 503")
    strategy = BaoBackedBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        cache_ttl_s=300.0,
    )
    with pytest.raises(SecretResolutionError):
        await strategy.auth_header(identity="x", request_context={})

    # Second call: backend recovers; strategy must retry.
    backend.fail_with = None
    backend.seed(
        mcp="outline", identity="x", path="services/outline/x", value="ok"
    )
    headers = await strategy.auth_header(identity="x", request_context={})
    assert headers == {"Authorization": "Bearer ok"}
    assert len(backend.calls) == 2


async def test_bao_backed_bearer_concurrent_requests_share_one_resolve() -> None:
    """Under contention, the strategy resolves once and serves the cached value.

    Locking around the resolve is critical: 100 concurrent calls on the
    first request should yield exactly one backend.resolve(), not 100.
    """
    backend = _FakeBackend()
    backend.seed(
        mcp="outline",
        identity="x",
        path="services/outline/x",
        value="shared",
    )
    strategy = BaoBackedBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        cache_ttl_s=300.0,
    )
    headers_list = await asyncio.gather(
        *[
            strategy.auth_header(identity="x", request_context={})
            for _ in range(50)
        ]
    )
    assert all(h["Authorization"] == "Bearer shared" for h in headers_list)
    # The double-checked-lock ensures at most one backend resolve happens.
    assert len(backend.calls) == 1


async def test_bao_backed_bearer_close_is_noop() -> None:
    backend = _FakeBackend()
    strategy = BaoBackedBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
    )
    # Strategy.close MUST NOT close the shared backend — the hub composer
    # owns the backend lifecycle.
    await strategy.close()
    # Backend is still usable.
    backend.seed(
        mcp="outline", identity="x", path="services/outline/x", value="v"
    )
    headers = await strategy.auth_header(identity="x", request_context={})
    assert headers == {"Authorization": "Bearer v"}


# ---------------------------------------------------------------------------
# SecretBearer — as-agent (per-identity autonomous vs delegated)
# ---------------------------------------------------------------------------


def test_secret_bearer_boot_capable_defaults_true() -> None:
    strategy = SecretBearer(
        secret_backend=_FakeBackend(),
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
    )
    assert strategy.boot_capable is True


def test_secret_bearer_boot_capable_false_when_all_as_agent() -> None:
    strategy = SecretBearer(
        secret_backend=_FakeBackend(),
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        as_agent_identities=frozenset({"alfred"}),
        boot_capable=False,
    )
    assert strategy.boot_capable is False


async def test_secret_bearer_as_agent_forwards_inbound_jwt() -> None:
    backend = _FakeBackend()
    backend.seed(
        mcp="outline",
        identity="alfred",
        path="services/outline/alfred",
        value="alfred-tok",
    )
    strategy = SecretBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        as_agent_identities=frozenset({"alfred"}),
    )
    headers = await strategy.auth_header(
        identity="alfred",
        request_context={CTX_KEY_BEARER_TOKEN: "alfred-inbound-jwt"},
    )
    assert headers == {"Authorization": "Bearer alfred-tok"}
    # The agent's inbound JWT was forwarded to the backend (as-agent login).
    assert backend.jwts == ["alfred-inbound-jwt"]


async def test_secret_bearer_delegated_identity_passes_no_jwt() -> None:
    backend = _FakeBackend()
    backend.seed(
        mcp="outline",
        identity="interactive",
        path="services/outline/interactive",
        value="human-tok",
    )
    # `interactive` is NOT in the as-agent set → deputy path, even though an
    # inbound JWT is present in the request context.
    strategy = SecretBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        as_agent_identities=frozenset({"alfred"}),
    )
    headers = await strategy.auth_header(
        identity="interactive",
        request_context={CTX_KEY_BEARER_TOKEN: "human-inbound-jwt"},
    )
    assert headers == {"Authorization": "Bearer human-tok"}
    # Deputy path: backend resolves with jwt=None (hub's own credentials).
    assert backend.jwts == [None]


async def test_secret_bearer_as_agent_missing_jwt_raises() -> None:
    backend = _FakeBackend()
    strategy = SecretBearer(
        secret_backend=backend,
        mcp_name="outline",
        path_template="services/outline/{identity}",
        field="api_token",
        as_agent_identities=frozenset({"alfred"}),
    )
    with pytest.raises(ValueError, match="inbound JWT is required"):
        await strategy.auth_header(identity="alfred", request_context={})


# ---------------------------------------------------------------------------
# JwtPassthrough
# ---------------------------------------------------------------------------


async def test_jwt_passthrough_forwards_bearer_from_request_context() -> None:
    strategy = JwtPassthrough()
    headers = await strategy.auth_header(
        identity="claude-code-dev",
        request_context={CTX_KEY_BEARER_TOKEN: "agent-jwt-here"},
    )
    assert headers == {"Authorization": "Bearer agent-jwt-here"}


async def test_jwt_passthrough_raises_when_token_absent() -> None:
    strategy = JwtPassthrough()
    with pytest.raises(ValueError, match="missing"):
        await strategy.auth_header(identity="x", request_context={})


async def test_jwt_passthrough_raises_when_token_empty() -> None:
    strategy = JwtPassthrough()
    request_context: dict[str, Any] = {CTX_KEY_BEARER_TOKEN: ""}
    with pytest.raises(ValueError, match="missing"):
        await strategy.auth_header(identity="x", request_context=request_context)


async def test_jwt_passthrough_close_is_noop() -> None:
    strategy = JwtPassthrough()
    await strategy.close()
    # Still usable afterward.
    headers = await strategy.auth_header(
        identity="x",
        request_context={CTX_KEY_BEARER_TOKEN: "tok"},
    )
    assert headers == {"Authorization": "Bearer tok"}


# ---------------------------------------------------------------------------
# NoneStrategy
# ---------------------------------------------------------------------------


def test_none_strategy_satisfies_protocol() -> None:
    strategy = NoneStrategy()
    assert isinstance(strategy, AuthStrategy)
    assert strategy.name == "none"


async def test_none_strategy_returns_empty_headers() -> None:
    strategy = NoneStrategy()
    headers = await strategy.auth_header(
        identity="any", request_context={"anything": 1}
    )
    assert headers == {}


async def test_none_strategy_close_is_noop() -> None:
    strategy = NoneStrategy()
    await strategy.close()
    # Still usable afterward.
    headers = await strategy.auth_header(identity="x", request_context={})
    assert headers == {}
