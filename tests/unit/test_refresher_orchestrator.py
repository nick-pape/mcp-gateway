"""Tests for TokenRefresher orchestrator + RefresherManager + factory helpers."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_hub.factory import build_refresher_manager, parse_duration
from mcp_hub.policy import HubConfig
from mcp_hub.refresher import (
    RefresherManager,
    Token,
    TokenMintError,
    TokenRefresher,
    TokenWriteError,
)

# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------


class _StubSource:
    name = "stub"

    def __init__(
        self,
        *,
        ttl_s: int = 900,
        fail_n: int = 0,
        fail_with: type[BaseException] = TokenMintError,
    ) -> None:
        self.ttl_s = ttl_s
        self.calls = 0
        self._fail_n = fail_n
        self._fail_with = fail_with
        self.closed = False

    async def mint(self) -> Token:
        self.calls += 1
        if self.calls <= self._fail_n:
            raise self._fail_with("planned failure")
        return Token(
            value=f"token-{self.calls}",
            expires_at=datetime.now(UTC) + timedelta(seconds=self.ttl_s),
        )

    async def close(self) -> None:
        self.closed = True


class _StubSink:
    name = "stub"

    def __init__(self, *, fail_n: int = 0) -> None:
        self.writes: list[str] = []
        self._fail_n = fail_n
        self.closed = False

    async def write(self, token: Token) -> None:
        if len(self.writes) < self._fail_n:
            self.writes.append(token.value)
            raise TokenWriteError("planned write failure")
        self.writes.append(token.value)

    async def close(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# parse_duration
# ---------------------------------------------------------------------------


class TestParseDuration:
    def test_minutes(self) -> None:
        assert parse_duration("minutes=10") == timedelta(minutes=10)

    def test_seconds(self) -> None:
        assert parse_duration("seconds=30") == timedelta(seconds=30)

    def test_zero(self) -> None:
        assert parse_duration("seconds=0") == timedelta(0)

    def test_unknown_unit(self) -> None:
        with pytest.raises(ValueError, match="unknown duration unit"):
            parse_duration("fortnights=1")

    def test_no_equals(self) -> None:
        with pytest.raises(ValueError, match="unit=N"):
            parse_duration("10 minutes")

    def test_non_int_value(self) -> None:
        with pytest.raises(ValueError, match="must be an integer"):
            parse_duration("minutes=ten")

    def test_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            parse_duration("minutes=-5")


# ---------------------------------------------------------------------------
# TokenRefresher.mint_initial
# ---------------------------------------------------------------------------


async def test_mint_initial_writes_to_sink() -> None:
    src = _StubSource()
    sink = _StubSink()
    r = TokenRefresher(
        name="test", source=src, sink=sink, rotate_every=timedelta(minutes=10)
    )
    token = await r.mint_initial()
    assert token.value == "token-1"
    assert sink.writes == ["token-1"]
    assert r.last_token is token
    assert r.consecutive_failures == 0


async def test_mint_initial_propagates_source_failure() -> None:
    src = _StubSource(fail_n=1)
    sink = _StubSink()
    r = TokenRefresher(
        name="test", source=src, sink=sink, rotate_every=timedelta(minutes=10)
    )
    with pytest.raises(TokenMintError):
        await r.mint_initial()
    assert sink.writes == []
    assert r.last_token is None


# ---------------------------------------------------------------------------
# RefresherManager.mint_initial
# ---------------------------------------------------------------------------


async def test_manager_initial_mints_in_parallel() -> None:
    s1, k1 = _StubSource(), _StubSink()
    s2, k2 = _StubSource(), _StubSink()
    mgr = RefresherManager(
        [
            TokenRefresher(name="a", source=s1, sink=k1, rotate_every=timedelta(minutes=10)),
            TokenRefresher(name="b", source=s2, sink=k2, rotate_every=timedelta(minutes=10)),
        ]
    )
    await mgr.mint_initial()
    assert k1.writes == ["token-1"]
    assert k2.writes == ["token-1"]


async def test_manager_initial_raises_with_context_on_partial_failure() -> None:
    s1, k1 = _StubSource(), _StubSink()
    s2, k2 = _StubSource(fail_n=99), _StubSink()
    mgr = RefresherManager(
        [
            TokenRefresher(name="ok", source=s1, sink=k1, rotate_every=timedelta(minutes=10)),
            TokenRefresher(name="bad", source=s2, sink=k2, rotate_every=timedelta(minutes=10)),
        ]
    )
    with pytest.raises(RuntimeError, match="initial mint failed for 1/2"):
        await mgr.mint_initial()
    # On manager failure, close() runs — sources should report closed.
    assert s1.closed and s2.closed


def test_manager_rejects_duplicate_names() -> None:
    r1 = TokenRefresher(name="dup", source=_StubSource(), sink=_StubSink(), rotate_every=timedelta(minutes=10))
    r2 = TokenRefresher(name="dup", source=_StubSource(), sink=_StubSink(), rotate_every=timedelta(minutes=10))
    with pytest.raises(ValueError, match="duplicate refresher names"):
        RefresherManager([r1, r2])


# ---------------------------------------------------------------------------
# Background rotation
# ---------------------------------------------------------------------------


async def test_background_rotation_re_mints(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set rotate_every very short so the loop runs N times quickly."""
    src = _StubSource(ttl_s=60)
    sink = _StubSink()
    r = TokenRefresher(
        name="test",
        source=src,
        sink=sink,
        # rotate_every is small but MIN_SLEEP clamps to 10s; monkeypatch
        # MIN_SLEEP for fast tests.
        rotate_every=timedelta(milliseconds=10),
    )
    monkeypatch.setattr("mcp_hub.refresher.orchestrator.MIN_SLEEP", timedelta(milliseconds=10))
    # Also override _compute_sleep to ignore safety_buffer math (test speed).
    r._compute_sleep = lambda token: timedelta(milliseconds=10)  # type: ignore[method-assign]

    mgr = RefresherManager([r])
    await mgr.mint_initial()
    mgr.start_background()
    # Let the loop run a bit.
    await asyncio.sleep(0.2)
    await mgr.close()
    # Should have at least 3 mints (initial + a few rotations).
    assert src.calls >= 3
    assert len(sink.writes) >= 3
    assert src.closed and sink.closed


async def test_background_loop_survives_transient_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mint fails twice (transient), then succeeds; loop should keep going."""
    src = _StubSource(fail_n=2)
    sink = _StubSink()
    r = TokenRefresher(
        name="test",
        source=src,
        sink=sink,
        rotate_every=timedelta(milliseconds=10),
        initial_backoff=timedelta(milliseconds=10),
        max_backoff=timedelta(milliseconds=20),
    )
    monkeypatch.setattr("mcp_hub.refresher.orchestrator.MIN_SLEEP", timedelta(milliseconds=10))
    r._compute_sleep = lambda token: timedelta(milliseconds=10)  # type: ignore[method-assign]

    mgr = RefresherManager([r])
    # mint_initial would propagate the first failure; skip it and use background only.
    mgr.start_background()
    await asyncio.sleep(0.2)
    await mgr.close()
    # After a few attempts, the source should have moved past its fail_n threshold.
    assert src.calls >= 3
    assert len(sink.writes) >= 1


# ---------------------------------------------------------------------------
# Factory wiring (full path: HubConfig → RefresherManager)
# ---------------------------------------------------------------------------


def _minimal_hub_config(extra_token_refresh: dict[str, object]) -> HubConfig:
    """Construct the smallest valid HubConfig with a custom token_refresh."""
    return HubConfig.model_validate(
        {
            "version": 1,
            "auth": {
                "issuer": "https://auth.example/",
                "jwks_uri": "https://auth.example/jwks/",
                "audience_prefix": "mcp-",
            },
            "secret_backend": {"name": "env", "config": {}},
            "approver": {"name": "auto", "config": {}},
            "mcps": {"echo": {"command": ["echo"], "secret_env_name": "FAKE"}},
            "identities": {
                "alice": {
                    "aud": "mcp-alice",
                    "uid_base": 1001,
                    "allowed_tools": ["echo_*"],
                    "secrets": {"echo": {"path": "x", "field": "y"}},
                }
            },
            "token_refresh": extra_token_refresh,
        }
    )


def test_factory_builds_manager_with_dotted_path_plugins(tmp_path: Path) -> None:
    """End-to-end: policy.yaml → HubConfig → RefresherManager via dotted-path."""
    cfg = _minimal_hub_config(
        {
            "demo": {
                "source": {
                    "type": f"{__name__}.__StubSourceForFactory",
                    "config": {},
                },
                "sink": {
                    "type": f"{__name__}.__StubSinkForFactory",
                    "config": {"path": str(tmp_path / "out")},
                },
                "rotate_every": "minutes=10",
            }
        }
    )
    mgr = build_refresher_manager(cfg)
    assert len(mgr.refreshers) == 1
    assert mgr.refreshers[0].name == "demo"


# Plugins for the factory dotted-path test. Class names are
# double-underscored so they don't collide with the simple stubs above.


class __StubSourceForFactory:
    name = "stub"

    async def mint(self) -> Token:
        return Token(value="x", expires_at=datetime.now(UTC) + timedelta(minutes=10))

    async def close(self) -> None:
        return None


class __StubSinkForFactory:
    name = "stub"

    def __init__(self, *, path: str) -> None:
        self.path = path

    async def write(self, token: Token) -> None:
        return None

    async def close(self) -> None:
        return None


def test_factory_empty_token_refresh_yields_empty_manager() -> None:
    cfg = _minimal_hub_config({})
    mgr = build_refresher_manager(cfg)
    assert mgr.refreshers == []


def test_factory_unknown_source_type_raises_with_path() -> None:
    cfg = _minimal_hub_config(
        {
            "broken": {
                "source": {"type": "nonexistent_source", "config": {}},
                "sink": {"type": "file", "config": {"path": "/tmp/x"}},
                "rotate_every": "minutes=10",
            }
        }
    )
    with pytest.raises(ValueError, match="token_refresh.broken.source"):
        build_refresher_manager(cfg)
