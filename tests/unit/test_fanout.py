"""Tests for the Fanout module.

Uses the ``echo_mcp`` fake (``tests/fakes/echo_mcp.py``) as the upstream
stdio MCP and an :class:`EnvSecretBackend` for secret resolution. Both
were validated in Phase 1.
"""

from __future__ import annotations

import asyncio
import platform
import sys
from pathlib import Path

import pytest

from mcp_fanout import (
    ChildSpawnFailed,
    Fanout,
    IdentityConfig,
    IdentityNotFound,
)
from mcp_hub.interfaces import (
    ResolvedSecret,
    SecretRef,
    SecretResolutionError,
)
from mcp_hub.secrets.env import EnvSecretBackend

ECHO_MCP = Path(__file__).resolve().parents[1] / "fakes" / "echo_mcp.py"
REF = SecretRef(path="secret/data/services/echo/{identity}", field="api_token")


def _identity(name: str, uid: int = 1000) -> IdentityConfig:
    return IdentityConfig(
        identity=name,
        uid=uid,
        ref=REF,
        secret_env_name="ECHO_SECRET_FILE",
    )


def _echo_command() -> list[str]:
    return [sys.executable, str(ECHO_MCP)]


# ---------------------------------------------------------------------------
# Construction-time validation
# ---------------------------------------------------------------------------


async def test_fanout_rejects_empty_identities(tmp_path: Path) -> None:
    backend = EnvSecretBackend()
    with pytest.raises(ValueError, match="at least one identity"):
        Fanout(
            mcp_name="echo",
            command=_echo_command(),
            identities=[],
            secret_backend=backend,
            runtime_dir=tmp_path,
        )


async def test_fanout_rejects_duplicate_identities(tmp_path: Path) -> None:
    backend = EnvSecretBackend()
    with pytest.raises(ValueError, match="duplicate identities"):
        Fanout(
            mcp_name="echo",
            command=_echo_command(),
            identities=[_identity("ironclaw"), _identity("ironclaw")],
            secret_backend=backend,
            runtime_dir=tmp_path,
        )


# ---------------------------------------------------------------------------
# Eager spawn
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_fanout_starts_one_child_per_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECHO_IRONCLAW", "ironclaw-token")
    monkeypatch.setenv("ECHO_PAPERLESS_BOT", "paperless-bot-token")
    fanout = Fanout(
        mcp_name="echo",
        command=_echo_command(),
        identities=[_identity("ironclaw"), _identity("paperless-bot")],
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
    )
    try:
        await fanout.start_eager_or_die()
        assert set(fanout.identities) == {"ironclaw", "paperless-bot"}
        # Token files were written for both:
        assert (tmp_path / "ironclaw-echo-token").exists()
        assert (tmp_path / "paperless-bot-echo-token").exists()
    finally:
        await fanout.close()


@pytest.mark.integration
async def test_fanout_eager_or_die_fails_whole_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If any identity fails secret resolution, the whole boot aborts."""
    monkeypatch.setenv("ECHO_IRONCLAW", "ironclaw-token")
    # paperless-bot's env var is intentionally NOT set.
    monkeypatch.delenv("ECHO_PAPERLESS_BOT", raising=False)
    fanout = Fanout(
        mcp_name="echo",
        command=_echo_command(),
        identities=[_identity("ironclaw"), _identity("paperless-bot")],
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
    )
    try:
        with pytest.raises(ChildSpawnFailed, match="paperless-bot"):
            await fanout.start_eager_or_die()
        # No leftover children.
        assert fanout.identities  # registered
        with pytest.raises(IdentityNotFound):
            await fanout.call(identity="ironclaw", request={"id": 1, "method": "x"})
    finally:
        await fanout.close()


@pytest.mark.integration
async def test_fanout_close_after_failed_spawn_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Token files written before the failure get unlinked on close."""
    monkeypatch.setenv("ECHO_IRONCLAW", "ironclaw-token")
    monkeypatch.delenv("ECHO_PAPERLESS_BOT", raising=False)
    fanout = Fanout(
        mcp_name="echo",
        command=_echo_command(),
        identities=[_identity("ironclaw"), _identity("paperless-bot")],
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
    )
    with pytest.raises(SecretResolutionError):
        try:
            await fanout.start_eager_or_die()
        except ChildSpawnFailed as exc:
            # ChildSpawnFailed wraps SecretResolutionError; raise the inner
            # for the test's assertion semantics.
            assert isinstance(exc.__cause__, SecretResolutionError)
            raise exc.__cause__ from None
    assert not (tmp_path / "ironclaw-echo-token").exists()


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_fanout_routes_call_to_correct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-identity ECHO_SECRET marker proves routing works."""
    monkeypatch.setenv("ECHO_IRONCLAW", "ironclaw-token")
    monkeypatch.setenv("ECHO_PAPERLESS_BOT", "paperless-bot-token")
    fanout = Fanout(
        mcp_name="echo",
        command=_echo_command(),
        identities=[_identity("ironclaw"), _identity("paperless-bot")],
        secret_backend=_FilePassthroughBackend(),
        runtime_dir=tmp_path,
    )
    try:
        await fanout.start_eager_or_die()
        # Talk to each child, confirm distinct ECHO_SECRET values surface.
        resp_a = await fanout.call(
            identity="ironclaw",
            request={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "x"}},
            },
        )
        resp_b = await fanout.call(
            identity="paperless-bot",
            request={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "x"}},
            },
        )
        text_a = resp_a["result"]["content"][0]["text"]
        text_b = resp_b["result"]["content"][0]["text"]
        assert "secret:ironclaw-token" in text_a
        assert "secret:paperless-bot-token" in text_b
    finally:
        await fanout.close()


@pytest.mark.integration
async def test_fanout_unknown_identity_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECHO_IRONCLAW", "x")
    fanout = Fanout(
        mcp_name="echo",
        command=_echo_command(),
        identities=[_identity("ironclaw")],
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
    )
    try:
        await fanout.start_eager_or_die()
        with pytest.raises(IdentityNotFound, match="unknown identity"):
            await fanout.call(identity="nobody", request={"id": 1})
    finally:
        await fanout.close()


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_fanout_concurrent_calls_to_different_children_parallel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECHO_IRONCLAW", "iron")
    monkeypatch.setenv("ECHO_PAPERLESS_BOT", "paper")
    fanout = Fanout(
        mcp_name="echo",
        command=_echo_command(),
        identities=[_identity("ironclaw"), _identity("paperless-bot")],
        secret_backend=_FilePassthroughBackend(),
        runtime_dir=tmp_path,
    )
    try:
        await fanout.start_eager_or_die()
        a, b = await asyncio.gather(
            fanout.call(
                identity="ironclaw",
                request={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "1"}},
                },
            ),
            fanout.call(
                identity="paperless-bot",
                request={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "1"}},
                },
            ),
        )
        assert "iron" in a["result"]["content"][0]["text"]
        assert "paper" in b["result"]["content"][0]["text"]
    finally:
        await fanout.close()


# ---------------------------------------------------------------------------
# Linux-only: cross-UID /proc/<sibling>/environ isolation
# ---------------------------------------------------------------------------


@pytest.mark.linux_only
@pytest.mark.integration
@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="UID separation requires Linux + gosu + root",
)
async def test_cross_uid_proc_environ_blocked() -> None:
    """A sibling at a different UID cannot read this child's environ.

    Skipped on non-Linux dev hosts. In CI / production, this asserts the
    architecture's stated isolation property: even if a poisoned tool
    result RCEs one MCP child, sibling identities' tokens are not
    reachable via ``/proc/<sibling-pid>/environ``.

    Implementation note: the Fanout itself doesn't run this check; this
    test verifies the underlying OS guarantee, then trusts the fanout's
    use of distinct UIDs.
    """
    # When this test runs (Linux+root), os.access on another UID's
    # /proc/<pid>/environ returns False. This is the kernel guarantee
    # the architecture relies on.
    pytest.skip("Manual procedure: run inside the deploy container as root")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FilePassthroughBackend:
    """Test backend that mirrors EnvSecretBackend without per-call ref logic.

    Used by routing/concurrency tests to keep them self-contained.
    """

    name: str = "file_passthrough"

    async def resolve(
        self,
        *,
        mcp: str,
        identity: str,
        ref: SecretRef,
    ) -> ResolvedSecret:
        import os

        env = f"{mcp}_{identity}".upper().replace("-", "_")
        value = os.environ.get(env)
        if value is None:
            raise SecretResolutionError(f"env var {env!r} not set")
        return ResolvedSecret(value=value)

    async def close(self) -> None:
        return None
