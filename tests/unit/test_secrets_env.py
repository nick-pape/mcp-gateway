"""Tests for the env-var SecretBackend."""

from __future__ import annotations

import pytest

from mcp_hub.interfaces import SecretRef, SecretResolutionError
from mcp_hub.secrets.env import EnvSecretBackend, env_var_name


@pytest.fixture
def ref() -> SecretRef:
    # Path/field are ignored by EnvSecretBackend; pass realistic values.
    return SecretRef(path="secret/data/services/technitium/ironclaw", field="api_token")


def test_env_var_name_uppercases() -> None:
    assert env_var_name("technitium", "ironclaw") == "TECHNITIUM_IRONCLAW"


def test_env_var_name_sanitizes_special_chars() -> None:
    # Hyphens and dots become underscores.
    assert env_var_name("paperless-bot", "claude.code.dev") == "PAPERLESS_BOT_CLAUDE_CODE_DEV"


def test_env_var_name_no_leading_or_trailing_underscores() -> None:
    assert env_var_name("--mcp--", "--id--") == "MCP_ID"


async def test_resolve_returns_value_when_set(
    ref: SecretRef, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TECHNITIUM_IRONCLAW", "ironclaw-token-here")
    backend = EnvSecretBackend()
    resolved = await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref)
    assert resolved.value == "ironclaw-token-here"
    assert resolved.ttl_s is None


async def test_resolve_raises_when_unset(
    ref: SecretRef, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TECHNITIUM_IRONCLAW", raising=False)
    backend = EnvSecretBackend()
    with pytest.raises(SecretResolutionError, match="TECHNITIUM_IRONCLAW"):
        await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref)


async def test_close_is_idempotent_noop() -> None:
    backend = EnvSecretBackend()
    await backend.close()
    await backend.close()  # second call also fine
