"""Tests for FileSecretBackend."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_hub.interfaces import SecretBackend, SecretRef, SecretResolutionError
from mcp_hub.secrets.file import FileSecretBackend


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "secrets.yaml"
    p.write_text(content)
    return p


async def test_resolves_path_and_field(tmp_path: Path) -> None:
    p = _write(tmp_path, "services/technitium/ironclaw:\n  api_token: tk_abc\n")
    backend = FileSecretBackend(path=p)
    got = await backend.resolve(
        mcp="technitium",
        identity="ironclaw",
        ref=SecretRef(path="services/technitium/ironclaw", field="api_token"),
    )
    assert got.value == "tk_abc"
    await backend.close()


async def test_resolves_multiple_fields(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "services/heb/grocery-agent:\n  heb_email: a@b.c\n  heb_password: pw\n",
    )
    backend = FileSecretBackend(path=p)
    path = "services/heb/grocery-agent"
    email = await backend.resolve(
        mcp="heb", identity="grocery-agent", ref=SecretRef(path=path, field="heb_email")
    )
    password = await backend.resolve(
        mcp="heb", identity="grocery-agent", ref=SecretRef(path=path, field="heb_password")
    )
    assert email.value == "a@b.c"
    assert password.value == "pw"
    await backend.close()


async def test_missing_path_raises(tmp_path: Path) -> None:
    p = _write(tmp_path, "services/x/y:\n  api_token: z\n")
    backend = FileSecretBackend(path=p)
    with pytest.raises(SecretResolutionError):
        await backend.resolve(
            mcp="m", identity="i", ref=SecretRef(path="nope", field="api_token")
        )


async def test_missing_field_raises(tmp_path: Path) -> None:
    p = _write(tmp_path, "services/x/y:\n  other: z\n")
    backend = FileSecretBackend(path=p)
    with pytest.raises(SecretResolutionError):
        await backend.resolve(
            mcp="m", identity="i", ref=SecretRef(path="services/x/y", field="api_token")
        )


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SecretResolutionError):
        FileSecretBackend(path=tmp_path / "nonexistent.yaml")


def test_non_mapping_top_level_raises(tmp_path: Path) -> None:
    p = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(SecretResolutionError):
        FileSecretBackend(path=p)


async def test_satisfies_protocol(tmp_path: Path) -> None:
    p = _write(tmp_path, "{}\n")
    backend = FileSecretBackend(path=p)
    assert isinstance(backend, SecretBackend)
    await backend.close()
