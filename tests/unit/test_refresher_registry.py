"""Tests for the plugin registry: entry-point lookup + dotted-path fallback."""

from __future__ import annotations

import pytest

from mcp_hub.refresher import (
    PluginNotFound,
    Token,
    resolve_sink,
    resolve_source,
)

# ---------------------------------------------------------------------------
# Built-in entry-point resolution
# ---------------------------------------------------------------------------


def test_resolve_oidc_source_via_entry_point() -> None:
    """Canonical entry point resolves to the OIDC source class."""
    cls = resolve_source("oidc_client_credentials")
    assert cls.__name__ == "OidcClientCredentialsSource"
    assert callable(cls.mint)
    assert callable(cls.close)


def test_authentik_source_alias_resolves_to_same_class() -> None:
    """The pre-#13 name stays a back-compat alias for the same class."""
    assert resolve_source("authentik_client_credentials") is resolve_source(
        "oidc_client_credentials"
    )


def test_resolve_file_sink_via_entry_point() -> None:
    cls = resolve_sink("file")
    assert cls.__name__ == "FileSink"
    assert callable(cls.write)
    assert callable(cls.close)


# ---------------------------------------------------------------------------
# Misses
# ---------------------------------------------------------------------------


def test_unknown_bare_name_raises_with_helpful_message() -> None:
    with pytest.raises(PluginNotFound) as ei:
        resolve_source("does_not_exist")
    msg = str(ei.value)
    assert "does_not_exist" in msg
    assert "available" in msg


def test_empty_string_rejected() -> None:
    with pytest.raises(PluginNotFound):
        resolve_sink("")


# ---------------------------------------------------------------------------
# Dotted-path fallback
# ---------------------------------------------------------------------------


# Define a plugin-shaped class at module scope so it's importable by dotted
# path. Real third-party plugins would do the same in their own package.


class _FakeSource:
    """Minimal valid TokenSource for the dotted-path test."""

    name = "fake"

    async def mint(self) -> Token:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class _FakeSink:
    """Minimal valid TokenSink for the dotted-path test."""

    name = "fake"

    async def write(self, token: Token) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class _NotASource:
    """Missing the mint() method on purpose."""

    name = "broken"


def test_dotted_path_source_resolves() -> None:
    cls = resolve_source(f"{__name__}._FakeSource")
    assert cls is _FakeSource


def test_dotted_path_sink_resolves() -> None:
    cls = resolve_sink(f"{__name__}._FakeSink")
    assert cls is _FakeSink


def test_dotted_path_unknown_module_raises() -> None:
    with pytest.raises(PluginNotFound, match="cannot import module"):
        resolve_source("nonexistent.package.MyClass")


def test_dotted_path_unknown_attribute_raises() -> None:
    with pytest.raises(PluginNotFound, match="has no attribute"):
        resolve_source(f"{__name__}.NoSuchAttr")


def test_protocol_methods_missing_rejected() -> None:
    with pytest.raises(PluginNotFound, match="missing methods"):
        resolve_source(f"{__name__}._NotASource")
