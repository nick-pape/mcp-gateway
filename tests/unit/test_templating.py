"""Tests for the config placeholder expander (#18)."""

from __future__ import annotations

import pytest

from mcp_hub.templating import expand_template


def test_expands_identity_and_mcp() -> None:
    assert (
        expand_template("services/{mcp}/{identity}", identity="alfred", mcp="outline")
        == "services/outline/alfred"
    )


def test_identity_only() -> None:
    assert (
        expand_template("services/outline/{identity}", identity="alfred", mcp="outline")
        == "services/outline/alfred"
    )


def test_mcp_only() -> None:
    assert expand_template("mcp-{mcp}-role", identity="alfred", mcp="outline") == (
        "mcp-outline-role"
    )


def test_literal_passthrough() -> None:
    assert (
        expand_template("services/heb/shared", identity="x", mcp="heb")
        == "services/heb/shared"
    )


def test_unsupported_placeholder_raises() -> None:
    # {aud} is deliberately unsupported.
    with pytest.raises(ValueError, match="unsupported placeholder"):
        expand_template("services/{aud}", identity="x", mcp="m")


def test_unknown_named_placeholder_raises() -> None:
    with pytest.raises(ValueError, match="unsupported placeholder"):
        expand_template("services/{foo}/{identity}", identity="x", mcp="m")


def test_malformed_brace_raises() -> None:
    with pytest.raises(ValueError, match="unsupported placeholder"):
        expand_template("services/{identity", identity="x", mcp="m")
