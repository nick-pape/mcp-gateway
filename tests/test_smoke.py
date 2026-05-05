"""Phase 0 smoke: packages import cleanly and toolchain runs."""

from __future__ import annotations


def test_packages_importable() -> None:
    import mcp_fanout  # noqa: F401
    import mcp_hub  # noqa: F401


def test_main_returns_nonzero() -> None:
    """The placeholder __main__ should exit nonzero until Phase 8."""
    from mcp_hub.__main__ import main

    assert main() != 0
