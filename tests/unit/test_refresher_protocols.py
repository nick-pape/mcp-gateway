"""Tests for refresher Protocols + value types."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from mcp_hub.refresher import Token, TokenMintError, TokenWriteError


class TestToken:
    def test_aware_datetime_accepted(self) -> None:
        exp = datetime.now(UTC) + timedelta(minutes=15)
        t = Token(value="x", expires_at=exp)
        assert t.value == "x"
        assert t.expires_at == exp

    def test_naive_datetime_rejected(self) -> None:
        # Naive datetimes silently miscompare against datetime.now(UTC) under
        # DST or non-UTC hosts. The lock-in test guards against accidentally
        # constructing one.
        with pytest.raises(ValueError, match="timezone-aware"):
            Token(value="x", expires_at=datetime.now())

    def test_non_utc_aware_accepted(self) -> None:
        # Aware-but-not-UTC is valid Python; we don't force UTC because
        # comparisons against UTC still work correctly.
        eastern = timezone(timedelta(hours=-5))
        exp = datetime.now(eastern) + timedelta(minutes=15)
        t = Token(value="x", expires_at=exp)
        assert t.expires_at.tzinfo == eastern

    def test_time_to_expiry_positive(self) -> None:
        now = datetime.now(UTC)
        exp = now + timedelta(seconds=600)
        t = Token(value="x", expires_at=exp)
        ttl = t.time_to_expiry(now=now)
        assert 599 < ttl.total_seconds() <= 600

    def test_time_to_expiry_negative_when_expired(self) -> None:
        now = datetime.now(UTC)
        t = Token(value="x", expires_at=now - timedelta(seconds=10))
        ttl = t.time_to_expiry(now=now)
        assert ttl.total_seconds() < 0


class TestExceptions:
    def test_mint_error_default_transient(self) -> None:
        exc = TokenMintError("oops")
        assert exc.transient is True

    def test_mint_error_explicit_non_transient(self) -> None:
        exc = TokenMintError("misconfig", transient=False)
        assert exc.transient is False

    def test_write_error_default_transient(self) -> None:
        exc = TokenWriteError("oops")
        assert exc.transient is True
