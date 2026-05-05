"""Tests for FileSink atomic write + permissions."""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_hub.refresher import Token, TokenWriteError
from mcp_hub.refresher.builtins.file_sink import FileSink


def _token(value: str = "tok-1") -> Token:
    return Token(value=value, expires_at=datetime.now(UTC) + timedelta(minutes=10))


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_write_creates_file_with_value(tmp_path: Path) -> None:
    dest = tmp_path / "tok"
    sink = FileSink(path=dest)
    await sink.write(_token("hello"))
    await sink.close()
    assert dest.read_text() == "hello"


async def test_write_replaces_existing_file_atomically(tmp_path: Path) -> None:
    dest = tmp_path / "tok"
    dest.write_text("old")
    sink = FileSink(path=dest)
    await sink.write(_token("new"))
    await sink.close()
    assert dest.read_text() == "new"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode semantics only")
async def test_default_mode_is_0400(tmp_path: Path) -> None:
    dest = tmp_path / "tok"
    sink = FileSink(path=dest)
    await sink.write(_token())
    actual = dest.stat().st_mode & 0o777
    assert actual == 0o400


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode semantics only")
async def test_custom_mode_int(tmp_path: Path) -> None:
    dest = tmp_path / "tok"
    sink = FileSink(path=dest, mode=0o600)
    await sink.write(_token())
    assert (dest.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode semantics only")
async def test_mode_accepts_string_octal(tmp_path: Path) -> None:
    """YAML 1.1 doesn't parse 0o400 as octal — string form must work."""
    dest = tmp_path / "tok"
    sink = FileSink(path=dest, mode="0o600")
    await sink.write(_token())
    assert (dest.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode semantics only")
async def test_mode_accepts_string_no_prefix(tmp_path: Path) -> None:
    # int(s, 0) parses '0400' as octal too.
    dest = tmp_path / "tok"
    sink = FileSink(path=dest, mode="0600")
    await sink.write(_token())
    assert (dest.stat().st_mode & 0o777) == 0o600


def test_mode_string_must_be_numeric() -> None:
    with pytest.raises(ValueError, match="numeric string"):
        FileSink(path="/tmp/whatever", mode="not-a-mode")


def test_owner_gid_without_uid_rejected() -> None:
    with pytest.raises(ValueError, match="without owner_uid"):
        FileSink(path="/tmp/whatever", owner_gid=100)


# ---------------------------------------------------------------------------
# Atomicity / failure handling
# ---------------------------------------------------------------------------


async def test_no_partial_state_visible_during_write(tmp_path: Path) -> None:
    """The destination should never be observable as zero-byte / half-written.

    Hard to truly observe without thread interleaving; instead we
    verify that the implementation uses a tmp file (visible in dir
    listing only briefly during write) and that the dest file has
    the FULL value once write() returns.
    """
    dest = tmp_path / "tok"
    dest.write_text("previous-valid")
    sink = FileSink(path=dest)
    await sink.write(_token("brand-new-value"))
    # After write returns, no .tmp files should remain.
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp." in p.name]
    assert leftovers == []
    assert dest.read_text() == "brand-new-value"


async def test_nonwritable_parent_raises_token_write_error(tmp_path: Path) -> None:
    # Point at a path under a file (not a dir) so parent.mkdir + os.open both fail.
    bad_parent = tmp_path / "i-am-a-file"
    bad_parent.write_text("blocking")
    dest = bad_parent / "tok"
    sink = FileSink(path=dest)
    with pytest.raises(TokenWriteError):
        await sink.write(_token())


async def test_creates_parent_dir(tmp_path: Path) -> None:
    dest = tmp_path / "newly-created-subdir" / "tok"
    sink = FileSink(path=dest)
    await sink.write(_token("x"))
    assert dest.read_text() == "x"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only failure mode")
async def test_chown_failure_propagates_as_token_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """chown must raise TokenWriteError, not be silently swallowed."""

    def boom(*_: object, **__: object) -> None:
        raise PermissionError("CAP_CHOWN missing")

    monkeypatch.setattr(os, "chown", boom)
    sink = FileSink(path=tmp_path / "tok", owner_uid=1234)
    with pytest.raises(TokenWriteError, match="chown"):
        await sink.write(_token())
    # tmp file cleaned up on failure
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp." in p.name]
    assert leftovers == []
