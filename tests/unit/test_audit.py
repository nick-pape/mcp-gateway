"""Tests for the audit module."""

from __future__ import annotations

import io
import json
import re

from mcp_hub.audit import (
    Audit,
    AuditLine,
    hash_args,
    new_request_id,
    now_iso,
)
from mcp_hub.errors import ErrorCode

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_new_request_id_is_ulid_format() -> None:
    """ULID = 26 chars from Crockford's base-32 alphabet."""
    rid = new_request_id()
    assert len(rid) == 26
    assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", rid), rid


def test_new_request_id_is_unique() -> None:
    """No collisions across a few calls."""
    ids = {new_request_id() for _ in range(100)}
    assert len(ids) == 100


def test_hash_args_starts_with_sha256_prefix() -> None:
    h = hash_args({"x": 1})
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64  # hex-encoded 32-byte digest


def test_hash_args_is_order_independent() -> None:
    """Reordering keys must not change the hash."""
    a = hash_args({"x": 1, "y": 2, "z": 3})
    b = hash_args({"z": 3, "x": 1, "y": 2})
    c = hash_args({"y": 2, "x": 1, "z": 3})
    assert a == b == c


def test_hash_args_is_value_sensitive() -> None:
    """Different values produce different hashes."""
    a = hash_args({"x": 1})
    b = hash_args({"x": 2})
    assert a != b


def test_hash_args_is_deterministic_for_unicode() -> None:
    """ensure_ascii guarantees stable bytes regardless of platform."""
    a = hash_args({"name": "café"})
    b = hash_args({"name": "café"})
    assert a == b


def test_now_iso_format_ends_with_z() -> None:
    ts = now_iso()
    assert ts.endswith("Z")
    # YYYY-MM-DDTHH:MM:SS.mmmZ
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", ts), ts


# ---------------------------------------------------------------------------
# AuditLine
# ---------------------------------------------------------------------------


def test_audit_line_serializes_required_fields_only() -> None:
    """None fields are omitted from the JSON output."""
    line = AuditLine(
        ts="2026-05-05T17:00:00.000Z",
        request_id="01HXY00000000000000000000",
        method="tools/list",
        status="ok",
    )
    parsed = json.loads(line.to_json_line())
    assert parsed == {
        "ts": "2026-05-05T17:00:00.000Z",
        "request_id": "01HXY00000000000000000000",
        "method": "tools/list",
        "status": "ok",
    }


def test_audit_line_includes_optional_fields_when_set() -> None:
    line = AuditLine(
        ts="2026-05-05T17:00:00.000Z",
        request_id="01HXY00000000000000000000",
        method="tools/call",
        status="ok",
        identity="ironclaw",
        tool="technitium_dhcp_list_reservations",
        args_hash="sha256:deadbeef",
        decision="auto-approve",
        fanout="technitium",
        child_uid=1001,
        duration_ms=142,
        hitl_duration_ms=0,
    )
    parsed = json.loads(line.to_json_line())
    assert parsed["identity"] == "ironclaw"
    assert parsed["tool"] == "technitium_dhcp_list_reservations"
    assert parsed["args_hash"] == "sha256:deadbeef"
    assert parsed["fanout"] == "technitium"
    assert parsed["child_uid"] == 1001


def test_audit_line_with_error_code_uses_string_enum_value() -> None:
    """ErrorCode passed via .value lands as a string in JSON."""
    line = AuditLine(
        ts="2026-05-05T17:00:00.000Z",
        request_id="01HXY00000000000000000000",
        method="tools/call",
        status="error",
        error_code=ErrorCode.POLICY_HITL_REJECTED.value,
    )
    parsed = json.loads(line.to_json_line())
    assert parsed["error_code"] == "POLICY_HITL_REJECTED"


def test_audit_line_serialization_is_deterministic() -> None:
    """Same input → same byte-exact output (keys sorted)."""
    line = AuditLine(
        ts="2026-05-05T17:00:00.000Z",
        request_id="01HXY00000000000000000000",
        method="tools/call",
        status="ok",
        identity="ironclaw",
        tool="echo_tool",
    )
    a = line.to_json_line()
    b = line.to_json_line()
    assert a == b
    # Keys must be in sorted order:
    assert a.startswith('{"identity":')


def test_audit_line_no_trailing_newline() -> None:
    """to_json_line returns a bare line; the sink adds the newline."""
    line = AuditLine(
        ts="x",
        request_id="r",
        method="m",
        status="s",
    )
    assert not line.to_json_line().endswith("\n")


# ---------------------------------------------------------------------------
# Audit sink
# ---------------------------------------------------------------------------


def test_audit_emits_one_line_per_call() -> None:
    sink = io.StringIO()
    audit = Audit(sink=sink)
    audit.emit(
        AuditLine(
            ts="2026-05-05T17:00:00.000Z",
            request_id="01HXY00000000000000000000",
            method="tools/list",
            status="ok",
        )
    )
    audit.emit(
        AuditLine(
            ts="2026-05-05T17:00:00.001Z",
            request_id="01HXY00000000000000000001",
            method="tools/call",
            status="ok",
        )
    )
    text = sink.getvalue()
    lines = text.split("\n")
    assert lines[-1] == ""  # trailing newline → empty last entry
    assert len(lines) == 3
    assert json.loads(lines[0])["request_id"].endswith("00000")
    assert json.loads(lines[1])["request_id"].endswith("00001")


def test_audit_default_sink_is_stderr(capsys: object) -> None:
    """When no sink is provided, audit lines land on stderr."""
    # Capsys captures stderr automatically.
    audit = Audit()
    audit.emit(
        AuditLine(
            ts="2026-05-05T17:00:00.000Z",
            request_id="01HXY00000000000000000000",
            method="tools/call",
            status="ok",
        )
    )
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "01HXY00000000000000000000" in captured.err
    assert "01HXY00000000000000000000" not in captured.out
