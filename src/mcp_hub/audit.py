"""Structured audit log.

Emits one newline-delimited JSON object per event to a configurable
sink (default: ``sys.stderr``). The schema is stable; field names
should not change without coordinating with Loki dashboards.

Example line (pretty-printed for readability — actual emission is
single-line):

.. code-block:: json

    {
      "ts": "2026-05-05T17:23:01.234+00:00",
      "request_id": "01HXY00000000000000000000",
      "identity": "ironclaw",
      "method": "tools/call",
      "tool": "technitium_dns_delete_record",
      "args_hash": "sha256:5b...",
      "decision": "auto-approve",
      "fanout": "technitium",
      "child_uid": 1001,
      "status": "ok",
      "duration_ms": 142,
      "hitl_duration_ms": 0
    }

Args are **never** logged in plaintext by default — only the SHA-256
hash of their canonical JSON encoding. This is a deliberate leak-
resistance default; per-tool overrides can unhash specific tools when
debugging is needed (Phase 8 wires that flag).
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import IO, Any

import ulid

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def new_request_id() -> str:
    """Generate a fresh ULID for use as a request_id.

    ULIDs are lexicographically sortable by creation time and contain
    millisecond-resolution timestamps, which makes Loki queries
    (sort + range) cheap.
    """
    return str(ulid.ULID())


def hash_args(args: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON encoding of ``args``.

    Canonical = sorted keys, no whitespace, ensure_ascii. This makes
    the hash invariant under key reordering — useful when comparing
    audit lines across runs.
    """
    canonical = json.dumps(
        dict(args), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def now_iso() -> str:
    """RFC 3339 timestamp with millisecond precision, UTC, ``Z`` suffix."""
    # `+00:00` → `Z` for compactness and Loki-friendliness.
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Audit line schema
# ---------------------------------------------------------------------------


@dataclass(slots=True, kw_only=True)
class AuditLine:
    """A single audit event ready to serialize.

    Every field is optional except ``ts``, ``request_id``, ``method``,
    and ``status``. ``None`` fields are omitted from the JSON output to
    keep lines compact and parseable.
    """

    ts: str
    request_id: str
    method: str
    status: str

    identity: str | None = None
    tool: str | None = None
    args_hash: str | None = None
    decision: str | None = None
    fanout: str | None = None
    child_uid: int | None = None
    duration_ms: int | None = None
    hitl_duration_ms: int | None = None
    error_code: str | None = None

    def to_json_line(self) -> str:
        """Serialize to a single-line JSON string (no trailing newline).

        ``None``-valued fields are omitted. Output is deterministic
        (sorted keys) for test stability.
        """
        d = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ---------------------------------------------------------------------------
# Sink
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Audit:
    """Emit structured JSONL audit lines to a configurable sink.

    The default sink is ``sys.stderr``; tests pass an :class:`io.StringIO`
    or similar to capture output.
    """

    sink: IO[str] = field(default_factory=lambda: sys.stderr)

    def emit(self, line: AuditLine) -> None:
        """Write a single audit line followed by a newline, then flush."""
        self.sink.write(line.to_json_line())
        self.sink.write("\n")
        self.sink.flush()
