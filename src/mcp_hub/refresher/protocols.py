"""Refresher Protocols + value types.

The contract between sources, sinks, and the orchestrator. Kept in its
own module so plugins can import it without pulling in orchestrator or
manager code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class Token:
    """A minted credential with its own absolute expiry.

    ``expires_at`` MUST be timezone-aware UTC. The orchestrator uses it
    to schedule the next mint; a naive datetime would silently compare
    against ``datetime.now(UTC)`` incorrectly under DST or non-UTC
    hosts.
    """

    value: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.expires_at.tzinfo is None:
            raise ValueError(
                "Token.expires_at must be timezone-aware (UTC); "
                "got a naive datetime"
            )

    def time_to_expiry(self, *, now: datetime | None = None) -> timedelta:
        """Seconds remaining before expiry. Negative if already expired.

        ``now`` is overridable for testing; defaults to ``datetime.now(UTC)``.
        """
        return self.expires_at - (now or datetime.now(UTC))


class TokenMintError(Exception):
    """A :class:`TokenSource` could not produce a fresh token.

    Sources MUST raise this on every failure path — never return a
    stale or partial token. The orchestrator distinguishes transient
    (retry with backoff) from persistent (give up after N attempts);
    sources can hint via the ``transient`` flag, default ``True``.
    """

    def __init__(self, message: str, *, transient: bool = True) -> None:
        super().__init__(message)
        self.transient = transient


class TokenWriteError(Exception):
    """A :class:`TokenSink` could not persist a token.

    Same retry-vs-bail semantics as :class:`TokenMintError`. Sinks
    SHOULD raise this for any failure that leaves the destination
    in an unreliable state (partial write, permission flip, etc.).
    """

    def __init__(self, message: str, *, transient: bool = True) -> None:
        super().__init__(message)
        self.transient = transient


@runtime_checkable
class TokenSource(Protocol):
    """Mints fresh credentials.

    Implementations are typically thin HTTP clients (Authentik, Vault,
    Keycloak, AWS STS, ...). They MUST be safe to call concurrently
    from a single event loop; the orchestrator serializes per-refresher
    but multiple refreshers may share a source instance.
    """

    name: str

    async def mint(self) -> Token:
        """Return a freshly minted token.

        Raises :class:`TokenMintError` on any failure — including
        network errors, auth errors, and unexpected response shapes.
        """
        ...

    async def close(self) -> None:
        """Release HTTP clients, sockets, etc. Idempotent."""
        ...


@runtime_checkable
class TokenSink(Protocol):
    """Persists tokens where consumers can read them.

    The first built-in is :class:`mcp_hub.refresher.builtins.file_sink.FileSink`
    (atomic file write). Future sinks could be bao KV, env-export
    files, named pipes, or HTTP push to a sidecar.
    """

    name: str

    async def write(self, token: Token) -> None:
        """Atomically persist ``token``.

        "Atomic" means consumers reading the destination either see
        the previous valid token or the new one — never a half-written
        or zero-byte intermediate state.

        Raises :class:`TokenWriteError` on any failure.
        """
        ...

    async def close(self) -> None:
        """Release resources. Idempotent."""
        ...


__all__ = [
    "Token",
    "TokenMintError",
    "TokenSink",
    "TokenSource",
    "TokenWriteError",
]
