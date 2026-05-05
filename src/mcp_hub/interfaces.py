"""Pluggable interface contracts.

Two backends are pluggable from day 1, both selected via `policy.yaml`:

- :class:`SecretBackend` — resolves per-identity secrets at boot. Production
  impl is :class:`mcp_hub.secrets.bao.BaoSecretBackend` (Phase 6b); the
  testing impl :class:`mcp_hub.secrets.env.EnvSecretBackend` (this phase)
  reads from environment variables.

- :class:`Approver` — decides HITL approval for `call_tool`. Production impl
  is :class:`mcp_hub.approvers.ntfy.NtfyApprover` (Phase 7); testing impls
  are :class:`mcp_hub.approvers.auto.AutoApprover` (always approve) and
  :class:`mcp_hub.approvers.reject.RejectApprover` (always reject).

Both are :func:`typing.runtime_checkable` Protocols so tests can
`isinstance(x, SecretBackend)`-assert conformance.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Secret backend
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecretRef:
    """Where to find a secret in the backend's namespace.

    For bao: ``path`` is the KV v2 path (e.g.
    ``secret/data/services/technitium/ironclaw``) and ``field`` is the
    JSON key within ``data`` (e.g. ``api_token``).
    """

    path: str
    field: str


@dataclass(frozen=True, slots=True)
class ResolvedSecret:
    """The secret value plus optional metadata about its lifetime."""

    value: str
    ttl_s: int | None = None


class SecretResolutionError(Exception):
    """Raised when a backend cannot produce the requested secret.

    Always treated as fatal during eager-spawn — failing one identity at
    boot is failing the whole stack (per design choice 2).
    """


@runtime_checkable
class SecretBackend(Protocol):
    """Resolves secrets at fanout-boot time per ``(mcp, identity)`` tuple.

    Implementations must be safe to call concurrently from a single event
    loop (the Fanout resolves N identities in sequence, but parallelism
    may be added later).
    """

    name: str

    async def resolve(
        self,
        *,
        mcp: str,
        identity: str,
        ref: SecretRef,
    ) -> ResolvedSecret:
        """Return the secret for the given (mcp, identity, ref).

        Raises :class:`SecretResolutionError` on any failure — including
        missing keys, network errors, and policy denials.
        """
        ...

    async def close(self) -> None:
        """Release resources (HTTP clients, sockets, etc.)."""
        ...


# ---------------------------------------------------------------------------
# Approver
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Inputs an approver needs to decide on a HITL-gated tool call."""

    request_id: str
    identity: str
    tool: str
    args: dict[str, object]
    # Human-readable rendering of args, suitable for a push notification
    # body. The hub computes this; approvers should not re-render.
    args_summary: str


class ApprovalResult(StrEnum):
    """Outcome of a HITL approval request."""

    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


@runtime_checkable
class Approver(Protocol):
    """Decides approval for HITL-gated tool calls.

    Implementations must be safe to call concurrently from many tasks —
    the hub may have N pending approvals at once (subject to per-identity
    rate limits, see :class:`mcp_hub.approvers.ntfy.NtfyApprover`).
    """

    name: str

    async def request_approval(
        self,
        request: ApprovalRequest,
        timeout_s: float,
    ) -> ApprovalResult:
        """Block until the approver returns a decision or the timeout fires.

        Must always return one of :class:`ApprovalResult`'s values; never
        raise to the caller. Internal errors map to ``REJECTED`` to fail
        closed.
        """
        ...

    async def close(self) -> None:
        """Release resources (HTTP clients, sockets, etc.)."""
        ...
