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

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

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
        jwt: str | None = None,
    ) -> ResolvedSecret:
        """Return the secret for the given (mcp, identity, ref).

        ``jwt`` is the "as-agent" hook: when provided, the backend should
        authenticate to its store using *that* token (the inbound agent's
        JWT) rather than its own service identity, so the store
        authenticates and audits the agent itself. Backends that don't
        support per-caller auth (``env``, ``file``) ignore it. When ``None``
        (boot path, stdio/container spawn), the backend uses its own
        credentials.

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
    # Backend MCP that owns the tool, e.g. ``technitium`` (the prefix on
    # the registered tool name). Approvers display this so the human
    # knows which subsystem is being touched.
    mcp_name: str
    # Tool name as registered with FastMCP (the prefixed form, e.g.
    # ``technitium_dns_health_check``). The unprefixed form is
    # derivable as ``tool.removeprefix(f"{mcp_name}_")``.
    tool: str
    # The agent's required justification (``args["justification"]``) for
    # push-approve calls; empty string for auto-approve cases (which
    # don't go through the approver). Surfacing this in the notification
    # is the human's primary signal for deciding.
    justification: str
    # Args sans the ``justification`` parameter (which is hub-only
    # metadata, not forwarded to the upstream tool).
    args: dict[str, object]
    # Human-readable rendering of args, suitable for a push notification
    # body. The hub computes this; approvers should not re-render.
    args_summary: str


class ApprovalResult(StrEnum):
    """Outcome of a HITL approval request."""

    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


class CallOutcome(StrEnum):
    """Final outcome of a HITL-gated call, used for receipt notifications.

    Distinguishes "approved + tool succeeded" from "approved + tool errored"
    because the human reviewer wants to know whether the work they
    authorized actually completed cleanly.
    """

    APPROVED_SUCCESS = "approved-success"
    APPROVED_ERROR = "approved-error"
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

    async def publish_outcome(
        self,
        request: ApprovalRequest,
        outcome: CallOutcome,
        *,
        result_snippet: str | None,
        wait_ms: int,
        execution_ms: int | None,
    ) -> None:
        """Send a receipt to the operator after the call resolves.

        Called by HITLMiddleware after a push-approve outcome lands —
        for every terminal state (approved+success, approved+error,
        rejected, timeout). Implementations that don't notify a human
        (AutoApprover, RejectApprover) should no-op.

        - ``result_snippet`` — for APPROVED_SUCCESS, a short rendering
          of the tool's response (truncated by middleware). For
          APPROVED_ERROR, the error message. ``None`` for REJECTED
          and TIMEOUT.
        - ``wait_ms`` — time between publish and human action / timeout.
        - ``execution_ms`` — only set for APPROVED_* outcomes; how long
          the upstream tool took to run.

        MUST NOT raise — internal errors should be logged and swallowed
        so a notification failure doesn't break the agent's response.
        """
        ...

    async def close(self) -> None:
        """Release resources (HTTP clients, sockets, etc.)."""
        ...


# ---------------------------------------------------------------------------
# Webhook callback routes (optional approver capability)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WebhookRoute:
    """An inbound callback route a push-approver wants the hub to mount.

    ``handler`` is framework-agnostic: it takes the request's query params and
    parsed JSON body and returns ``(status_code, json_body)``. The hub adapts
    it to its HTTP framework, so approvers don't import Starlette.
    """

    path: str
    methods: tuple[str, ...]
    handler: Callable[
        [Mapping[str, str], dict[str, Any]], Awaitable[tuple[int, dict[str, Any]]]
    ]


@runtime_checkable
class WebhookApprover(Protocol):
    """Optional capability: an :class:`Approver` that needs callback routes.

    Push-based approvers (ntfy, Slack, ...) implement this to self-register
    their inbound webhook(s); the hub mounts whatever they return. Approvers
    without callbacks (auto, reject) simply don't implement it.
    """

    def webhook_routes(self) -> list[WebhookRoute]: ...
