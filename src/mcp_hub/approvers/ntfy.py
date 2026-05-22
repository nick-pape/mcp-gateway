"""ntfy-based HITL approver.

Production approver: when an agent calls a tool whose policy says
``push-approve``, send a push notification to a phone via ntfy with
"Approve" / "Reject" buttons. Block until the human responds (or until
``timeout_s`` fires).

Lifecycle per :meth:`request_approval`:

1. **Rate-limit check** per identity (token bucket). If too many
   pending requests, return :attr:`ApprovalResult.REJECTED` immediately
   without sending a notification — protects the phone from a runaway
   agent.

2. **Generate unguessable nonce + ack_token** via :func:`secrets.token_urlsafe`.

3. **Write ack_token to bao** at ``hitl/pending/{nonce}`` with a
   bao-side TTL (default 5 min). This is the crash safety net: even
   if the hub dies mid-approval, bao auto-evicts and the orphaned
   entry doesn't accumulate.

4. **Publish ntfy push** with HTTP action buttons. The action URLs
   contain the nonce as a query param; the action body contains the
   ack_token. The phone POSTs back to our webhook on tap.

5. **Await an asyncio.Event** signaled by the webhook handler.

6. On completion / timeout / error: **cleanup bao entry** and
   **decrement rate-limit counter**.

Webhook handler (:meth:`handle_webhook`):

- Read the bao entry for the given nonce
- Constant-time compare of the posted ack_token against the stored one
- On match: atomically consume (kv_delete), then signal the Event
- On mismatch / missing: ignore, return 200 anyway (no oracle —
  attackers cannot probe to learn whether a nonce is pending)
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from mcp_hub.approvers.store import (
    BaoTransientStore,
    TransientStore,
    TransientStoreError,
)
from mcp_hub.bao_client import BaoClient, compare_digest
from mcp_hub.interfaces import (
    ApprovalRequest,
    ApprovalResult,
    CallOutcome,
    WebhookRoute,
)

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 120.0
_DEFAULT_ACK_TTL_S = 300
_DEFAULT_PATH_TEMPLATE = "hitl/pending/{nonce}"
_DEFAULT_RATE_LIMIT = 5
_DEFAULT_HTTP_TIMEOUT_S = 10.0


@dataclass(slots=True)
class _Pending:
    """Per-nonce event + result storage. Signaled by the webhook."""

    event: asyncio.Event = field(default_factory=asyncio.Event)
    decision: ApprovalResult | None = None


class NtfyApprover:
    """HITL approver via ntfy push notifications + bao ack-token KV."""

    name: str = "ntfy"

    def __init__(
        self,
        *,
        store: TransientStore | None = None,
        bao_client: BaoClient | None = None,
        bao_role: str = "",
        ntfy_server: str,
        # Topic to publish to. May contain ``{identity}`` as a
        # placeholder — substituted per-call from
        # ``ApprovalRequest.identity``. A static string (no placeholder)
        # works too: every approval lands on the same topic.
        # Recommended for multi-human deployments:
        # ``"mcp-hitl-{identity}"`` so each human only subscribes to
        # the identities they own.
        topic_template: str,
        publish_token_path: str | Path,
        webhook_base_url: str,
        webhook_path: str = "/hitl/ack",
        timeout_default_s: float = _DEFAULT_TIMEOUT_S,
        ack_ttl_s: int = _DEFAULT_ACK_TTL_S,
        bao_path_template: str = _DEFAULT_PATH_TEMPLATE,
        rate_limit_per_identity: int = _DEFAULT_RATE_LIMIT,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not ntfy_server.startswith(("https://", "http://")):
            raise ValueError(f"ntfy_server must be http(s)://, got {ntfy_server!r}")
        if not webhook_base_url.startswith(("https://", "http://")):
            raise ValueError(
                f"webhook_base_url must be http(s)://, got {webhook_base_url!r}"
            )
        # Validate the topic_template at construction so config errors
        # surface at boot, not at first push. Reject empty placeholders
        # like ``{}`` or unknown ones like ``{user}``.
        try:
            topic_template.format(identity="probe")
        except (KeyError, IndexError) as exc:
            raise ValueError(
                f"topic_template {topic_template!r} contains an unsupported "
                f"placeholder; only {{identity}} is recognized: {exc}"
            ) from exc
        if not topic_template:
            raise ValueError("topic_template must be non-empty")
        # Storage for pending HITL state is pluggable: an in-memory store
        # (no external dep) or a bao-backed one for crash-safety. Accept a
        # ready store, or build a bao one from the legacy bao_* args.
        if store is not None:
            self._store: TransientStore = store
        elif bao_client is not None:
            self._store = BaoTransientStore(
                bao_client=bao_client,
                bao_role=bao_role,
                path_template=bao_path_template,
            )
        else:
            raise ValueError("NtfyApprover requires either store= or bao_client=")
        self._ntfy_server = ntfy_server.rstrip("/")
        self._topic_template = topic_template
        self._publish_token_path = Path(publish_token_path)
        self._webhook_path = webhook_path
        self._webhook_url = f"{webhook_base_url.rstrip('/')}{webhook_path}"
        self._timeout_default_s = timeout_default_s
        self._ack_ttl_s = ack_ttl_s
        self._rate_limit_per_identity = rate_limit_per_identity
        self._http = http_client or httpx.AsyncClient(timeout=_DEFAULT_HTTP_TIMEOUT_S)
        self._owns_client = http_client is None

        # Pending state — per-nonce coordination between request_approval
        # and handle_webhook.
        self._pending: dict[str, _Pending] = {}
        # Per-identity counter for rate limiting; protected by lock to
        # avoid race when 6+ requests arrive simultaneously.
        self._pending_per_identity: dict[str, int] = defaultdict(int)
        self._pending_lock = asyncio.Lock()

    async def close(self) -> None:
        await self._store.close()
        if self._owns_client:
            await self._http.aclose()

    # -----------------------------------------------------------------------
    # Outcome receipt (fire-and-forget after a push-approve resolves)
    # -----------------------------------------------------------------------

    async def publish_outcome(
        self,
        request: ApprovalRequest,
        outcome: CallOutcome,
        *,
        result_snippet: str | None,
        wait_ms: int,
        execution_ms: int | None,
    ) -> None:
        """Send a follow-up "receipt" notification to the operator.

        Different visual cue than the prompt notifications: lower
        priority (informational, not urgent), no action buttons,
        outcome-specific tag/icon. Pairs with the original push so the
        operator gets explicit feedback that their tap took effect (or
        the system timed out, etc.).
        """
        try:
            publish_token = self._publish_token_path.read_text(
                encoding="utf-8"
            ).strip()
        except OSError as exc:
            logger.warning(
                "ntfy approver: cannot read publish token for receipt: %s; "
                "skipping receipt for tool=%s",
                exc, request.tool,
            )
            return

        topic = self._topic_template.format(identity=request.identity)
        title = _format_receipt_title(request, outcome)
        message = _format_receipt_body(
            request, outcome, result_snippet, wait_ms, execution_ms
        )
        payload: dict[str, Any] = {
            "topic": topic,
            "title": title,
            "message": message,
            # Lower priority than the prompt (4) — receipts are
            # informational, the user already chose / was timed out.
            "priority": 2,
            "tags": [_RECEIPT_TAGS[outcome]],
            # Deliberately no actions — receipts are read-only.
        }
        try:
            response = await self._http.post(
                self._ntfy_server,
                json=payload,
                headers={"Authorization": f"Bearer {publish_token}"},
            )
            response.raise_for_status()
        except Exception:
            # MUST NOT raise — log and swallow per the Approver protocol.
            logger.exception(
                "ntfy approver: receipt publish failed for "
                "tool=%s outcome=%s; agent response NOT affected",
                request.tool, outcome,
            )

    # -----------------------------------------------------------------------
    # Approval flow (called by the hub for each push-approve tool call)
    # -----------------------------------------------------------------------

    async def request_approval(
        self,
        request: ApprovalRequest,
        timeout_s: float,
    ) -> ApprovalResult:
        # 1. Rate-limit check.
        async with self._pending_lock:
            count = self._pending_per_identity[request.identity]
            if count >= self._rate_limit_per_identity:
                logger.warning(
                    "ntfy approver: rate limit reached for identity=%s "
                    "(pending=%d, limit=%d) — rejecting without push",
                    request.identity,
                    count,
                    self._rate_limit_per_identity,
                )
                return ApprovalResult.REJECTED
            self._pending_per_identity[request.identity] += 1

        try:
            return await self._approve_with_lifecycle(request, timeout_s)
        finally:
            async with self._pending_lock:
                self._pending_per_identity[request.identity] -= 1

    async def _approve_with_lifecycle(
        self,
        request: ApprovalRequest,
        timeout_s: float,
    ) -> ApprovalResult:
        # 2. Generate unguessable identifiers.
        nonce = secrets.token_urlsafe(32)
        ack_token = secrets.token_urlsafe(48)

        # 3. Stage the pending entry: in memory (for the waiting coroutine)
        # and in the transient store (for the webhook handler + crash-safety).
        pending = _Pending()
        self._pending[nonce] = pending

        try:
            try:
                await self._store.put(
                    nonce,
                    {
                        "ack_token": ack_token,
                        "identity": request.identity,
                        "tool": request.tool,
                    },
                    ttl_s=self._ack_ttl_s,
                )
            except TransientStoreError:
                logger.exception(
                    "ntfy approver: failed to stage ack token for "
                    "identity=%s tool=%s; failing closed",
                    request.identity,
                    request.tool,
                )
                # Fail closed per Approver Protocol contract.
                return ApprovalResult.REJECTED

            # 4. Publish to ntfy.
            try:
                await self._publish(request, nonce, ack_token)
            except (httpx.HTTPError, ValueError):
                logger.exception(
                    "ntfy approver: ntfy publish failed; cleaning up bao entry"
                )
                await self._store.delete(nonce)
                return ApprovalResult.REJECTED

            # 5. Await webhook signal.
            try:
                await asyncio.wait_for(pending.event.wait(), timeout=timeout_s)
                # decision is set atomically by handle_webhook before signaling
                # the event, so it's never None here.
                return pending.decision or ApprovalResult.REJECTED
            except TimeoutError:
                logger.info(
                    "ntfy approver: timeout for identity=%s tool=%s nonce=%s",
                    request.identity,
                    request.tool,
                    nonce,
                )
                return ApprovalResult.TIMEOUT
        finally:
            self._pending.pop(nonce, None)
            # Always best-effort cleanup of bao entry. bao TTL would do it
            # eventually, but explicit delete on completion keeps the path
            # clean for observability.
            await self._store.delete(nonce)

    async def _publish(
        self,
        request: ApprovalRequest,
        nonce: str,
        ack_token: str,
    ) -> None:
        """Publish a JSON push notification to ntfy with action buttons."""
        try:
            publish_token = self._publish_token_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(
                f"cannot read ntfy publish token at {self._publish_token_path}: {exc}"
            ) from exc

        action_url = f"{self._webhook_url}?nonce={nonce}"
        approve_body = f'{{"ack_token":"{ack_token}","decision":"approve"}}'
        reject_body = f'{{"ack_token":"{ack_token}","decision":"reject"}}'

        # Title: "<identity> wants to run <mcp_name> <unprefixed_tool>"
        # Strip the "<mcp_name>_" prefix so the title doesn't repeat
        # "technitium technitium_dns_health_check".
        unprefixed = request.tool.removeprefix(f"{request.mcp_name}_")
        title = (
            f"{request.identity} wants to run {request.mcp_name} {unprefixed}"
        )
        message = _format_notification_body(request)

        # Resolve {identity} into the topic for this call. Static
        # templates (no placeholder) format() unchanged; templates with
        # {identity} get the per-request value.
        topic = self._topic_template.format(identity=request.identity)
        payload: dict[str, Any] = {
            "topic": topic,
            "title": title,
            "message": message,
            "priority": 4,
            "actions": [
                {
                    "action": "http",
                    "label": "Approve",
                    "url": action_url,
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "body": approve_body,
                    "clear": True,
                },
                {
                    "action": "http",
                    "label": "Reject",
                    "url": action_url,
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "body": reject_body,
                    "clear": True,
                },
            ],
        }
        response = await self._http.post(
            self._ntfy_server,
            json=payload,
            headers={"Authorization": f"Bearer {publish_token}"},
        )
        response.raise_for_status()

    # -----------------------------------------------------------------------
    # Webhook handler (called by the hub server for POST /hitl/ack)
    # -----------------------------------------------------------------------

    def webhook_routes(self) -> list[WebhookRoute]:
        """Self-register the /hitl/ack callback (WebhookApprover capability)."""

        async def _handle(
            query: Mapping[str, str], body: dict[str, Any]
        ) -> tuple[int, dict[str, Any]]:
            status = await self.handle_webhook(nonce=query.get("nonce", ""), body=body)
            return status, {"ok": True}

        return [
            WebhookRoute(path=self._webhook_path, methods=("POST",), handler=_handle)
        ]

    async def handle_webhook(
        self,
        *,
        nonce: str,
        body: Mapping[str, Any],
    ) -> int:
        """Process an inbound /hitl/ack webhook. Always returns HTTP 200.

        The "always 200, no oracle" property is critical: an attacker
        who can hit the webhook endpoint must NOT be able to probe
        which nonces are pending by observing different status codes
        for valid vs. invalid inputs. We log internally but always
        respond 200.
        """
        posted_ack = body.get("ack_token")
        decision = body.get("decision")

        if not isinstance(posted_ack, str) or decision not in ("approve", "reject"):
            logger.info(
                "ntfy webhook: malformed body for nonce=%s; ignoring",
                _redact(nonce),
            )
            return 200

        # Read the staged ack_token. If it's gone (TTL expired, already
        # consumed via double-tap, or never existed), silently ignore — the
        # no-oracle property means we still return 200 regardless.
        stored = await self._store.get(nonce)
        if stored is None:
            logger.info(
                "ntfy webhook: stale ack ignored for nonce=%s "
                "(already consumed or expired)",
                _redact(nonce),
            )
            return 200

        stored_ack = stored.get("ack_token")
        if not isinstance(stored_ack, str) or not compare_digest(stored_ack, posted_ack):
            logger.info(
                "ntfy webhook: ack_token mismatch for nonce=%s; ignoring",
                _redact(nonce),
            )
            return 200

        # Atomic consumption: delete the entry BEFORE signaling. If we crashed
        # between signal and delete, a replay could re-trigger; delete first.
        await self._store.delete(nonce)

        pending = self._pending.get(nonce)
        if pending is None:
            # Webhook arrived before request_approval registered the
            # pending entry, OR after the request_approval timed out and
            # cleaned up. Either way, no in-flight caller — silently drop.
            logger.info(
                "ntfy webhook: no in-flight pending for nonce=%s (timed out?); ignoring",
                _redact(nonce),
            )
            return 200

        pending.decision = (
            ApprovalResult.APPROVED if decision == "approve" else ApprovalResult.REJECTED
        )
        pending.event.set()
        return 200

    # -----------------------------------------------------------------------
    # Test introspection (small surface, kept separate from public API)
    # -----------------------------------------------------------------------

    @property
    def pending_count_for_identity(self) -> Mapping[str, int]:
        """Read-only view of the pending-per-identity counter (for tests)."""
        return self._pending_per_identity


def _redact(s: str) -> str:
    """Show first 4 chars of an opaque identifier for logging."""
    if len(s) <= 8:
        return "****"
    return s[:4] + "..."


def _format_notification_body(
    request: ApprovalRequest,
    *,
    max_value_len: int = 80,
    max_args_block: int = 800,
) -> str:
    """Compose the ntfy notification body.

    Layout (the human's primary decision context):

    .. code-block:: text

        <justification>

        param1: value1
        param2: value2
        …

    No markdown — ntfy's Android app renders it raw and we want it
    readable everywhere. Long values are truncated; the args block is
    capped so a runaway args dict can't blow past ntfy's body limit.
    """
    parts: list[str] = []
    if request.justification:
        parts.append(request.justification)

    if request.args:
        if parts:
            parts.append("")  # blank line separator
        arg_lines: list[str] = []
        running_len = 0
        for k, v in request.args.items():
            line = f"{k}: {_short_value(v, max_value_len)}"
            if running_len + len(line) + 1 > max_args_block:
                arg_lines.append("…")
                break
            arg_lines.append(line)
            running_len += len(line) + 1
        parts.extend(arg_lines)

    return "\n".join(parts) if parts else "(no details)"


def _short_value(v: object, max_len: int) -> str:
    """Render an arg value compactly: scalars as ``str``, complex as JSON."""
    if isinstance(v, (dict, list)):
        import json

        s = json.dumps(v, separators=(",", ":"), default=repr)
    else:
        s = str(v)
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


# ---------------------------------------------------------------------------
# Receipt formatters
# ---------------------------------------------------------------------------


# ntfy emoji tags per outcome — render as a small icon on the
# notification, distinct from the prompt notification's lack of tags.
_RECEIPT_TAGS = {
    CallOutcome.APPROVED_SUCCESS: "white_check_mark",
    CallOutcome.APPROVED_ERROR: "warning",
    CallOutcome.REJECTED: "x",
    CallOutcome.TIMEOUT: "alarm_clock",
}

_RECEIPT_LABELS = {
    CallOutcome.APPROVED_SUCCESS: "Approved",
    CallOutcome.APPROVED_ERROR: "Approved (errored)",
    CallOutcome.REJECTED: "Rejected",
    CallOutcome.TIMEOUT: "Timed out",
}

_RECEIPT_ICONS = {
    CallOutcome.APPROVED_SUCCESS: "✓",
    CallOutcome.APPROVED_ERROR: "⚠",
    CallOutcome.REJECTED: "✗",
    CallOutcome.TIMEOUT: "⏱",
}


def _format_receipt_title(request: ApprovalRequest, outcome: CallOutcome) -> str:
    icon = _RECEIPT_ICONS[outcome]
    label = _RECEIPT_LABELS[outcome]
    unprefixed = request.tool.removeprefix(f"{request.mcp_name}_")
    return f"{icon} {label} · {request.mcp_name} {unprefixed}"


def _format_receipt_body(
    request: ApprovalRequest,
    outcome: CallOutcome,
    result_snippet: str | None,
    wait_ms: int,
    execution_ms: int | None,
    *,
    max_snippet_len: int = 280,
) -> str:
    """Receipt body — short, scannable, plain text (no markdown)."""
    parts: list[str] = []

    if outcome == CallOutcome.APPROVED_SUCCESS and result_snippet:
        snippet = result_snippet
        if len(snippet) > max_snippet_len:
            snippet = snippet[: max_snippet_len - 1] + "…"
        parts.append(snippet)
    elif outcome == CallOutcome.APPROVED_ERROR and result_snippet:
        snippet = result_snippet
        if len(snippet) > max_snippet_len:
            snippet = snippet[: max_snippet_len - 1] + "…"
        parts.append(f"Error: {snippet}")
    elif outcome == CallOutcome.TIMEOUT and request.justification:
        parts.append(f"Justification was: {request.justification[:200]}")

    # Timing line — always present, last
    if parts:
        parts.append("")
    if outcome in (CallOutcome.APPROVED_SUCCESS, CallOutcome.APPROVED_ERROR):
        wait_s = wait_ms / 1000
        exec_part = (
            f"{execution_ms}ms exec" if execution_ms is not None else "exec ?"
        )
        parts.append(f"Took {wait_s:.0f}s waiting + {exec_part}")
    elif outcome == CallOutcome.REJECTED:
        parts.append(f"Rejected after {wait_ms / 1000:.0f}s")
    elif outcome == CallOutcome.TIMEOUT:
        parts.append(f"Timed out after {wait_ms / 1000:.0f}s")

    return "\n".join(parts) if parts else "(no details)"
