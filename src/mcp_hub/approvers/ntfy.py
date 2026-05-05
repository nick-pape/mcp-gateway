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

from mcp_hub.bao_client import BaoClient, BaoError, compare_digest
from mcp_hub.interfaces import ApprovalRequest, ApprovalResult

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
        bao_client: BaoClient,
        bao_role: str,
        ntfy_server: str,
        ntfy_topic: str,
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
        self._bao = bao_client
        self._bao_role = bao_role
        self._ntfy_server = ntfy_server.rstrip("/")
        self._ntfy_topic = ntfy_topic
        self._publish_token_path = Path(publish_token_path)
        self._webhook_url = f"{webhook_base_url.rstrip('/')}{webhook_path}"
        self._timeout_default_s = timeout_default_s
        self._ack_ttl_s = ack_ttl_s
        self._bao_path_template = bao_path_template
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
        if self._owns_client:
            await self._http.aclose()

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

        bao_path = self._bao_path_template.format(nonce=nonce)

        # 3. Stage the pending entry in memory and in bao.
        pending = _Pending()
        self._pending[nonce] = pending

        try:
            try:
                bao_token = await self._bao.jwt_login(role=self._bao_role)
                await self._bao.kv_write(
                    token=bao_token,
                    path=bao_path,
                    data={
                        "ack_token": ack_token,
                        "identity": request.identity,
                        "tool": request.tool,
                    },
                    ttl_s=self._ack_ttl_s,
                )
            except BaoError:
                logger.exception(
                    "ntfy approver: failed to stage ack token in bao for "
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
                await self._cleanup_bao(bao_path)
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
            await self._cleanup_bao(bao_path)

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
            raise BaoError(
                f"cannot read ntfy publish token at {self._publish_token_path}: {exc}"
            ) from exc

        action_url = f"{self._webhook_url}?nonce={nonce}"
        approve_body = f'{{"ack_token":"{ack_token}","decision":"approve"}}'
        reject_body = f'{{"ack_token":"{ack_token}","decision":"reject"}}'

        payload: dict[str, Any] = {
            "topic": self._ntfy_topic,
            "title": f"[{request.identity}] {request.tool}?",
            "message": request.args_summary or "(no args)",
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

    async def _cleanup_bao(self, bao_path: str) -> None:
        """Best-effort delete of the bao pending entry."""
        try:
            bao_token = await self._bao.jwt_login(role=self._bao_role)
            await self._bao.kv_delete(token=bao_token, path=bao_path)
        except BaoError:
            # If cleanup fails, bao TTL still evicts. Log and move on.
            logger.warning("ntfy approver: bao cleanup failed for %s", bao_path)

    # -----------------------------------------------------------------------
    # Webhook handler (called by the hub server for POST /hitl/ack)
    # -----------------------------------------------------------------------

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

        bao_path = self._bao_path_template.format(nonce=nonce)

        # Read the staged ack_token from bao. If it doesn't exist (TTL
        # expired, already consumed, never existed), silently ignore.
        try:
            bao_token = await self._bao.jwt_login(role=self._bao_role)
            stored = await self._bao.kv_read(token=bao_token, path=bao_path)
        except BaoError as exc:
            logger.info(
                "ntfy webhook: bao read failed for nonce=%s (%s); ignoring",
                _redact(nonce),
                exc,
            )
            return 200

        stored_ack = stored.get("ack_token")
        if not isinstance(stored_ack, str) or not compare_digest(stored_ack, posted_ack):
            logger.info(
                "ntfy webhook: ack_token mismatch for nonce=%s; ignoring",
                _redact(nonce),
            )
            return 200

        # Atomic consumption: delete the bao entry BEFORE signaling.
        # If we crashed between signal and delete, a replay could
        # re-trigger; deleting first prevents that.
        try:
            await self._bao.kv_delete(token=bao_token, path=bao_path)
        except BaoError:
            logger.warning(
                "ntfy webhook: bao delete failed for nonce=%s; "
                "proceeding anyway (TTL will clean up)",
                _redact(nonce),
            )

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
