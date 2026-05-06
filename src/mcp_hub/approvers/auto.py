"""Always-approve Approver (testing only).

Selected via:

.. code-block:: yaml

    approver:
      name: auto

Combined with the audit log, this lets unit and integration tests
exercise the full hub flow including HITL gating without a human or
ntfy round-trip. Never use in production — by design it provides no
gate at all.
"""

from __future__ import annotations

from mcp_hub.interfaces import ApprovalRequest, ApprovalResult, CallOutcome


class AutoApprover:
    """Returns :attr:`ApprovalResult.APPROVED` for every request."""

    name: str = "auto"

    async def request_approval(
        self,
        request: ApprovalRequest,
        timeout_s: float,
    ) -> ApprovalResult:
        return ApprovalResult.APPROVED

    async def publish_outcome(
        self,
        request: ApprovalRequest,
        outcome: CallOutcome,
        *,
        result_snippet: str | None,
        wait_ms: int,
        execution_ms: int | None,
    ) -> None:
        # No human to notify; receipts are a NtfyApprover concept.
        return None

    async def close(self) -> None:
        return None
