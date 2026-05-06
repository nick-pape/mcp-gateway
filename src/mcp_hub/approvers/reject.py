"""Always-reject Approver (testing only).

Selected via:

.. code-block:: yaml

    approver:
      name: reject

Lets tests verify that rejection paths surface as ``POLICY_HITL_REJECTED``
to the agent. Useful as a chaos toggle during integration testing.
"""

from __future__ import annotations

from mcp_hub.interfaces import ApprovalRequest, ApprovalResult, CallOutcome


class RejectApprover:
    """Returns :attr:`ApprovalResult.REJECTED` for every request."""

    name: str = "reject"

    async def request_approval(
        self,
        request: ApprovalRequest,
        timeout_s: float,
    ) -> ApprovalResult:
        return ApprovalResult.REJECTED

    async def publish_outcome(
        self,
        request: ApprovalRequest,
        outcome: CallOutcome,
        *,
        result_snippet: str | None,
        wait_ms: int,
        execution_ms: int | None,
    ) -> None:
        return None

    async def close(self) -> None:
        return None
