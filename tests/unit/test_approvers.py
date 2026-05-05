"""Tests for AutoApprover and RejectApprover."""

from __future__ import annotations

import pytest

from mcp_hub.approvers.auto import AutoApprover
from mcp_hub.approvers.reject import RejectApprover
from mcp_hub.interfaces import ApprovalRequest, ApprovalResult


@pytest.fixture
def request_() -> ApprovalRequest:
    return ApprovalRequest(
        request_id="01HXY00000000000000000000",
        identity="ironclaw",
        tool="technitium_dns_delete_record",
        args={"domain": "stale.pape.house", "ip": "172.16.0.99"},
        args_summary="domain=stale.pape.house ip=172.16.0.99",
    )


async def test_auto_approver_always_approves(request_: ApprovalRequest) -> None:
    approver = AutoApprover()
    result = await approver.request_approval(request_, timeout_s=60.0)
    assert result == ApprovalResult.APPROVED


async def test_auto_approver_does_not_block(request_: ApprovalRequest) -> None:
    """Even with a 0s timeout the auto approver returns immediately."""
    approver = AutoApprover()
    result = await approver.request_approval(request_, timeout_s=0.0)
    assert result == ApprovalResult.APPROVED


async def test_reject_approver_always_rejects(request_: ApprovalRequest) -> None:
    approver = RejectApprover()
    result = await approver.request_approval(request_, timeout_s=60.0)
    assert result == ApprovalResult.REJECTED


async def test_close_is_idempotent_noop() -> None:
    a = AutoApprover()
    r = RejectApprover()
    await a.close()
    await r.close()
    # Second calls should also be fine.
    await a.close()
    await r.close()
