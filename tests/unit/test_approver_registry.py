"""Tests for the Approver plugin registry."""

from __future__ import annotations

import pytest

from mcp_hub.approvers.auto import AutoApprover
from mcp_hub.approvers.ntfy import NtfyApprover
from mcp_hub.approvers.registry import ApproverNotFound, resolve_approver
from mcp_hub.approvers.reject import RejectApprover


def test_resolves_builtins_by_name() -> None:
    assert resolve_approver("auto") is AutoApprover
    assert resolve_approver("reject") is RejectApprover
    assert resolve_approver("ntfy") is NtfyApprover


def test_dotted_path_fallback_for_in_repo_approver() -> None:
    assert resolve_approver("mcp_hub.approvers.auto.AutoApprover") is AutoApprover


def test_unknown_bare_name_raises() -> None:
    with pytest.raises(ApproverNotFound):
        resolve_approver("does-not-exist")


def test_empty_name_raises() -> None:
    with pytest.raises(ApproverNotFound):
        resolve_approver("")


def test_dotted_path_to_missing_attr_raises() -> None:
    with pytest.raises(ApproverNotFound):
        resolve_approver("mcp_hub.approvers.auto.NoSuchClass")


def test_class_without_protocol_methods_raises() -> None:
    # pathlib.Path is a class but lacks request_approval/publish_outcome.
    with pytest.raises(ApproverNotFound):
        resolve_approver("pathlib.Path")
