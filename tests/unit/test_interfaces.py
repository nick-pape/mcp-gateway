"""Confirm the test-fake backends conform to their Protocols."""

from __future__ import annotations

from mcp_hub.approvers.auto import AutoApprover
from mcp_hub.approvers.reject import RejectApprover
from mcp_hub.interfaces import Approver, SecretBackend
from mcp_hub.secrets.env import EnvSecretBackend


def test_env_backend_satisfies_secret_backend_protocol() -> None:
    backend = EnvSecretBackend()
    assert isinstance(backend, SecretBackend)
    assert backend.name == "env"


def test_auto_approver_satisfies_approver_protocol() -> None:
    approver = AutoApprover()
    assert isinstance(approver, Approver)
    assert approver.name == "auto"


def test_reject_approver_satisfies_approver_protocol() -> None:
    approver = RejectApprover()
    assert isinstance(approver, Approver)
    assert approver.name == "reject"
