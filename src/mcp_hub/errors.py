"""Stable error code taxonomy.

These codes appear in two places:

1. **Audit lines**, in the ``error_code`` field, so operators can grep
   for class of failure
2. **MCP error responses to the agent** so agent loops can react
   programmatically (e.g., retry vs. give up)

The values here are stable string identifiers — never change one
without coordinating with downstream consumers.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    # Authn / authz
    AUTH_FAILED = "AUTH_FAILED"
    IDENTITY_UNKNOWN = "IDENTITY_UNKNOWN"

    # Policy gates
    POLICY_REJECTED = "POLICY_REJECTED"
    POLICY_HITL_REJECTED = "POLICY_HITL_REJECTED"
    POLICY_HITL_TIMEOUT = "POLICY_HITL_TIMEOUT"

    # Backend (fanout) failures
    BACKEND_CHILD_DEAD = "BACKEND_CHILD_DEAD"
    BACKEND_UNREACHABLE = "BACKEND_UNREACHABLE"

    # Catch-all
    INTERNAL_ERROR = "INTERNAL_ERROR"
