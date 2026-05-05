"""Unit tests for the FastMCP middleware classes.

These test the middleware logic in isolation by driving each hook
directly with a stub MiddlewareContext + a stub fastmcp_context. Full
end-to-end (with a real FastMCP server + Client) lives in
tests/integration/test_hub_e2e.py.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any

import pytest

from mcp_hub.approvers.auto import AutoApprover
from mcp_hub.approvers.reject import RejectApprover
from mcp_hub.audit import Audit
from mcp_hub.interfaces import (
    ApprovalRequest,
    ApprovalResult,
)
from mcp_hub.middleware import (
    AuditMiddleware,
    HITLMiddleware,
    ToolCurationMiddleware,
    _args_summary,
    _ctx,
)
from mcp_hub.policy import HubConfig, Policy
from tests.unit.test_policy import MINIMAL

# ---------------------------------------------------------------------------
# Stubs that imitate enough of the FastMCP types for unit tests
# ---------------------------------------------------------------------------


@dataclass
class _StubFastMCPContext:
    """Imitates fastmcp.server.context.Context.set_state/get_state."""

    state: dict[str, Any] = field(default_factory=dict)

    def set_state(self, key: str, value: Any) -> None:
        self.state[key] = value

    def get_state(self, key: str) -> Any:
        return self.state.get(key)


@dataclass
class _StubMessage:
    name: str
    arguments: dict[str, Any]


@dataclass
class _StubMiddlewareContext:
    fastmcp_context: _StubFastMCPContext
    message: _StubMessage | None = None


def _make_ctx(identity: str | None = None) -> _StubMiddlewareContext:
    fc = _StubFastMCPContext()
    if identity is not None:
        fc.set_state("identity", identity)
        fc.set_state("request_id", "test-request-id-001")
    return _StubMiddlewareContext(fastmcp_context=fc)


# Helper to make a stub Tool that has only a `.name` (matches the part
# of fastmcp.tools.tool.Tool that ToolCurationMiddleware reads).
@dataclass
class _StubTool:
    name: str


# ---------------------------------------------------------------------------
# Policy fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def policy() -> Policy:
    """Minimal policy with ironclaw allowed technitium_dns_*, paperless-bot allowed nothing."""
    import copy

    raw: dict[str, Any] = copy.deepcopy(MINIMAL)
    raw["identities"]["paperless-bot"] = {
        "aud": "mcp-paperless-bot",
        "uid_base": 1002,
        "allowed_tools": ["technitium_dhcp_*"],
        "hitl": {"defaults": "auto-approve"},
        "secrets": {
            "technitium": {"path": "x", "field": "api_token"},
        },
    }
    return Policy(HubConfig.model_validate(raw))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_ctx_helper_raises_without_fastmcp_context() -> None:
    """The _ctx helper enforces that middleware always has a context."""
    @dataclass
    class _NoCtx:
        fastmcp_context: Any = None

    with pytest.raises(RuntimeError, match="without a fastmcp context"):
        _ctx(_NoCtx())  # type: ignore[arg-type]


def test_args_summary_short_args() -> None:
    out = _args_summary({"x": 1, "y": "abc"})
    assert "x" in out and "y" in out


def test_args_summary_truncates() -> None:
    out = _args_summary({"big": "x" * 1000}, max_len=50)
    assert len(out) <= 50
    assert out.endswith("…")


# ---------------------------------------------------------------------------
# ToolCurationMiddleware
# ---------------------------------------------------------------------------


async def _list_tools_via_middleware(
    middleware: ToolCurationMiddleware,
    upstream_tools: list[_StubTool],
    identity: str | None,
) -> list[Any]:
    """Drive on_list_tools with a stub call_next that returns upstream_tools."""
    ctx = _make_ctx(identity)

    async def call_next(_c: Any) -> list[Any]:
        return list(upstream_tools)

    return list(await middleware.on_list_tools(ctx, call_next))  # type: ignore[arg-type]


async def test_tool_curation_filters_per_identity(policy: Policy) -> None:
    middleware = ToolCurationMiddleware(policy)
    all_tools = [
        _StubTool("technitium_dns_list"),
        _StubTool("technitium_dhcp_list_reservations"),
        _StubTool("paperless_get_doc"),
    ]
    iron = await _list_tools_via_middleware(middleware, all_tools, "ironclaw")
    paper = await _list_tools_via_middleware(middleware, all_tools, "paperless-bot")
    iron_names = {t.name for t in iron}
    paper_names = {t.name for t in paper}
    assert iron_names == {"technitium_dns_list"}
    assert paper_names == {"technitium_dhcp_list_reservations"}


async def test_tool_curation_no_identity_returns_empty(policy: Policy) -> None:
    """No identity in context → no tools (fail closed)."""
    middleware = ToolCurationMiddleware(policy)
    out = await _list_tools_via_middleware(middleware, [_StubTool("technitium_dns_list")], None)
    assert out == []


# ---------------------------------------------------------------------------
# HITLMiddleware
# ---------------------------------------------------------------------------


async def _call_tool_via_middleware(
    middleware: HITLMiddleware,
    *,
    tool_name: str,
    identity: str | None,
    upstream_returns: Any = "ok",
    extra_args: dict[str, Any] | None = None,
) -> tuple[Any, _StubMiddlewareContext]:
    """Drive on_call_tool; returns (result, context_after) or raises."""
    ctx = _make_ctx(identity)
    args: dict[str, Any] = {"x": 1}
    if extra_args:
        args.update(extra_args)
    ctx.message = _StubMessage(name=tool_name, arguments=args)

    async def call_next(_c: Any) -> Any:
        return upstream_returns

    return await middleware.on_call_tool(ctx, call_next), ctx  # type: ignore[arg-type]


async def test_hitl_auto_approve_passes_through(policy: Policy) -> None:
    middleware = HITLMiddleware(policy, AutoApprover())
    result, ctx = await _call_tool_via_middleware(
        middleware, tool_name="technitium_dns_list", identity="ironclaw"
    )
    assert result == "ok"
    assert ctx.fastmcp_context.get_state("hitl_decision") == "auto-approve"


async def test_hitl_disallowed_tool_rejected(policy: Policy) -> None:
    """A tool not in identity's allowed_tools is rejected even before HITL."""
    middleware = HITLMiddleware(policy, AutoApprover())
    from mcp import McpError

    with pytest.raises(McpError, match="POLICY_REJECTED"):
        await _call_tool_via_middleware(
            middleware,
            tool_name="paperless_get_doc",  # ironclaw isn't allowed paperless
            identity="ironclaw",
        )


async def test_hitl_no_identity_rejected(policy: Policy) -> None:
    middleware = HITLMiddleware(policy, AutoApprover())
    from mcp import McpError

    with pytest.raises(McpError, match="IDENTITY_UNKNOWN"):
        await _call_tool_via_middleware(
            middleware, tool_name="technitium_dns_list", identity=None
        )


async def test_hitl_push_approve_calls_approver(policy: Policy) -> None:
    """A push-approve tool routes through the Approver."""
    import copy

    raw: dict[str, Any] = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["allowed_tools"] = ["technitium_*"]
    raw["identities"]["ironclaw"]["hitl"] = {
        "defaults": "auto-approve",
        "overrides": {"technitium_dns_delete_record": "push-approve"},
    }
    p = Policy(HubConfig.model_validate(raw))

    seen: list[ApprovalRequest] = []

    class _CapturingApprover:
        name = "capturing"

        async def request_approval(
            self, req: ApprovalRequest, timeout_s: float
        ) -> ApprovalResult:
            seen.append(req)
            return ApprovalResult.APPROVED

        async def close(self) -> None:
            return None

    middleware = HITLMiddleware(p, _CapturingApprover())
    result, ctx = await _call_tool_via_middleware(
        middleware,
        tool_name="technitium_dns_delete_record",
        identity="ironclaw",
        extra_args={"justification": "stale record from leftover test data"},
    )
    assert result == "ok"
    assert ctx.fastmcp_context.get_state("hitl_decision") == "approved"
    assert len(seen) == 1
    req = seen[0]
    assert req.identity == "ironclaw"
    assert req.tool == "technitium_dns_delete_record"
    assert req.mcp_name == "technitium"
    assert req.justification == "stale record from leftover test data"
    # Justification must be stripped from args before forwarding upstream.
    assert "justification" not in req.args


async def test_hitl_push_approve_rejected_raises(policy: Policy) -> None:
    """RejectApprover causes HITL flow to raise POLICY_HITL_REJECTED."""
    import copy

    raw: dict[str, Any] = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["hitl"] = {
        "defaults": "push-approve",
    }
    p = Policy(HubConfig.model_validate(raw))
    middleware = HITLMiddleware(p, RejectApprover())
    from mcp import McpError

    with pytest.raises(McpError, match="POLICY_HITL_REJECTED"):
        await _call_tool_via_middleware(
            middleware,
            tool_name="technitium_dns_list",
            identity="ironclaw",
            extra_args={"justification": "needed for diagnostics"},
        )


async def test_hitl_push_approve_missing_justification_raises(policy: Policy) -> None:
    """Push-approve without a justification arg → JUSTIFICATION_REQUIRED."""
    import copy

    raw: dict[str, Any] = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["hitl"] = {"defaults": "push-approve"}
    p = Policy(HubConfig.model_validate(raw))
    from mcp_hub.approvers.auto import AutoApprover

    middleware = HITLMiddleware(p, AutoApprover())
    from mcp import McpError

    with pytest.raises(McpError, match="JUSTIFICATION_REQUIRED"):
        await _call_tool_via_middleware(
            middleware,
            tool_name="technitium_dns_list",
            identity="ironclaw",
            # no extra_args → no justification
        )


async def test_hitl_push_approve_empty_justification_raises(policy: Policy) -> None:
    """Push-approve with empty/whitespace justification → JUSTIFICATION_REQUIRED."""
    import copy

    raw: dict[str, Any] = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["hitl"] = {"defaults": "push-approve"}
    p = Policy(HubConfig.model_validate(raw))
    from mcp_hub.approvers.auto import AutoApprover

    middleware = HITLMiddleware(p, AutoApprover())
    from mcp import McpError

    with pytest.raises(McpError, match="JUSTIFICATION_REQUIRED"):
        await _call_tool_via_middleware(
            middleware,
            tool_name="technitium_dns_list",
            identity="ironclaw",
            extra_args={"justification": "   "},
        )


async def test_hitl_explicit_reject_raises(policy: Policy) -> None:
    """defaults=reject raises POLICY_REJECTED without invoking approver."""
    import copy

    raw: dict[str, Any] = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["hitl"] = {"defaults": "reject"}
    p = Policy(HubConfig.model_validate(raw))

    class _NeverApprover:
        name = "never"
        called = False

        async def request_approval(
            self, req: ApprovalRequest, timeout_s: float
        ) -> ApprovalResult:
            self.called = True
            return ApprovalResult.APPROVED

        async def close(self) -> None:
            return None

    approver = _NeverApprover()
    middleware = HITLMiddleware(p, approver)
    from mcp import McpError

    with pytest.raises(McpError, match="POLICY_REJECTED"):
        await _call_tool_via_middleware(
            middleware, tool_name="technitium_dns_list", identity="ironclaw"
        )
    assert approver.called is False


# ---------------------------------------------------------------------------
# AuditMiddleware
# ---------------------------------------------------------------------------


async def test_audit_emits_one_line_per_tools_call(policy: Policy) -> None:
    sink = io.StringIO()
    middleware = AuditMiddleware(Audit(sink=sink), policy)

    ctx = _make_ctx("ironclaw")
    ctx.message = _StubMessage(name="technitium_dns_list", arguments={"x": 1})

    async def call_next(_c: Any) -> str:
        return "ok"

    await middleware.on_call_tool(ctx, call_next)  # type: ignore[arg-type]
    lines = sink.getvalue().strip().splitlines()
    assert len(lines) == 1
    import json

    parsed = json.loads(lines[0])
    assert parsed["method"] == "tools/call"
    assert parsed["status"] == "ok"
    assert parsed["identity"] == "ironclaw"
    assert parsed["tool"] == "technitium_dns_list"
    assert parsed["fanout"] == "technitium"
    assert "args_hash" in parsed


async def test_audit_emits_error_on_mcp_error(policy: Policy) -> None:
    sink = io.StringIO()
    middleware = AuditMiddleware(Audit(sink=sink), policy)
    from mcp import McpError
    from mcp.types import ErrorData

    ctx = _make_ctx("ironclaw")
    ctx.message = _StubMessage(name="technitium_dns_list", arguments={})

    async def failing(_c: Any) -> Any:
        raise McpError(ErrorData(code=-32001, message="POLICY_HITL_TIMEOUT: nope"))

    with pytest.raises(McpError):
        await middleware.on_call_tool(ctx, failing)  # type: ignore[arg-type]
    import json

    parsed = json.loads(sink.getvalue().strip().splitlines()[0])
    assert parsed["status"] == "error"
    assert parsed["error_code"] == "POLICY_HITL_TIMEOUT"
