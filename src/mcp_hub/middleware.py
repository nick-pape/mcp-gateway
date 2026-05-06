"""FastMCP middleware: identity, tool curation, HITL gating, audit.

Hooks into FastMCP's ``Middleware`` base class. The chain runs in order
of ``add_middleware`` calls; outer-most middleware sees the request
first and the response last.

Order matters:

1. :class:`IdentityMiddleware` — first, to validate JWT and stash
   identity in context state. All later middleware can read it.
2. :class:`ToolCurationMiddleware` — filters ``tools/list`` per identity.
3. :class:`HITLMiddleware` — gates ``tools/call`` per-tool with the
   approver. Defense-in-depth: also re-checks tool permission.
4. :class:`AuditMiddleware` — wraps everything to emit structured
   JSONL on egress.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Sequence
from typing import Any

from fastmcp.server.context import Context
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool, ToolResult
from mcp import McpError
from mcp.types import CallToolRequestParams, ErrorData, ListToolsRequest

from .audit import Audit, AuditLine, hash_args, new_request_id, now_iso
from .auth import AuthentikJWTValidator, AuthFailed
from .errors import ErrorCode
from .interfaces import ApprovalRequest, ApprovalResult, Approver, CallOutcome
from .policy import HITLAction, Policy


def _ctx(context: MiddlewareContext[Any]) -> Context:
    """Assert and return the FastMCP context — never None in real flows."""
    fc = context.fastmcp_context
    if fc is None:
        raise RuntimeError("middleware invoked without a fastmcp context")
    return fc

logger = logging.getLogger(__name__)


# JSON-RPC error codes per the MCP spec are roughly:
# -32000..-32099 reserved for server errors (we use this band)
# -32001 = our generic policy/auth rejection
_RPC_AUTH_REJECTED = -32001
_RPC_POLICY_REJECTED = -32002


# ---------------------------------------------------------------------------
# IdentityMiddleware
# ---------------------------------------------------------------------------


class IdentityMiddleware(Middleware):
    """Validate the inbound JWT and attach identity to context state.

    Reads the ``Authorization: Bearer <jwt>`` header from the underlying
    Starlette request, validates against Authentik via the configured
    :class:`AuthentikJWTValidator`, and sets two state keys:

    - ``identity`` — the resolved identity name (from the aud-suffix)
    - ``request_id`` — a fresh ULID, used by audit + HITL approver

    For non-HTTP transports (stdio, used in some tests), this middleware
    no-ops and lets later middleware handle missing identity.
    """

    def __init__(self, validator: AuthentikJWTValidator) -> None:
        self._validator = validator

    async def on_message(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        try:
            request = get_http_request()
        except RuntimeError:
            # No HTTP request in scope (e.g. stdio transport in tests).
            return await call_next(context)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise McpError(
                ErrorData(
                    code=_RPC_AUTH_REJECTED,
                    message=f"{ErrorCode.AUTH_FAILED}: missing bearer token",
                )
            )

        token = auth_header[len("bearer ") :].strip()
        try:
            identity = await self._validator.validate(token)
        except AuthFailed as exc:
            raise McpError(
                ErrorData(
                    code=_RPC_AUTH_REJECTED,
                    message=f"{ErrorCode.AUTH_FAILED}: {exc}",
                )
            ) from exc

        _ctx(context).set_state("identity", identity.name)
        _ctx(context).set_state("request_id", new_request_id())
        return await call_next(context)


# ---------------------------------------------------------------------------
# ToolCurationMiddleware
# ---------------------------------------------------------------------------


class ToolCurationMiddleware(Middleware):
    """Filter ``tools/list`` responses per the caller's identity.

    Disallowed tools are *invisible* to the LLM — they don't appear in
    the list at all (per the architecture decision: never auto-reject
    a tool the LLM was told it could use).
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    async def on_list_tools(
        self,
        context: MiddlewareContext[ListToolsRequest],
        call_next: CallNext[ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        identity = _ctx(context).get_state("identity")
        if identity is None:
            # No identity set (e.g. stdio test transport with no auth
            # middleware). Return nothing rather than fall open.
            return []
        return [t for t in tools if self._policy.is_tool_allowed(identity, t.name)]


# ---------------------------------------------------------------------------
# HITLMiddleware
# ---------------------------------------------------------------------------


class HITLMiddleware(Middleware):
    """Gate ``tools/call`` per-tool via policy + approver.

    Three outcomes from policy:

    - ``auto-approve`` → forward to upstream
    - ``push-approve`` → call ``approver.request_approval``, forward iff APPROVED
    - ``reject``       → raise McpError immediately

    Defense-in-depth: even though :class:`ToolCurationMiddleware` already
    filtered ``tools/list``, we re-check ``is_tool_allowed`` here in case
    the LLM tried to call a tool name it wasn't shown.
    """

    def __init__(self, policy: Policy, approver: Approver) -> None:
        self._policy = policy
        self._approver = approver

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        identity = _ctx(context).get_state("identity")
        tool_name = context.message.name
        args = dict(context.message.arguments or {})

        if identity is None:
            raise McpError(
                ErrorData(
                    code=_RPC_AUTH_REJECTED,
                    message=f"{ErrorCode.IDENTITY_UNKNOWN}: no identity in context",
                )
            )

        if not self._policy.is_tool_allowed(identity, tool_name):
            raise McpError(
                ErrorData(
                    code=_RPC_POLICY_REJECTED,
                    message=f"{ErrorCode.POLICY_REJECTED}: tool {tool_name!r} "
                    f"not allowed for identity {identity!r}",
                )
            )

        action = self._policy.hitl_decision(identity, tool_name)
        if action == HITLAction.REJECT:
            raise McpError(
                ErrorData(
                    code=_RPC_POLICY_REJECTED,
                    message=f"{ErrorCode.POLICY_REJECTED}: tool {tool_name!r} "
                    f"reject-listed for identity {identity!r}",
                )
            )

        if action == HITLAction.PUSH_APPROVE:
            # Read justification from args without removing it — the
            # FunctionTool's pydantic validator runs AFTER this middleware
            # and will reject if it's missing from the args. The
            # registered tool handler in server.py is what strips it
            # before forwarding to the upstream MCP.
            justification_raw = args.get("justification")
            justification = (
                justification_raw.strip()
                if isinstance(justification_raw, str)
                else ""
            )
            if not justification:
                raise McpError(
                    ErrorData(
                        code=_RPC_POLICY_REJECTED,
                        message=f"{ErrorCode.JUSTIFICATION_REQUIRED}: tool "
                        f"{tool_name!r} requires a non-empty 'justification' "
                        f"argument explaining why this call should be approved",
                    )
                )

            request_id = _ctx(context).get_state("request_id") or new_request_id()
            mcp_name = tool_name.split("_", 1)[0]
            # Build the approval request with args MINUS justification so
            # the notification body shows only the upstream tool's args
            # (justification is its own field on ApprovalRequest, rendered
            # as its own line above the args block).
            args_for_approval = {k: v for k, v in args.items() if k != "justification"}
            req = ApprovalRequest(
                request_id=request_id,
                identity=identity,
                mcp_name=mcp_name,
                tool=tool_name,
                justification=justification,
                args=args_for_approval,
                args_summary=_args_summary(args_for_approval),
            )
            wait_start = time.monotonic()
            result = await self._approver.request_approval(req, timeout_s=120.0)
            wait_ms = int((time.monotonic() - wait_start) * 1000)
            _ctx(context).set_state("hitl_decision", str(result))

            if result == ApprovalResult.REJECTED:
                self._fire_receipt(req, CallOutcome.REJECTED, None, wait_ms, None)
                raise McpError(
                    ErrorData(
                        code=_RPC_POLICY_REJECTED,
                        message=f"{ErrorCode.POLICY_HITL_REJECTED}: operator rejected",
                    )
                )
            if result == ApprovalResult.TIMEOUT:
                self._fire_receipt(req, CallOutcome.TIMEOUT, None, wait_ms, None)
                raise McpError(
                    ErrorData(
                        code=_RPC_POLICY_REJECTED,
                        message=f"{ErrorCode.POLICY_HITL_TIMEOUT}: no response in time",
                    )
                )

            # APPROVED: run the upstream call, capture outcome + duration,
            # send the receipt, and return the result (or re-raise the error).
            exec_start = time.monotonic()
            try:
                tool_result = await call_next(context)
            except McpError as exc:
                exec_ms = int((time.monotonic() - exec_start) * 1000)
                self._fire_receipt(
                    req, CallOutcome.APPROVED_ERROR,
                    str(exc)[:300], wait_ms, exec_ms,
                )
                raise
            except Exception as exc:
                exec_ms = int((time.monotonic() - exec_start) * 1000)
                self._fire_receipt(
                    req, CallOutcome.APPROVED_ERROR,
                    f"{type(exc).__name__}: {exc}"[:300], wait_ms, exec_ms,
                )
                raise

            exec_ms = int((time.monotonic() - exec_start) * 1000)
            self._fire_receipt(
                req, CallOutcome.APPROVED_SUCCESS,
                _result_snippet(tool_result), wait_ms, exec_ms,
            )
            return tool_result

        # auto-approve path
        _ctx(context).set_state("hitl_decision", "auto-approve")
        return await call_next(context)

    def _fire_receipt(
        self,
        req: ApprovalRequest,
        outcome: CallOutcome,
        result_snippet: str | None,
        wait_ms: int,
        execution_ms: int | None,
    ) -> None:
        """Schedule a fire-and-forget receipt publish.

        Wrapping in create_task means the agent's response isn't blocked
        on the receipt publish; the publish runs concurrently. Errors in
        the approver's publish_outcome are swallowed inside the task.
        """
        try:
            asyncio.create_task(
                self._approver.publish_outcome(
                    req, outcome,
                    result_snippet=result_snippet,
                    wait_ms=wait_ms,
                    execution_ms=execution_ms,
                ),
                name=f"hitl-receipt-{req.request_id}",
            )
        except Exception:
            # Even create_task can fail if the loop is shutting down.
            # Don't let receipt machinery affect the actual response.
            logger.exception(
                "hitl middleware: failed to schedule receipt for "
                "tool=%s outcome=%s",
                req.tool, outcome,
            )


# ---------------------------------------------------------------------------
# AuditMiddleware
# ---------------------------------------------------------------------------


class AuditMiddleware(Middleware):
    """Emit one JSONL audit line per ``tools/call`` (and ``tools/list``).

    Captures: identity, request_id, tool, args_hash, decision, status,
    duration. Errors caught from later middleware are recorded as
    ``status=error`` with the error code.
    """

    def __init__(self, audit: Audit, policy: Policy) -> None:
        self._audit = audit
        self._policy = policy

    async def on_list_tools(
        self,
        context: MiddlewareContext[ListToolsRequest],
        call_next: CallNext[ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        start = time.monotonic()
        try:
            tools = await call_next(context)
            self._emit(
                context,
                method="tools/list",
                status="ok",
                duration_s=time.monotonic() - start,
            )
            return tools
        except McpError as exc:
            self._emit(
                context,
                method="tools/list",
                status="error",
                duration_s=time.monotonic() - start,
                error_code=str(exc),
            )
            raise

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        start = time.monotonic()
        tool_name = context.message.name
        args = dict(context.message.arguments or {})
        try:
            result = await call_next(context)
            self._emit(
                context,
                method="tools/call",
                status="ok",
                duration_s=time.monotonic() - start,
                tool=tool_name,
                args_hash=hash_args(args),
            )
            return result
        except McpError as exc:
            self._emit(
                context,
                method="tools/call",
                status="error",
                duration_s=time.monotonic() - start,
                tool=tool_name,
                args_hash=hash_args(args),
                error_code=_extract_error_code(exc),
            )
            raise

    def _emit(
        self,
        context: MiddlewareContext[Any],
        *,
        method: str,
        status: str,
        duration_s: float,
        tool: str | None = None,
        args_hash: str | None = None,
        error_code: str | None = None,
    ) -> None:
        identity = _ctx(context).get_state("identity")
        request_id = _ctx(context).get_state("request_id") or "no-request-id"
        decision = _ctx(context).get_state("hitl_decision")
        fanout = self._policy.mcp_name_for_tool(tool) if tool else None
        line = AuditLine(
            ts=now_iso(),
            request_id=request_id,
            method=method,
            status=status,
            identity=identity,
            tool=tool,
            args_hash=args_hash,
            decision=decision,
            fanout=fanout,
            duration_ms=int(duration_s * 1000),
            error_code=error_code,
        )
        self._audit.emit(line)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result_snippet(tool_result: Any, max_len: int = 280) -> str | None:
    """Extract a short, human-readable snippet from a tool's response.

    Used by HITLMiddleware to populate the receipt body for
    approved-success outcomes. Returns ``None`` if no readable text is
    discoverable; the receipt then renders without a result line.

    FastMCP tool results take a few shapes (CallToolResult,
    StructuredResult, plain str, etc.). This walks the common cases
    defensively — a malformed result MUST NOT crash the receipt path.
    """
    try:
        # Plain string return from a registered handler.
        if isinstance(tool_result, str):
            text = tool_result
        else:
            content = getattr(tool_result, "content", None)
            if content and len(content) > 0:
                first = content[0]
                text = getattr(first, "text", None) or str(first)
            else:
                text = str(tool_result)
        if not text:
            return None
        text = text.strip()
        if len(text) > max_len:
            text = text[: max_len - 1] + "…"
        return text
    except Exception:
        return None


def _args_summary(args: dict[str, Any], max_len: int = 200) -> str:
    """Compact human-readable rendering of args for ntfy push body."""
    try:
        s = json.dumps(args, separators=(",", ": "), default=repr)
    except (TypeError, ValueError):
        s = repr(args)
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def _extract_error_code(exc: McpError) -> str:
    """Pull the leading ``ERROR_CODE:`` token out of the MCP error message."""
    msg = str(exc)
    if ":" in msg:
        head, _, _ = msg.partition(":")
        head = head.strip()
        if head.replace("_", "").isalnum():
            return head
    return "INTERNAL_ERROR"
