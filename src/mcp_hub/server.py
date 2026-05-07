"""Hub server: composes everything.

The :class:`Hub` class:

1. Spawns one :class:`Fanout` per backend MCP via the configured
   :class:`SecretBackend`.
2. Discovers each backend's tool schema by querying one stdio child
   per fanout.
3. Registers each tool with FastMCP under the prefix ``<mcp_name>_``.
   Each tool's handler routes through the Fanout for per-identity
   dispatch.
4. Installs the middleware chain (identity, curation, HITL, audit)
   in order.
5. Exposes the FastMCP app for ``run(transport="http", ...)``.

Per-identity multi-tenancy: the Fanout (Phase 2) holds N stdio children
per backend (one per identity). When a tool call arrives, the registered
handler reads the identity from context state (set by IdentityMiddleware)
and dispatches to the matching child via ``fanout.call(identity, ...)``.

This preserves the architecture's per-identity isolation properties
without forcing FastMCP's static-tool model to know about identities.

For ``/hitl/ack`` webhook integration with NtfyApprover, callers should
register a custom Starlette route on the underlying ASGI app (see
__main__.py).
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from mcp.types import TextContent

from mcp_fanout import ContainerFanout, Fanout, HttpFanout

from .audit import Audit
from .auth import AuthentikJWTValidator
from .auth_strategies import CTX_KEY_BEARER_TOKEN
from .errors import ErrorCode
from .factory import build_docker_client, build_fanout
from .interfaces import Approver, SecretBackend
from .middleware import (
    AuditMiddleware,
    HITLMiddleware,
    IdentityMiddleware,
    ToolCurationMiddleware,
)
from .policy import Policy

logger = logging.getLogger(__name__)


# Sentinel used as the default value for non-required parameters in the
# forged tool signature. FastMCP unpacks the call's arguments through the
# forged signature; if the agent omitted an optional parameter, the
# handler receives _UNSET for it. We strip _UNSET-valued kwargs before
# forwarding to the upstream MCP. This preserves the agent's ability to
# intentionally pass JSON null (which arrives as Python None) for tools
# whose schemas declare a field nullable, while not forwarding a fake
# null for fields the agent never set — Outline's Zod schemas reject
# null on plain `string`/`boolean` optional fields.
_UNSET: Any = object()


# All three fanouts implement this duck-typed interface (mcp_name,
# identities, start_eager_or_die, call, close). server.py treats them
# uniformly via this union.
FanoutLike = Fanout | HttpFanout | ContainerFanout


class Hub:
    """Composed MCP gateway: fanouts + middleware + tool routing."""

    def __init__(
        self,
        *,
        policy: Policy,
        secret_backend: SecretBackend,
        approver: Approver,
        validator: AuthentikJWTValidator,
        audit: Audit,
        runtime_dir: Path,
    ) -> None:
        self._policy = policy
        self._secret_backend = secret_backend
        self._approver = approver
        self._validator = validator
        self._audit = audit
        self._runtime_dir = runtime_dir
        self._fanouts: dict[str, FanoutLike] = {}
        # FastMCP app — middleware installed at __init__ so tests can drive
        # it before start() is called.
        self.mcp = FastMCP(
            name="mcp.pape.house",
            instructions="Multi-tenant MCP gateway. JWT auth required.",
        )
        self._install_middleware()

    @property
    def approver(self) -> Approver:
        """Public access for the webhook handler in __main__."""
        return self._approver

    @property
    def fanouts(self) -> Mapping[str, FanoutLike]:
        return self._fanouts

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn fanouts (eager-or-die) and register their tools.

        Failure during any fanout's start aborts the whole hub.
        """
        # 1. Build all fanouts — one per MCP defined in policy. The
        #    factory dispatches to stdio Fanout vs HttpFanout vs
        #    ContainerFanout based on each MCP's transport setting.
        # 1a. Lazily construct a Docker client only if any container-transport
        #     MCP is present. The hub deploys without DOCKER_HOST configured
        #     don't pay the import cost for the docker SDK.
        docker_client: object | None = None
        if any(
            mc.transport == "container" for mc in self._policy.config.mcps.values()
        ):
            docker_client = build_docker_client()
        for mcp_name, mcp_config in self._policy.config.mcps.items():
            self._fanouts[mcp_name] = build_fanout(
                mcp_name,
                mcp_config,
                identities=self._policy.config.identities,
                secret_backend=self._secret_backend,
                runtime_dir=self._runtime_dir,
                auth_config=self._policy.config.auth,
                docker_client=docker_client,
            )
        # 2. Eager-spawn each in turn. If any fails, close already-started
        #    ones before re-raising.
        try:
            for fanout in self._fanouts.values():
                await fanout.start_eager_or_die()
        except Exception:
            await self.close()
            raise
        # 3. Discover tools from each fanout and register with FastMCP.
        await self._register_all_tools()

    async def close(self) -> None:
        """Tear down all fanouts. Idempotent."""
        for fanout in self._fanouts.values():
            try:
                await fanout.close()
            except Exception:
                logger.exception("error closing fanout %s", fanout.mcp_name)
        self._fanouts.clear()
        try:
            await self._validator.close()
        except Exception:
            logger.exception("error closing JWT validator")
        try:
            await self._approver.close()
        except Exception:
            logger.exception("error closing approver")

    # -----------------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------------

    def _install_middleware(self) -> None:
        # Order: identity → curation → HITL → audit.
        # FastMCP's middleware list is processed in registration order
        # (first-added wraps outer-most). Audit wraps last so it can
        # log success/failure of the whole chain.
        self.mcp.add_middleware(IdentityMiddleware(self._validator))
        self.mcp.add_middleware(ToolCurationMiddleware(self._policy))
        # Pull HITL timeout from approver config (policy.yaml's
        # approver.config.timeout_default_s). Falls back to 120s if absent.
        approver_cfg = self._policy.config.approver.config or {}
        hitl_timeout = float(approver_cfg.get("timeout_default_s", 120.0))
        self.mcp.add_middleware(
            HITLMiddleware(self._policy, self._approver, default_timeout_s=hitl_timeout)
        )
        self.mcp.add_middleware(AuditMiddleware(self._audit, self._policy))

    async def _register_all_tools(self) -> None:
        """Discover and register tools from each running fanout.

        For each fanout: pick the first identity, query its child for
        ``tools/list``, and register each returned tool with FastMCP
        under the prefix ``<mcp_name>_``. The handler routes through the
        Fanout using the per-request identity from context state.

        The hub doesn't have a per-identity JWT at boot — IdentityMiddleware
        only populates ``request_context.bearer_token`` for inbound user
        requests. So for boot-time tools/list against fanouts that need a
        bearer token (JwtPassthrough on container fanouts), we fall back
        to the hub's own service-account JWT (fanout_jwt). Wrappers
        accept aud=mcp-fanout-svc as a trusted-hub bootstrap audience
        alongside their per-identity audience. See entrypoint.py's
        OIDC_BOOT_AUDIENCE for the wrapper side.
        """
        # Best-effort read of the hub's own JWT for boot-time discovery.
        # If the file doesn't exist (e.g. test deploys with no refresher),
        # we fall back to no token — works fine for fanouts that don't
        # need one (BaoBackedBearer-only HTTP federations).
        boot_bearer: str | None = None
        from pathlib import Path as _P
        for candidate in ("/etc/mcp-pape-house/fanout_jwt",):
            p = _P(candidate)
            if p.exists():
                with contextlib.suppress(OSError):
                    boot_bearer = p.read_text().strip() or None
                if boot_bearer:
                    logger.info(
                        "registering tools with boot-time bearer from %s (len=%d)",
                        candidate, len(boot_bearer),
                    )
                    break
        boot_request_context: dict[str, Any] = {}
        if boot_bearer is not None:
            boot_request_context[CTX_KEY_BEARER_TOKEN] = boot_bearer

        for mcp_name, fanout in self._fanouts.items():
            sample_identity = next(iter(fanout.identities))
            list_response = await _fanout_call(
                fanout,
                identity=sample_identity,
                request={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                },
                request_context=boot_request_context,
            )
            upstream_tools = list_response.get("result", {}).get("tools", [])
            for tool_def in upstream_tools:
                self._register_one_tool(mcp_name, fanout, tool_def)

    def _register_one_tool(
        self, mcp_name: str, fanout: FanoutLike, tool_def: dict[str, Any]
    ) -> None:
        """Register one upstream tool with FastMCP under prefix.

        The handler closes over ``mcp_name``, ``fanout``, and the
        upstream tool name so the dispatch logic at call time is
        self-contained.
        """
        upstream_name = tool_def["name"]
        prefixed_name = f"{mcp_name}_{upstream_name}"
        description = tool_def.get("description", "")
        # Defensive copy — we mutate the schema below to inject
        # ``justification`` for HITL-gated tools, and tool_def comes
        # from the upstream MCP's tools/list which we don't own.
        input_schema = dict(tool_def.get("inputSchema") or {"type": "object", "properties": {}})
        input_schema["properties"] = dict(input_schema.get("properties", {}))
        input_schema["required"] = list(input_schema.get("required", []))

        # If this tool resolves to push-approve for any identity, the
        # agent MUST send a justification with the call. Inject it as a
        # required string parameter at the gateway level so the schema
        # the agent sees includes it. Auto-approve callers never see
        # the field validated (HITL middleware only enforces it on
        # push-approve), so headless agents stay simple.
        gates_hitl = self._policy.is_tool_ever_push_approved(prefixed_name)
        if gates_hitl and "justification" not in input_schema["properties"]:
            input_schema["properties"]["justification"] = {
                "type": "string",
                "description": (
                    "Required for push-approve tools: a brief, specific "
                    "explanation of WHY this call should be approved. The "
                    "human reviewer sees this as the primary signal for "
                    "deciding. Vague text ('user requested this') will "
                    "likely be rejected; reference concrete intent."
                ),
            }
            if "justification" not in input_schema["required"]:
                input_schema["required"].append("justification")

        # FastMCP introspects the function's signature for both schema
        # generation AND argument unpacking. **kwargs is rejected by its
        # validator, but a function with __signature__ overridden to a
        # Signature of KEYWORD_ONLY params (matching the upstream tool's
        # input schema) passes validation AND tells FastMCP what arg
        # names to extract from the call's `arguments` dict.
        async def handler(**arguments: Any) -> str:
            from fastmcp.server.dependencies import get_context

            ctx = get_context()
            identity: str | None = ctx.get_state("identity")
            if identity is None:
                raise RuntimeError(
                    f"{ErrorCode.IDENTITY_UNKNOWN}: tool {prefixed_name} "
                    f"called with no identity"
                )
            # Defense-in-depth: HITL middleware also strips ``justification``
            # from context.message.arguments before call_next, but pop here
            # too in case the upstream FastMCP version doesn't propagate
            # the middleware mutation. Justification is hub-only metadata
            # and the upstream MCP would reject it as an unknown parameter.
            arguments.pop("justification", None)
            # Drop kwargs whose value is the _UNSET sentinel — these are
            # optional parameters the agent didn't pass, which FastMCP
            # filled in from the forged signature's default. Forwarding
            # them as JSON null breaks upstream MCPs whose optional-field
            # schemas don't declare nullable=true (e.g. Outline's Zod).
            # Explicit None from the agent is preserved.
            arguments = {k: v for k, v in arguments.items() if v is not _UNSET}
            # Build request_context for HTTP-fanout auth strategies.
            # Only HttpFanout reads it; stdio Fanout ignores the kwarg.
            bearer_token = ctx.get_state(CTX_KEY_BEARER_TOKEN)
            request_context: dict[str, Any] = {}
            if isinstance(bearer_token, str):
                request_context[CTX_KEY_BEARER_TOKEN] = bearer_token
            response = await _fanout_call(
                fanout,
                identity=identity,
                request={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": upstream_name, "arguments": arguments},
                },
                request_context=request_context,
            )
            if "error" in response:
                err = response["error"]
                raise RuntimeError(
                    f"{ErrorCode.BACKEND_CHILD_DEAD}: upstream "
                    f"{mcp_name}/{upstream_name}: {err.get('message', err)}"
                )
            result = response.get("result", {})
            content = result.get("content", [])
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and first.get("type") == "text":
                    return str(first.get("text", ""))
            import json as _json

            return _json.dumps(result, separators=(",", ":"))

        # Forge the signature: one KEYWORD_ONLY param per upstream-tool input
        # property. FastMCP's validator only rejects VAR_POSITIONAL / VAR_KEYWORD
        # kinds; explicit named params pass through.
        import inspect as _inspect

        properties: dict[str, Any] = input_schema.get("properties", {})
        required = set(input_schema.get("required", []))
        forged_params = [
            _inspect.Parameter(
                name=prop_name,
                kind=_inspect.Parameter.KEYWORD_ONLY,
                default=_inspect.Parameter.empty if prop_name in required else _UNSET,
                annotation=Any,
            )
            for prop_name in properties
        ]
        handler.__signature__ = _inspect.Signature(  # type: ignore[attr-defined]
            parameters=forged_params, return_annotation=str
        )
        # Pydantic walks __annotations__ (via typing.get_type_hints) for
        # arguments-schema validation; __signature__ alone isn't enough.
        handler.__annotations__ = {p.name: Any for p in forged_params}
        handler.__annotations__["return"] = str

        from fastmcp.tools.tool import FunctionTool

        tool = FunctionTool.from_function(
            fn=handler,
            name=prefixed_name,
            description=description,
        )
        # Replace the auto-generated parameters schema with the upstream's
        # actual tool schema so the LLM sees correct field names/types.
        tool.parameters = input_schema
        self.mcp._tool_manager.add_tool(tool)  # noqa: SLF001


# ---------------------------------------------------------------------------
# Generic fanout-call shim
# ---------------------------------------------------------------------------


async def _fanout_call(
    fanout: FanoutLike,
    *,
    identity: str,
    request: dict[str, Any],
    request_context: dict[str, Any],
) -> dict[str, Any]:
    """Dispatch ``call`` across all three Fanout impls.

    Stdio :class:`Fanout.call` doesn't take ``request_context``; the two
    HTTP-shaped fanouts (:class:`HttpFanout` and :class:`ContainerFanout`)
    do. We isolate the type-narrow here so every other call site stays
    uniform.
    """
    if isinstance(fanout, (HttpFanout, ContainerFanout)):
        return await fanout.call(
            identity=identity,
            request=request,
            request_context=request_context,
        )
    return await fanout.call(identity=identity, request=request)


# ---------------------------------------------------------------------------
# TextContent helper export to satisfy mypy that we use it
# ---------------------------------------------------------------------------

__all__ = ["Hub", "TextContent"]
