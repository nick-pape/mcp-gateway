"""Tool-name normalization proxy between the homelab MCP hub and better-email-mcp.

See README.md for the why. In short: rewrites upstream's 7 composite
tools into 23 granular tools so the hub's HITL policy can glob-match
read-vs-write at tool-name granularity instead of all-or-nothing per
composite.

Two rewrite hooks:

- ``tools/list`` responses → substitute upstream's tools array with the
  hand-authored entries from ``tool-schemas.yaml`` (stripped of the
  ``_composite`` / ``_action`` proxy-only metadata before emitting)
- ``tools/call`` requests → if ``params.name`` matches a known granular
  name, rewrite to ``{name: composite, arguments: {action, ...rest}}``
  before forwarding upstream

Streamable HTTP MCP nuances:

- ``Mcp-Session-Id`` header round-trips both directions
- Responses may be ``application/json`` OR ``text/event-stream`` (SSE);
  both are passed through. For SSE we still parse + rewrite the ``data:
  {...}`` JSON-RPC payloads inline so tools/list rewriting works
- Initialize handshake passes through unchanged
- Notifications (``method`` starts with ``notifications/``) pass through

The proxy makes no bao calls — it forwards whatever ``Authorization``
header comes in. The hub's ``bao_backed_bearer`` strategy provides the
bearer; both proxy and email-mcp accept the same single ``hub_bearer``
value.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sys
from typing import Any

import httpx
import uvicorn
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

EMAIL_MCP_URL = os.environ.get("EMAIL_MCP_URL", "http://email-mcp:8080").rstrip("/")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
SCHEMA_FILE = os.environ.get("SCHEMA_FILE", "/app/tool-schemas.yaml")
REQUEST_TIMEOUT_S = float(os.environ.get("REQUEST_TIMEOUT_S", "30"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("email-mcp-proxy")

# Proxy-only metadata fields stripped from each schema entry before
# emitting to the hub via tools/list. Hand-authored YAML uses them as
# the rewrite source-of-truth.
_PROXY_META_FIELDS = ("_composite", "_action")


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------


def load_schemas(path: str) -> tuple[list[dict[str, Any]], dict[str, tuple[str, str | None]]]:
    """Load tool-schemas.yaml; return (tools_for_emit, name→(composite, action) map).

    ``tools_for_emit`` is the schema entries with proxy-only metadata
    fields stripped — what we substitute into ``tools/list`` responses.
    The map keys are granular names (e.g. ``messages_search``) and values
    are the composite+action pair the rewriter forwards as.
    """
    with open(path) as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict) or "tools" not in raw:
        raise ValueError(f"{path}: expected top-level mapping with 'tools' key")

    tools_for_emit: list[dict[str, Any]] = []
    name_to_composite: dict[str, tuple[str, str | None]] = {}
    for entry in raw["tools"]:
        if not isinstance(entry, dict) or "name" not in entry:
            raise ValueError(f"{path}: each tool entry needs a 'name'")
        name = entry["name"]
        composite = entry.get("_composite", name)
        action = entry.get("_action")
        name_to_composite[name] = (composite, action)
        clean = {k: v for k, v in entry.items() if k not in _PROXY_META_FIELDS}
        tools_for_emit.append(clean)

    log.info(
        "loaded %d granular tool schemas from %s (composites: %s)",
        len(tools_for_emit), path,
        sorted({c for c, _ in name_to_composite.values()}),
    )
    return tools_for_emit, name_to_composite


# ---------------------------------------------------------------------------
# Rewrite helpers
# ---------------------------------------------------------------------------


def rewrite_tools_call(
    payload: dict[str, Any], name_to_composite: dict[str, tuple[str, str | None]]
) -> dict[str, Any]:
    """Translate granular tool name → upstream composite + action.

    Input shape (per MCP spec): ``{jsonrpc, id, method:"tools/call",
    params:{name, arguments}}``. If ``name`` is a granular tool we
    recognize, mutate to the composite shape. Unknown names pass through
    untouched (logged warning — likely upstream added a new tool the
    proxy hasn't been taught yet).

    Returns the (possibly mutated) payload. Caller is responsible for
    re-serializing.
    """
    if payload.get("method") != "tools/call":
        return payload
    params = payload.get("params") or {}
    name = params.get("name")
    if not isinstance(name, str) or name not in name_to_composite:
        if isinstance(name, str):
            log.warning("tools/call for unknown granular tool %r — passing through", name)
        return payload

    composite, action = name_to_composite[name]
    if composite == name and action is None:
        # Leaf tool (help, config__open_relay) — no rewrite needed
        return payload

    args = dict(params.get("arguments") or {})
    if action is not None:
        args["action"] = action
    params["name"] = composite
    params["arguments"] = args
    payload["params"] = params
    log.debug("tools/call rewrite: %s → %s (action=%s)", name, composite, action)
    return payload


def rewrite_tools_list_response(
    payload: dict[str, Any], tools_for_emit: list[dict[str, Any]]
) -> dict[str, Any]:
    """Substitute the upstream tools array with our granular set.

    Only mutates if the payload is a tools/list response (i.e. has
    ``result.tools``). Otherwise pass-through.
    """
    if not isinstance(payload, dict):
        return payload
    result = payload.get("result")
    if not isinstance(result, dict) or "tools" not in result:
        return payload

    upstream_names = sorted(t.get("name", "?") for t in result.get("tools") or [])
    result["tools"] = tools_for_emit
    log.info(
        "tools/list rewrite: upstream %s (%d) → granular (%d)",
        upstream_names, len(upstream_names), len(tools_for_emit),
    )
    return payload


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


app = FastAPI(title="email-mcp-proxy", version="0.1")


@app.on_event("startup")
async def _startup() -> None:
    app.state.tools_for_emit, app.state.name_to_composite = load_schemas(SCHEMA_FILE)
    # One persistent client per process — connection pooling, HTTP/2 disabled
    # (email-mcp speaks HTTP/1.1 only via the docker network).
    app.state.http = httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S)
    log.info("proxy ready: forwarding to %s, listening on :%d", EMAIL_MCP_URL, LISTEN_PORT)


@app.on_event("shutdown")
async def _shutdown() -> None:
    with contextlib.suppress(Exception):
        await app.state.http.aclose()


@app.get("/health")
async def health() -> Response:
    """200 if schemas loaded AND upstream's well-known returns 200."""
    try:
        r = await app.state.http.get(
            f"{EMAIL_MCP_URL}/.well-known/oauth-authorization-server",
            timeout=5.0,
        )
        if r.status_code != 200:
            return JSONResponse(
                {"status": "degraded", "upstream_well_known": r.status_code},
                status_code=503,
            )
    except Exception as exc:
        return JSONResponse({"status": "degraded", "error": str(exc)}, status_code=503)
    return JSONResponse({
        "status": "ok",
        "upstream": EMAIL_MCP_URL,
        "granular_tools": len(app.state.tools_for_emit),
    })


# Headers we drop on the way to upstream because httpx/uvicorn set them
# automatically — preserving the inbound versions causes confusion (chunked
# transfer, host, etc.).
_HOP_BY_HOP_REQUEST_DROP = {"host", "content-length", "transfer-encoding", "connection"}
_HOP_BY_HOP_RESPONSE_DROP = {"content-length", "transfer-encoding", "connection"}


def _forward_request_headers(headers) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in _HOP_BY_HOP_REQUEST_DROP:
            continue
        out[k] = v
    return out


def _forward_response_headers(headers) -> list[tuple[str, str]]:
    out = []
    for k, v in headers.items():
        if k.lower() in _HOP_BY_HOP_RESPONSE_DROP:
            continue
        out.append((k, v))
    return out


@app.post("/mcp")
async def mcp(request: Request) -> Response:
    """Forward MCP requests to email-mcp, rewriting tool names both directions.

    Streamable HTTP supports two response shapes from the same endpoint:
    JSON (``application/json``) or SSE (``text/event-stream``). We have
    to handle both. SSE is more complex because we need to rewrite
    each ``data:`` line's JSON-RPC payload inline as it streams through.
    """
    raw_body = await request.body()
    # Best-effort parse for rewriting; if body isn't JSON we just forward
    # as-is (notifications/batched-requests/etc).
    payload: dict[str, Any] | None = None
    with contextlib.suppress(Exception):
        payload = json.loads(raw_body) if raw_body else None

    if isinstance(payload, dict):
        payload = rewrite_tools_call(payload, request.app.state.name_to_composite)
        body_out = json.dumps(payload).encode()
    else:
        body_out = raw_body

    headers = _forward_request_headers(request.headers)

    # Streamable HTTP transport requires we ask for both content types.
    if "accept" not in {k.lower() for k in headers}:
        headers["Accept"] = "application/json, text/event-stream"

    upstream_url = f"{EMAIL_MCP_URL}/mcp"
    log.debug("forward POST %s (body=%d bytes)", upstream_url, len(body_out))

    try:
        # Stream the response so SSE works; we manually buffer for JSON
        # responses below.
        req = request.app.state.http.build_request(
            "POST", upstream_url, content=body_out, headers=headers,
        )
        upstream = await request.app.state.http.send(req, stream=True)
    except httpx.HTTPError as exc:
        log.error("upstream forward failed: %s", exc)
        return JSONResponse({"error": "upstream unreachable", "detail": str(exc)}, status_code=502)

    content_type = upstream.headers.get("content-type", "")
    response_headers = _forward_response_headers(upstream.headers)

    if "text/event-stream" in content_type:
        # SSE: stream through, rewriting any data: lines whose JSON-RPC
        # payload is a tools/list response.
        async def _sse_iter():
            try:
                buf = b""
                async for chunk in upstream.aiter_bytes():
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        yield _maybe_rewrite_sse_line(line, request.app) + b"\n"
                if buf:
                    yield _maybe_rewrite_sse_line(buf, request.app)
            finally:
                await upstream.aclose()

        return StreamingResponse(
            _sse_iter(),
            status_code=upstream.status_code,
            headers=dict(response_headers),
            media_type=content_type,
        )

    # Non-SSE: buffer + rewrite + return
    try:
        body = await upstream.aread()
    finally:
        await upstream.aclose()

    if "application/json" in content_type:
        with contextlib.suppress(Exception):
            resp_payload = json.loads(body)
            resp_payload = rewrite_tools_list_response(
                resp_payload, request.app.state.tools_for_emit,
            )
            body = json.dumps(resp_payload).encode()

    return Response(
        content=body,
        status_code=upstream.status_code,
        headers=dict(response_headers),
        media_type=content_type,
    )


def _maybe_rewrite_sse_line(line: bytes, app_obj) -> bytes:
    """Inspect an SSE line; if it's a data: tools/list response, rewrite it."""
    if not line.startswith(b"data: "):
        return line
    payload_bytes = line[len(b"data: "):].rstrip(b"\r")
    if not payload_bytes:
        return line
    try:
        payload = json.loads(payload_bytes)
    except Exception:
        return line
    rewritten = rewrite_tools_list_response(payload, app_obj.state.tools_for_emit)
    return b"data: " + json.dumps(rewritten).encode()


def main() -> int:
    # Uvicorn config picked deliberately for the proxy:
    # - single worker (no shared state needed; one process per container)
    # - no access log (we log per-request at debug level)
    # - server_header=False (no Server: uvicorn leak to MCP clients)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=LISTEN_PORT,
        log_level=LOG_LEVEL.lower(),
        access_log=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
