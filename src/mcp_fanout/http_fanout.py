"""HTTP-transport variant of :class:`Fanout` for federated MCP servers.

Streamable-HTTP MCPs accept their credential per request (via
``Authorization``) rather than at spawn time. There is therefore no
need for the per-identity subprocess + per-UID token-file machinery
that :class:`Fanout` (the stdio variant) implements; the hub just
needs to inject the right header on each forwarded request.

:class:`HttpFanout` mirrors the stdio Fanout's external interface
(``start_eager_or_die``, ``call``, ``close``, ``mcp_name``,
``identities``) so the rest of the hub can treat both kinds
generically. The auth dispatch is delegated to an
:class:`mcp_hub.auth_strategies.AuthStrategy` injected by the factory.

Eager-or-die at boot still applies: a failed JSON-RPC ``initialize``
handshake against the upstream aborts hub startup the same way a
failed stdio child spawn does.

This module lives in :mod:`mcp_fanout` (alongside the stdio Fanout)
because it shares the public API surface; tests import both via
``from mcp_fanout import ...``.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from contextlib import suppress
from typing import Any

import httpx

from mcp_hub.auth_strategies import AuthStrategy

from .exceptions import HttpUpstreamFailed, IdentityNotFound

logger = logging.getLogger(__name__)


# Same default as stdio Fanout: 4 MiB cap on a single response. Anything
# larger is almost certainly a runaway upstream we don't want to
# absorb into hub RSS.
DEFAULT_MAX_RESPONSE_BYTES: int = 4 * 1024 * 1024

# Default per-request timeout for upstream HTTP MCP calls. Streamable
# HTTP MCPs sometimes do nontrivial work; 30s is generous without
# letting calls hang forever.
DEFAULT_REQUEST_TIMEOUT_S: float = 30.0


class HttpFanout:
    """Multi-identity HTTP MCP forwarder.

    Usage::

        fanout = HttpFanout(
            mcp_name="outline",
            url="https://notes.pape.house/mcp",
            auth_strategy=BaoBackedBearer(...),
            identities=["claude-code-dev", "interactive"],
        )
        await fanout.start_eager_or_die()
        result = await fanout.call(
            identity="claude-code-dev",
            request={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            request_context={"bearer_token": "..."},
        )
        await fanout.close()
    """

    def __init__(
        self,
        *,
        mcp_name: str,
        url: str,
        auth_strategy: AuthStrategy,
        identities: Sequence[str],
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not identities:
            raise ValueError(f"HttpFanout({mcp_name!r}) needs at least one identity")
        if len(set(identities)) != len(identities):
            raise ValueError(
                f"HttpFanout({mcp_name!r}) has duplicate identities: {sorted(identities)}"
            )
        if not url.startswith(("http://", "https://")):
            raise ValueError(
                f"HttpFanout({mcp_name!r}) url must be http(s)://, got {url!r}"
            )
        self._mcp_name = mcp_name
        self._url = url
        self._auth = auth_strategy
        self._identities: tuple[str, ...] = tuple(identities)
        self._max_response_bytes = max_response_bytes
        self._request_timeout_s = request_timeout_s
        # If the caller provided a client, we don't own it (no aclose
        # at .close() time). Otherwise we manage the lifecycle.
        self._http: httpx.AsyncClient | None = http_client
        self._owns_client: bool = http_client is None
        self._negotiated_protocol_version: str | None = None
        self._started: bool = False

    @property
    def mcp_name(self) -> str:
        return self._mcp_name

    @property
    def identities(self) -> tuple[str, ...]:
        return self._identities

    @property
    def negotiated_protocol_version(self) -> str | None:
        """Protocol version returned by the upstream's ``initialize``.

        ``None`` until ``start_eager_or_die`` has run. Recorded for
        observability — the upstream might respond differently to
        future requests based on this value, but currently we only
        log it.
        """
        return self._negotiated_protocol_version

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start_eager_or_die(self) -> None:
        """Open the HTTP client and confirm upstream connectivity.

        Performs one MCP ``initialize`` JSON-RPC against the upstream
        using the first identity's auth header. Any failure (network,
        HTTP 4xx/5xx, JSON-RPC error, malformed body) aborts hub startup,
        same as the stdio fanout's failed-child-spawn behavior.
        """
        if self._started:
            return
        if self._http is None:
            # HTTP/1.1 only — h2 isn't in deps and the federated upstreams
            # are LAN-local single-call workloads where multiplexing isn't
            # the bottleneck. If a real perf case for HTTP/2 emerges, add
            # `httpx[http2]` to pyproject.toml and flip http2=True back on.
            # Sensible timeouts to keep request bodies from hanging the
            # loop; default 5s connect/read is too aggressive for federated
            # MCPs that may be GC-paused at handshake.
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=self._request_timeout_s,
                    write=10.0,
                    pool=10.0,
                ),
            )
            self._owns_client = True

        # Use the first identity for the boot-time handshake. If the
        # auth strategy is identity-specific (BaoBackedBearer) this
        # also implicitly verifies the boot identity's secret resolves;
        # other identities' secrets are resolved lazily on first call.
        boot_identity = self._identities[0]
        try:
            init_response = await self._post_jsonrpc(
                identity=boot_identity,
                request={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "clientInfo": {
                            "name": "mcp-fanout-http",
                            "version": "0.0.0",
                        },
                    },
                },
                # Boot-time request_context is empty: BaoBackedBearer
                # ignores it; JwtPassthrough won't be configured for an
                # MCP whose boot-time auth is identity-only.
                request_context={},
            )
        except HttpUpstreamFailed:
            # Make sure we don't leak the http client we just opened.
            await self.close()
            raise

        if "error" in init_response:
            await self.close()
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): initialize failed: "
                f"{init_response['error']}"
            )

        # Stash the negotiated version for observability. The MCP spec
        # leaves room for the server to downgrade us; record what we got.
        result = init_response.get("result", {})
        if isinstance(result, dict):
            negotiated = result.get("protocolVersion")
            if isinstance(negotiated, str):
                self._negotiated_protocol_version = negotiated

        # Per spec: send notifications/initialized after init. Many
        # streamable-HTTP MCPs accept it as a fire-and-forget POST
        # (no JSON-RPC id, no response). Best-effort: log and continue
        # if the upstream rejects the notification.
        with suppress(HttpUpstreamFailed):
            await self._post_notification(
                identity=boot_identity,
                request={"jsonrpc": "2.0", "method": "notifications/initialized"},
                request_context={},
            )

        logger.info(
            "HttpFanout(%s) initialized: protocolVersion=%s",
            self._mcp_name,
            self._negotiated_protocol_version,
        )
        self._started = True

    async def call(
        self,
        *,
        identity: str,
        request: dict[str, Any],
        request_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Forward a JSON-RPC request to the upstream HTTP MCP.

        ``request_context`` carries strategy-specific per-request
        values (e.g., the agent's bearer token for JwtPassthrough).
        Defaults to an empty dict for backends (BaoBackedBearer) that
        don't read from it.
        """
        if not self._started:
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): not started; call "
                f"start_eager_or_die() first"
            )
        if identity not in self._identities:
            raise IdentityNotFound(
                f"HttpFanout({self._mcp_name}): unknown identity {identity!r}; "
                f"registered: {sorted(self._identities)}"
            )
        return await self._post_jsonrpc(
            identity=identity,
            request=request,
            request_context=request_context or {},
        )

    async def close(self) -> None:
        """Close the HTTP client (if owned). Idempotent."""
        if self._http is not None and self._owns_client:
            with suppress(Exception):
                await self._http.aclose()
        self._http = None
        self._started = False
        with suppress(Exception):
            await self._auth.close()

    # -----------------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------------

    async def _post_jsonrpc(
        self,
        *,
        identity: str,
        request: dict[str, Any],
        request_context: dict[str, Any],
    ) -> dict[str, Any]:
        if self._http is None:
            # call() before start_eager_or_die() is a programming bug.
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): not started; call "
                f"start_eager_or_die() first"
            )

        try:
            auth_headers = await self._auth.auth_header(
                identity=identity, request_context=request_context
            )
        except Exception as exc:
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): auth strategy "
                f"{self._auth.name!r} failed for identity={identity!r}: {exc}"
            ) from exc

        # MCP Streamable-HTTP transport spec: clients MUST send Accept
        # values for both application/json and text/event-stream. The
        # latter signals support for streamed responses; the upstream
        # may pick either. We handle the JSON path here and surface
        # SSE responses as an upstream error (the federation we
        # currently support is non-streaming).
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **auth_headers,
        }
        try:
            response = await self._http.post(
                self._url,
                json=request,
                headers=headers,
                timeout=self._request_timeout_s,
            )
        except httpx.HTTPError as exc:
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): network error calling "
                f"{self._url}: {exc}"
            ) from exc

        if response.status_code >= 400:
            # Truncate body for log/exception sanity; upstream errors
            # can be arbitrary HTML (Cloudflare-style 5xx pages).
            body_excerpt = response.text[:500]
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): upstream {self._url} "
                f"returned HTTP {response.status_code}: {body_excerpt!r}"
            )

        # httpx already buffers the body; checking length here costs
        # nothing and surfaces oversized bodies before json().
        body_bytes = response.content
        if len(body_bytes) > self._max_response_bytes:
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): upstream response "
                f"{len(body_bytes)} bytes > max_response_bytes="
                f"{self._max_response_bytes}"
            )

        # MCP Streamable-HTTP transport: server picks JSON or SSE per
        # response. Many upstreams (e.g., Outline's native MCP) always
        # reply with SSE even for single-result responses, so we must
        # handle both. For SSE we only support single-message replies
        # (one `event: message` block with one `data:` payload) — that's
        # all every known MCP upstream emits today. Multi-message
        # streaming would require a different return shape from `call()`.
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type.lower():
            try:
                parsed = _parse_single_sse_message(response.text)
            except ValueError as exc:
                raise HttpUpstreamFailed(
                    f"HttpFanout({self._mcp_name}): upstream returned "
                    f"unparseable SSE: {exc}"
                ) from exc
        else:
            try:
                parsed = response.json()
            except (ValueError, UnicodeDecodeError) as exc:
                raise HttpUpstreamFailed(
                    f"HttpFanout({self._mcp_name}): upstream returned "
                    f"unparseable JSON: {exc}"
                ) from exc

        if not isinstance(parsed, dict):
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): upstream returned "
                f"non-object JSON: {type(parsed).__name__}"
            )
        return parsed

    async def _post_notification(
        self,
        *,
        identity: str,
        request: dict[str, Any],
        request_context: dict[str, Any],
    ) -> None:
        """POST a JSON-RPC notification (no id, no response expected).

        Streamable-HTTP servers may respond with 202 Accepted and an
        empty body. We don't parse the response; we just check the
        status code so transient failures get logged.
        """
        if self._http is None:
            return
        try:
            auth_headers = await self._auth.auth_header(
                identity=identity, request_context=request_context
            )
        except Exception as exc:
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): auth strategy "
                f"{self._auth.name!r} failed for identity={identity!r}: {exc}"
            ) from exc
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **auth_headers,
        }
        try:
            response = await self._http.post(
                self._url,
                json=request,
                headers=headers,
                timeout=self._request_timeout_s,
            )
        except httpx.HTTPError as exc:
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): network error sending "
                f"notification to {self._url}: {exc}"
            ) from exc
        if response.status_code >= 400:
            raise HttpUpstreamFailed(
                f"HttpFanout({self._mcp_name}): notification rejected: "
                f"HTTP {response.status_code}"
            )


# ---------------------------------------------------------------------------
# SSE single-message parser
# ---------------------------------------------------------------------------


def _parse_single_sse_message(body: str) -> dict[str, Any]:
    """Parse an SSE response body and return the FINAL JSON-RPC reply.

    The MCP Streamable-HTTP transport allows servers to reply with SSE for
    request/response calls (Outline's native MCP always does; some others
    do for large responses). For our federation pattern each request
    expects exactly one logical reply, but the upstream may interleave
    intermediate ``notifications/progress`` messages before the final
    result — Home Assistant's MCP does this on ``get_history`` and other
    big-result tools.

    Strategy:
      1. Collect every ``data:`` line from the whole body (across event
         boundaries, ignoring ``event: ...`` headers — they exist only to
         help streaming clients dispatch). Per SSE spec, strip a single
         leading space after ``data:``.
      2. Fast path: join all data lines with newlines (matches the SSE
         spec for multi-line pretty-printed JSON in a single event) and
         try to parse as one JSON object. If the upstream emitted exactly
         one event with a single JSON payload, this succeeds.
      3. Fallback: parse each data line individually and return the LAST
         one that's a JSON object. This handles upstreams that emit
         multiple events (progress + final) — we throw away progress
         notifications (which are JSON-RPC requests with no ``id``) and
         return the final reply (which has an ``id`` matching ours).

    Raises :class:`ValueError` if the body has no parseable data line or
    nothing in it deserialises to a JSON object.
    """
    import json as _json

    data_lines: list[str] = []
    for raw_line in body.splitlines():
        if not raw_line.startswith("data:"):
            continue
        # SSE spec: strip a single leading space after "data:" if present.
        line = raw_line[len("data:") :]
        if line.startswith(" "):
            line = line[1:]
        data_lines.append(line)

    if not data_lines:
        raise ValueError(f"no data line in SSE body (first 200 chars: {body[:200]!r})")

    # Fast path: single event with one (possibly multi-line) JSON payload.
    joined = "\n".join(data_lines)
    try:
        parsed = _json.loads(joined)
    except _json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        return parsed

    # Fallback: multi-event responses (progress notifications followed by
    # the final reply). Parse each data line, keep the last dict. Final
    # JSON-RPC reply has an ``id``; intermediate progress notifications
    # don't — so the order matters and we want the LAST valid dict.
    last_dict: dict[str, Any] | None = None
    for line in data_lines:
        try:
            obj = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            last_dict = obj

    if last_dict is not None:
        return last_dict

    raise ValueError(
        f"SSE body had {len(data_lines)} data line(s) but none parsed to a JSON object "
        f"(first line preview: {data_lines[0][:200]!r})"
    )
