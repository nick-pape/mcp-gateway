"""Entrypoint for ``python -m mcp_hub`` and the ``mcp-hub`` console script.

Loads ``policy.yaml`` (path from ``MCP_HUB_CONFIG`` env, default
``/etc/mcp-gateway/policy.yaml``), builds the hub, registers the
``/hitl/ack`` webhook route on the FastMCP HTTP app (when the approver
needs it), and runs streamable HTTP.

End-to-end validation of this entry happens in Phase 11 (real Authentik
device flow + real ntfy push from Claude Code). Phase 8 ships the wiring;
the smoke happens then.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .audit import Audit
from .auth import AuthentikJWTValidator
from .factory import build_approver, build_refresher_manager, build_secret_backend
from .interfaces import WebhookApprover, WebhookRoute
from .policy import Policy
from .server import Hub

logger = logging.getLogger(__name__)


def _config_path() -> Path:
    return Path(os.environ.get("MCP_HUB_CONFIG", "/etc/mcp-gateway/policy.yaml"))


def _runtime_dir() -> Path:
    return Path(os.environ.get("MCP_HUB_RUNTIME_DIR", "/run"))


async def _async_main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config_path = _config_path()
    if not config_path.exists():
        logger.error("config not found at %s", config_path)
        return 1

    policy = Policy.from_yaml(config_path)
    auth = policy.config.auth
    server_cfg = policy.config.server

    # Single httpx client shared across backends to keep connection pools warm.
    http_client = httpx.AsyncClient(timeout=10.0)

    validator = AuthentikJWTValidator(
        jwks_uri=auth.jwks_uri,
        issuer=auth.issuer,
        audience_prefix=auth.audience_prefix,
        algorithms=auth.algorithms,
        clock_skew_s=auth.clock_skew_s,
        cache_ttl_s=auth.cache_ttl_s,
        http_client=http_client,
    )
    secret_backend = build_secret_backend(policy.config, http_client=http_client)
    approver = build_approver(policy.config, http_client=http_client)
    audit = Audit()  # default: stderr → Loki via Promtail

    # Token refreshers MUST mint before Hub.start() — Hub.start() does the
    # bao login that reads role_jwt_path, which is the refresher's output.
    # Build, mint synchronously, THEN start hub, THEN spawn rotation tasks.
    refresher_manager = build_refresher_manager(policy.config)
    try:
        await refresher_manager.mint_initial()
    except Exception:
        logger.exception("token refresher initial mint failed; exiting")
        await refresher_manager.close()
        await http_client.aclose()
        return 1

    hub = Hub(
        policy=policy,
        secret_backend=secret_backend,
        approver=approver,
        validator=validator,
        audit=audit,
        runtime_dir=_runtime_dir(),
    )

    try:
        await hub.start()
    except Exception:
        logger.exception("hub start failed; exiting")
        await refresher_manager.close()
        await http_client.aclose()
        return 1

    # Hub is up + bao login succeeded → safe to rotate underneath.
    refresher_manager.start_background()

    # Mount any callback routes the approver needs (e.g. ntfy's /hitl/ack).
    # Generic: any approver implementing WebhookApprover self-registers its
    # routes; auto/reject implement nothing and register none.
    if isinstance(approver, WebhookApprover):
        for route in approver.webhook_routes():

            def _adapter(
                r: WebhookRoute,
            ) -> Callable[[Request], Awaitable[Response]]:
                async def _handler(request: Request) -> Response:
                    try:
                        body: dict[str, Any] = await request.json()
                    except (ValueError, RuntimeError):
                        body = {}
                    status, payload = await r.handler(
                        dict(request.query_params), body
                    )
                    return JSONResponse(payload, status_code=status)

                return _handler

            hub.mcp.custom_route(route.path, methods=list(route.methods))(
                _adapter(route)
            )

    async def health(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    hub.mcp.custom_route("/health", methods=["GET"])(health)

    # OAuth discovery + DCR shim. The hub doesn't run its own OAuth server;
    # we proxy discovery to Authentik (mcp-interactive provider) and fake
    # Dynamic Client Registration since Authentik's /application/o/register/
    # endpoint requires a per-tenant feature flag we haven't enabled. All
    # MCP clients land on the same registered Authentik client_id —
    # acceptable because Authentik's redirect_uri regex on that provider
    # already allows any http://localhost:* loopback (Claude Code's pattern),
    # and the OAuth flow + JWT validation downstream is identical regardless
    # of which client requested registration.
    #
    # Three endpoints:
    # - /.well-known/oauth-protected-resource  (RFC 9728) — points at us
    # - /.well-known/oauth-authorization-server (RFC 8414) — full metadata
    #   copying Authentik's endpoints + registration_endpoint=us
    # - POST /oauth/register (RFC 7591) — static response, ignores body
    #   except echoing redirect_uris back

    INTERACTIVE_CLIENT_ID = "mcp-interactive"
    AUTHENTIK_BASE = "https://auth.pape.house"

    def _public_base(request: Request) -> str:
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.url.netloc)
        return f"{scheme}://{host}"

    async def oauth_protected_resource(request: Request) -> Response:
        base = _public_base(request)
        return JSONResponse({
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            # offline_access is the standard scope a client requests to
            # opt into refresh-token issuance (RFC 6749 §1.5 / SEP-2207).
            # Claude Code today doesn't try refresh, but advertising the
            # scope here means we're correct from the day it ships.
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
        })

    async def oauth_authorization_server(request: Request) -> Response:
        base = _public_base(request)
        return JSONResponse({
            # Issuer matches the JWT's iss claim (Authentik), not the
            # discovery host, per RFC 8414 §3 — clients verify token iss
            # against this value.
            "issuer": auth.issuer,
            "authorization_endpoint": f"{AUTHENTIK_BASE}/application/o/authorize/",
            "token_endpoint": f"{AUTHENTIK_BASE}/application/o/token/",
            "userinfo_endpoint": f"{AUTHENTIK_BASE}/application/o/userinfo/",
            "jwks_uri": f"{AUTHENTIK_BASE}/application/o/{INTERACTIVE_CLIENT_ID}/jwks/",
            "registration_endpoint": f"{base}/oauth/register",
            # See oauth_protected_resource for why offline_access is here.
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })

    async def oauth_register(request: Request) -> Response:
        # RFC 7591 minimal response. We don't actually persist anything —
        # every caller gets the same INTERACTIVE_CLIENT_ID. Echo back the
        # redirect_uris the client provided so it can verify the response.
        try:
            body: dict[str, Any] = await request.json()
        except (ValueError, RuntimeError):
            body = {}
        redirect_uris = body.get("redirect_uris") or []
        # Keep the response shape strict to RFC 7591 — clients vary in
        # how they parse extra fields.
        return JSONResponse({
            "client_id": INTERACTIVE_CLIENT_ID,
            "client_id_issued_at": int(__import__("time").time()),
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": body.get("client_name", "MCP Client"),
        }, status_code=201)

    # Both /.well-known paths — clients vary on which they probe first.
    hub.mcp.custom_route(
        "/.well-known/oauth-protected-resource",
        methods=["GET"],
    )(oauth_protected_resource)
    hub.mcp.custom_route(
        "/.well-known/oauth-protected-resource/mcp",
        methods=["GET"],
    )(oauth_protected_resource)
    hub.mcp.custom_route(
        "/.well-known/oauth-authorization-server",
        methods=["GET"],
    )(oauth_authorization_server)
    hub.mcp.custom_route(
        "/oauth/register",
        methods=["POST"],
    )(oauth_register)

    bind_host, _, bind_port_s = server_cfg.bind.partition(":")
    bind_port = int(bind_port_s) if bind_port_s else 8443
    logger.info("hub starting on %s:%d", bind_host, bind_port)
    try:
        await hub.mcp.run_async(transport="http", host=bind_host, port=bind_port)
    finally:
        await refresher_manager.close()
        await hub.close()
        await http_client.aclose()

    return 0


def main() -> int:
    return asyncio.run(_async_main())


if __name__ == "__main__":
    sys.exit(main())
