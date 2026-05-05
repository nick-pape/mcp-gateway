"""Entrypoint for ``python -m mcp_hub`` and the ``mcp-hub`` console script.

Loads ``policy.yaml`` (path from ``MCP_HUB_CONFIG`` env, default
``/etc/mcp-pape-house/policy.yaml``), builds the hub, registers the
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
from pathlib import Path
from typing import Any

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .approvers.ntfy import NtfyApprover
from .audit import Audit
from .auth import AuthentikJWTValidator
from .factory import build_approver, build_refresher_manager, build_secret_backend
from .policy import Policy
from .server import Hub

logger = logging.getLogger(__name__)


def _config_path() -> Path:
    return Path(os.environ.get("MCP_HUB_CONFIG", "/etc/mcp-pape-house/policy.yaml"))


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

    # Wire /hitl/ack webhook route iff the approver supports it (NtfyApprover).
    if isinstance(approver, NtfyApprover):
        async def hitl_ack(request: Request) -> Response:
            nonce = request.query_params.get("nonce", "")
            try:
                body: dict[str, Any] = await request.json()
            except (ValueError, RuntimeError):
                body = {}
            status = await approver.handle_webhook(nonce=nonce, body=body)
            return JSONResponse({"ok": True}, status_code=status)

        # FastMCP exposes its underlying ASGI app for adding custom routes.
        # The exact attribute name varies by version; read the source if this
        # breaks. As of 2.14, ``mcp.streamable_http_app()`` returns the app.
        hub.mcp.custom_route(server_cfg.hitl_webhook_path, methods=["POST"])(hitl_ack)

    async def health(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    hub.mcp.custom_route("/health", methods=["GET"])(health)

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
