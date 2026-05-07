"""mcp-wrapper-base — generic Authentik-fronted HTTPS-to-stdio bridge.

Spawns a configured stdio MCP child once at startup, exposes /mcp as a
Streamable-HTTP endpoint, validates inbound JWTs against the homelab's
Authentik issuer + JWKS. Tokens for the spawned child are passed via
env at container spawn time (orchestrator-injected, no on-disk state).

Required env:
    MCP_COMMAND            shlex-parseable command for the stdio MCP child
    OIDC_ISSUER            iss claim value, e.g. https://auth.pape.house/
    OIDC_DISCOVERY_URL     OIDC discovery base, e.g.
                           https://auth.pape.house/application/o/mcp-fanout-svc/
                           (JWKS is fetched from <discovery>/.well-known/openid-configuration)
    OIDC_AUDIENCE          aud claim value, e.g. mcp-interactive

Optional env:
    LISTEN_PORT            default 8080
    LOG_LEVEL              default INFO
    JWT_CLOCK_SKEW_S       default 30
    JWKS_CACHE_TTL_S       default 600
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import sys
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _required_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        sys.stderr.write(f"FATAL: required env {name} is unset\n")
        sys.exit(2)
    return val


MCP_COMMAND = _required_env("MCP_COMMAND")
OIDC_ISSUER = _required_env("OIDC_ISSUER")
OIDC_DISCOVERY_URL = _required_env("OIDC_DISCOVERY_URL").rstrip("/")
OIDC_AUDIENCE = _required_env("OIDC_AUDIENCE")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
JWT_CLOCK_SKEW_S = int(os.environ.get("JWT_CLOCK_SKEW_S", "30"))
JWKS_CACHE_TTL_S = int(os.environ.get("JWKS_CACHE_TTL_S", "600"))

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("mcp-wrapper")


# ---------------------------------------------------------------------------
# JWKS cache + JWT validation
# ---------------------------------------------------------------------------

_jwt = JsonWebToken(["RS256"])


class JWKSCache:
    """Fetch JWKS from the OIDC discovery doc; cache with TTL.

    Single-flight refresh via the lock — concurrent requests don't trigger
    duplicate JWKS fetches. JWKS itself is rotated by Authentik very rarely;
    the TTL is mostly to bound how long a compromised-then-revoked key
    stays valid.
    """

    def __init__(self, discovery_url: str, ttl_s: int) -> None:
        self._discovery_url = discovery_url
        self._ttl_s = ttl_s
        self._jwks: JsonWebKey | None = None
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def populated(self) -> bool:
        return self._jwks is not None

    async def get(self, http: httpx.AsyncClient) -> JsonWebKey:
        async with self._lock:
            now = time.monotonic()
            if self._jwks is not None and (now - self._fetched_at) < self._ttl_s:
                return self._jwks
            disc = (await http.get(f"{self._discovery_url}/.well-known/openid-configuration", timeout=10.0)).raise_for_status().json()
            jwks_uri = disc["jwks_uri"]
            jwks_data = (await http.get(jwks_uri, timeout=10.0)).raise_for_status().json()
            self._jwks = JsonWebKey.import_key_set(jwks_data)
            self._fetched_at = now
            logger.info(
                "Refreshed JWKS from %s (%d keys)",
                jwks_uri, len(jwks_data.get("keys", [])),
            )
            return self._jwks


_jwks_cache = JWKSCache(OIDC_DISCOVERY_URL, JWKS_CACHE_TTL_S)


async def validate_token(http: httpx.AsyncClient, token: str) -> dict[str, Any]:
    """Validate signature + iss + aud + exp; return the decoded claims."""
    jwks = await _jwks_cache.get(http)
    claims_options = {
        "iss": {"essential": True, "value": OIDC_ISSUER},
        "aud": {"essential": True, "value": OIDC_AUDIENCE},
        "exp": {"essential": True},
    }
    try:
        claims = _jwt.decode(token, key=jwks, claims_options=claims_options)
        claims.validate(leeway=JWT_CLOCK_SKEW_S)
    except JoseError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token: {exc}")
    return dict(claims)


async def jwt_dep(request: Request) -> dict[str, Any]:
    """FastAPI dependency: extract Bearer token, validate, return claims."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing Bearer token")
    token = auth_header[len("bearer ") :].strip()
    return await validate_token(request.app.state.http, token)


# ---------------------------------------------------------------------------
# Stdio child management
# ---------------------------------------------------------------------------


class StdioChild:
    """Async wrapper around a stdio MCP subprocess.

    JSON-RPC over stdio is line-delimited. We serialize calls via an asyncio
    Lock — the child is single-process and the spec doesn't require
    multiplexed responses, so serialization is simpler than building an
    id-correlation table.
    """

    def __init__(self, command: str) -> None:
        self._command = command
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self) -> None:
        args = shlex.split(self._command)
        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # inherit → flows to the container's stderr / docker logs
        )
        logger.info("Spawned stdio child pid=%d cmd=%s", self._proc.pid, self._command)

    async def call(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Forward a JSON-RPC message. Returns the response, or None for notifications."""
        if not self.alive:
            raise RuntimeError("stdio child is not running")
        is_notification = "id" not in msg or msg.get("id") is None
        async with self._lock:
            assert self._proc is not None and self._proc.stdin is not None and self._proc.stdout is not None
            line = (json.dumps(msg, separators=(",", ":")) + "\n").encode()
            self._proc.stdin.write(line)
            await self._proc.stdin.drain()
            if is_notification:
                return None
            target_id = msg["id"]
            # Keep reading until we get a line matching our id — server-initiated
            # notifications could arrive interleaved (e.g., progress updates). We
            # drop those for v0; an id-aware multiplexer is a follow-up.
            while True:
                resp_line = await self._proc.stdout.readline()
                if not resp_line:
                    raise RuntimeError("stdio child closed stdout unexpectedly")
                try:
                    parsed = json.loads(resp_line)
                except json.JSONDecodeError:
                    logger.warning("non-JSON line from child: %r", resp_line[:200])
                    continue
                if parsed.get("id") == target_id:
                    return parsed
                logger.debug("dropping out-of-order child msg: %s", parsed)

    async def stop(self) -> None:
        if self._proc is None:
            return
        if self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        logger.info("stdio child exited rc=%s", self._proc.returncode)
        self._proc = None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0))
    app.state.child = StdioChild(MCP_COMMAND)
    await app.state.child.start()
    # Best-effort warm JWKS so the first real call doesn't pay the discovery latency.
    try:
        await _jwks_cache.get(app.state.http)
    except Exception as exc:
        logger.warning("JWKS prefetch failed (will retry on first call): %s", exc)
    try:
        yield
    finally:
        await app.state.child.stop()
        await app.state.http.aclose()


app = FastAPI(lifespan=lifespan, title="mcp-wrapper")


@app.get("/health")
async def health() -> Response:
    if not app.state.child.alive:
        return JSONResponse({"status": "child-dead"}, status_code=503)
    return JSONResponse({"status": "ok"})


@app.get("/ready")
async def ready() -> Response:
    if not app.state.child.alive:
        return JSONResponse({"status": "child-dead"}, status_code=503)
    if not _jwks_cache.populated:
        return JSONResponse({"status": "jwks-not-fetched"}, status_code=503)
    return JSONResponse({"status": "ready"})


@app.post("/mcp")
async def mcp(request: Request, _claims: dict[str, Any] = Depends(jwt_dep)):
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body must be a JSON object")
    try:
        response = await asyncio.wait_for(app.state.child.call(body), timeout=60.0)
    except asyncio.TimeoutError:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "stdio child did not respond within 60s")
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    if response is None:
        # Notification — JSON-RPC says no response. Per the Streamable-HTTP MCP
        # spec, returning 202 Accepted with empty body is conventional.
        return Response(status_code=202)
    return JSONResponse(response)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "entrypoint:app",
        host="0.0.0.0",
        port=LISTEN_PORT,
        log_level=LOG_LEVEL.lower(),
        access_log=False,
    )
