"""Per-request auth strategies for HTTP MCP upstreams.

Stdio MCPs receive their credentials at spawn time via a per-UID token
file. HTTP MCPs accept credentials per request via an Authorization
header. The hub therefore needs a small abstraction that, given an
``identity`` and the current request's context, returns the headers
to attach when forwarding to the upstream.

Strategies are constructed at hub startup (one per HTTP fanout) from
``policy.yaml`` and live for the process lifetime. They MUST be safe
to call concurrently from many tasks.

Built-in strategies:

- :class:`BaoBackedBearer` — resolves a per-identity secret from
  :class:`mcp_hub.interfaces.SecretBackend` and emits
  ``Authorization: Bearer <value>``. Caches resolved values for a
  short TTL because the existing :class:`mcp_hub.secrets.bao.BaoSecretBackend`
  re-logs-in on every ``resolve()`` call.

- :class:`JwtPassthrough` — forwards the agent's incoming JWT (set in
  request context by :class:`mcp_hub.middleware.IdentityMiddleware`) as
  the upstream Bearer header. Useful for HTTP MCPs that natively trust
  the same Authentik issuer.

Adding a strategy:

1. Implement the :class:`AuthStrategy` Protocol below.
2. Wire a discriminator value in
   :func:`mcp_hub.factory.build_auth_strategy` (the dispatch point).
3. Document its config shape in ``policy.example.yaml``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Protocol, runtime_checkable

from .interfaces import SecretBackend, SecretRef, SecretResolutionError

# Default cache TTL for BaoBackedBearer: 30s. Rationale: bao tokens are
# short-lived but we don't want to log in to bao on every single request.
# 30s is short enough that token rotation propagates promptly without
# making bao's auth path the gateway's bottleneck.
DEFAULT_BAO_CACHE_TTL_S: float = 30.0


# Request-context keys that strategies read. Defined here so callers
# (server.py) and strategies share one source of truth.
#
# The IdentityMiddleware stores ``identity`` and ``request_id`` in
# fastmcp_context state. For JwtPassthrough we additionally capture the
# raw bearer token under ``bearer_token`` — see middleware.py.
CTX_KEY_BEARER_TOKEN: str = "bearer_token"  # noqa: S105 (state key, not a secret)


@runtime_checkable
class AuthStrategy(Protocol):
    """Produce per-request auth headers for an upstream HTTP MCP.

    Implementations MUST be coroutine-safe (the same instance is shared
    across all in-flight requests for one HttpFanout).
    """

    name: str

    async def auth_header(
        self,
        *,
        identity: str,
        request_context: dict[str, Any],
    ) -> dict[str, str]:
        """Return the headers to attach to the outgoing upstream request.

        ``request_context`` is a dict carrying per-request state (e.g.,
        the agent's incoming JWT for passthrough strategies). The exact
        keys depend on the strategy; producers MUST set whatever keys
        their configured strategies need.

        Strategies that fail to produce credentials should raise — the
        caller (HttpFanout.call) translates the failure into a fanout
        exception that the hub surfaces as an MCP error.
        """
        ...

    async def close(self) -> None:
        """Release resources (HTTP clients, etc.)."""
        ...


# ---------------------------------------------------------------------------
# BaoBackedBearer
# ---------------------------------------------------------------------------


class BaoBackedBearer:
    """AuthStrategy that resolves the upstream Bearer token from a SecretBackend.

    Reads ``ref = SecretRef(path=path_template.format(identity=identity), field=field)``
    via the configured backend on each call (with a small in-memory
    cache to avoid hammering bao). Returns
    ``{"Authorization": f"Bearer {value}"}``.

    The cache stores the resolved value per identity for ``cache_ttl_s``
    seconds. A short TTL is critical: bao tokens DO rotate and we
    don't want stale caches surviving across rotations.
    """

    name: str = "bao_backed_bearer"

    def __init__(
        self,
        *,
        secret_backend: SecretBackend,
        mcp_name: str,
        path_template: str,
        field: str,
        cache_ttl_s: float = DEFAULT_BAO_CACHE_TTL_S,
    ) -> None:
        if "{identity}" not in path_template:
            # Allow callers to use a fully-static path (shared upstream
            # token across identities); but warn-by-validation against
            # the most likely typo: forgetting the placeholder.
            #
            # Static paths are legitimate when one upstream API token
            # is shared across all identities. We accept it; the
            # cache then collapses to a single shared entry under
            # whichever identity requested first. Identity-keyed cache
            # entries with the same path keep that fan-in-safe.
            pass
        self._backend = secret_backend
        self._mcp_name = mcp_name
        self._path_template = path_template
        self._field = field
        self._cache_ttl_s = cache_ttl_s
        # identity -> (header_value, expires_at_monotonic)
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    async def auth_header(
        self,
        *,
        identity: str,
        request_context: dict[str, Any],
    ) -> dict[str, str]:
        # request_context is unused for bao-backed strategy — secret
        # lookup is keyed entirely by identity.
        del request_context
        bearer = await self._resolve(identity)
        return {"Authorization": f"Bearer {bearer}"}

    async def _resolve(self, identity: str) -> str:
        now = time.monotonic()
        # Fast path: serve cached without lock if fresh.
        cached = self._cache.get(identity)
        if cached is not None and cached[1] > now:
            return cached[0]

        # Slow path: take the lock and double-check.
        async with self._lock:
            cached = self._cache.get(identity)
            now = time.monotonic()
            if cached is not None and cached[1] > now:
                return cached[0]

            ref = SecretRef(
                path=self._path_template.format(identity=identity),
                field=self._field,
            )
            try:
                resolved = await self._backend.resolve(
                    mcp=self._mcp_name, identity=identity, ref=ref
                )
            except SecretResolutionError:
                # Don't cache failures; let the next call retry.
                raise
            self._cache[identity] = (resolved.value, now + self._cache_ttl_s)
            return resolved.value

    async def close(self) -> None:
        # The SecretBackend is owned by the hub composer (factory.py),
        # not by this strategy. Closing it here would tear down
        # whatever else is using it. No-op.
        return None


# ---------------------------------------------------------------------------
# JwtPassthrough
# ---------------------------------------------------------------------------


class JwtPassthrough:
    """AuthStrategy that forwards the agent's inbound JWT as the upstream Bearer.

    Reads the raw token out of ``request_context[CTX_KEY_BEARER_TOKEN]``
    (the IdentityMiddleware stashes it there after validation).
    Useful when the upstream MCP natively trusts the same Authentik
    issuer and audience.

    Raises :class:`ValueError` if the bearer token is missing from the
    request context — the hub surfaces this as an internal error since
    middleware ordering should always set it.
    """

    name: str = "jwt_passthrough"

    async def auth_header(
        self,
        *,
        identity: str,
        request_context: dict[str, Any],
    ) -> dict[str, str]:
        del identity  # not used; the JWT IS the identity proof
        token = request_context.get(CTX_KEY_BEARER_TOKEN)
        if not isinstance(token, str) or not token:
            raise ValueError(
                "JwtPassthrough: request_context missing "
                f"{CTX_KEY_BEARER_TOKEN!r}; ensure IdentityMiddleware "
                "ran before this dispatch and stashed the bearer token"
            )
        return {"Authorization": f"Bearer {token}"}

    async def close(self) -> None:
        return None
