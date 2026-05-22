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

- :class:`FanoutJwt` — forwards the hub's OWN service-account JWT
  (the rotated ``fanout_jwt`` written by ``mcp_hub.refresher`` to
  ``/etc/mcp-gateway/fanout_jwt``) as the upstream Bearer
  regardless of caller identity. Use with ``scope: shared`` container
  MCPs whose wrapper accepts ``aud=mcp-fanout-svc`` via
  ``OIDC_BOOT_AUDIENCE``. Per-identity HITL/audit still happens
  hub-side via the inbound caller JWT — only the upstream-facing
  request uses the hub's JWT.

Adding a strategy:

1. Implement the :class:`AuthStrategy` Protocol below.
2. Wire a discriminator value in
   :func:`mcp_hub.factory.build_auth_strategy` (the dispatch point).
3. Document its config shape in ``policy.example.yaml``.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .interfaces import SecretBackend, SecretRef, SecretResolutionError
from .templating import expand_template

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


class SecretBearer:
    """AuthStrategy that resolves the upstream Bearer token from a SecretBackend.

    Reads ``ref = SecretRef(path=path_template.format(identity=identity), field=field)``
    via the configured backend on each call (with a small in-memory
    cache to avoid hammering bao). Returns
    ``{"Authorization": f"Bearer {value}"}``.

    The cache stores the resolved value per identity for ``cache_ttl_s``
    seconds. A short TTL is critical: bao tokens DO rotate and we
    don't want stale caches surviving across rotations.

    ``as_agent_identities`` controls *who authenticates to the secret store*
    per caller — the set of identities that should authenticate AS THEMSELVES:

    - identity NOT in the set (delegated / deputy): the backend uses the hub's
      own credentials to read the secret. Works at boot because no inbound
      request is needed.
    - identity IN the set (autonomous, as-agent): the strategy pulls the
      inbound agent JWT from ``request_context[CTX_KEY_BEARER_TOKEN]`` and
      passes it to the backend, so the store authenticates and audits the
      *agent* (e.g. a bao role bound to ``aud=mcp-<identity>``). The downstream
      Bearer injected is still the per-agent token at ``path_template``;
      as-agent only changes who proves identity to the store (closes the
      confused-deputy gap).

    This is per-identity (not per-MCP) because shared MCPs serve both delegated
    humans (stay deputy) and autonomous agents (as-agent).

    ``boot_capable`` is set by the factory: True when at least one of the MCP's
    identities can produce a header at boot (a delegated identity). Only False
    when EVERY identity is as-agent — then :class:`HttpFanout` skips the
    authenticated boot handshake and does a no-auth reachability probe.
    """

    name: str = "secret_bearer"

    def __init__(
        self,
        *,
        secret_backend: SecretBackend,
        mcp_name: str,
        path_template: str,
        field: str,
        cache_ttl_s: float = DEFAULT_BAO_CACHE_TTL_S,
        as_agent_identities: frozenset[str] | None = None,
        boot_capable: bool = True,
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
        self._as_agent_identities: frozenset[str] = frozenset(as_agent_identities or ())
        self._boot_capable = boot_capable
        # identity -> (header_value, expires_at_monotonic)
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    @property
    def boot_capable(self) -> bool:
        """Whether this strategy can produce a header at boot (no inbound JWT).

        False only when EVERY identity on this MCP is as-agent (no delegated
        identity to run the deputy boot handshake). HttpFanout reads this to
        decide whether to skip the authenticated boot handshake.
        """
        return self._boot_capable

    async def auth_header(
        self,
        *,
        identity: str,
        request_context: dict[str, Any],
    ) -> dict[str, str]:
        agent_jwt: str | None = None
        if identity in self._as_agent_identities:
            agent_jwt = request_context.get(CTX_KEY_BEARER_TOKEN)
            if not isinstance(agent_jwt, str) or not agent_jwt:
                raise ValueError(
                    f"SecretBearer(as-agent, mcp={self._mcp_name!r}, "
                    f"identity={identity!r}): request_context missing "
                    f"{CTX_KEY_BEARER_TOKEN!r}; the agent's inbound JWT is "
                    f"required to authenticate to the secret store as the agent. "
                    f"Ensure IdentityMiddleware ran first."
                )
        # Delegated identities pass agent_jwt=None → backend uses the hub's own
        # credentials (deputy). Autonomous identities forward their inbound JWT.
        bearer = await self._resolve(identity, agent_jwt)
        return {"Authorization": f"Bearer {bearer}"}

    async def _resolve(self, identity: str, agent_jwt: str | None = None) -> str:
        now = time.monotonic()
        # Fast path: serve cached without lock if fresh. (A cache hit needs no
        # agent_jwt — the resolved downstream token is per-identity.)
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
                path=expand_template(
                    self._path_template, identity=identity, mcp=self._mcp_name
                ),
                field=self._field,
            )
            try:
                resolved = await self._backend.resolve(
                    mcp=self._mcp_name, identity=identity, ref=ref, jwt=agent_jwt
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


# Back-compat alias: this strategy was named for the bao backend, but it only
# depends on the SecretBackend Protocol. `secret_bearer` is the canonical name;
# `bao_backed_bearer` keeps existing policy.yaml working.
BaoBackedBearer = SecretBearer


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


# ---------------------------------------------------------------------------
# NoneStrategy
# ---------------------------------------------------------------------------


class NoneStrategy:
    """AuthStrategy that adds no auth header to upstream requests.

    For upstreams that don't require auth — rare; usually only homelab-internal
    services that are gated by network ACL or by a token embedded in the URL
    path (e.g. Home Assistant's built-in MCP Server integration, which exposes
    ``/<random-token>/<rest>`` and ignores ``Authorization`` entirely).

    Returns an empty headers dict, which HttpFanout treats as "no headers to
    inject" — the rest of the request still carries httpx's defaults (Host,
    User-Agent, etc.). Use sparingly; prefer a real bearer scheme when the
    upstream offers one.
    """

    name: str = "none"

    async def auth_header(
        self,
        *,
        identity: str,
        request_context: dict[str, Any],
    ) -> dict[str, str]:
        del identity, request_context
        return {}

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# FanoutJwt
# ---------------------------------------------------------------------------


# Default path matches the refresher sink configured in policy.example.yaml
# (``token_refresh.fanout_jwt.sink.config.path``). Can be overridden in
# ``policy.yaml`` per fanout via ``auth.config.path``.
DEFAULT_FANOUT_JWT_PATH: str = "/etc/mcp-gateway/fanout_jwt"


class FanoutJwt:
    """AuthStrategy that forwards the hub's own ``fanout_jwt`` as the upstream Bearer.

    Reads the rotated JWT from disk on each call so the refresher can
    overwrite it without restarting the hub. Returns ``Authorization:
    Bearer <fanout_jwt>`` regardless of the inbound caller identity.

    Use with ``scope: shared`` container MCPs whose wrapper accepts
    ``aud=mcp-fanout-svc`` via ``OIDC_BOOT_AUDIENCE`` — the per-call
    JWT audiences vary by caller and won't match the spawn-time
    ``OIDC_AUDIENCE``, so passthrough doesn't work for shared containers.

    Per-identity audit/HITL is unaffected: those run inside the hub
    against the inbound caller JWT *before* this strategy fires.

    Raises ``ValueError`` if the JWT file is missing or empty (probably
    a refresher misconfiguration; not transient).
    """

    name: str = "fanout_jwt"

    def __init__(self, *, path: str = DEFAULT_FANOUT_JWT_PATH) -> None:
        self._path = Path(path)

    async def auth_header(
        self,
        *,
        identity: str,
        request_context: dict[str, Any],
    ) -> dict[str, str]:
        del identity, request_context  # not used; this is the hub-side JWT
        try:
            token = self._path.read_text(encoding="utf-8").strip()
        except FileNotFoundError as exc:
            raise ValueError(
                f"FanoutJwt: {self._path} does not exist; refresher should "
                f"have written it. Check token_refresh.fanout_jwt config."
            ) from exc
        except OSError as exc:
            raise ValueError(
                f"FanoutJwt: failed to read {self._path}: {exc}"
            ) from exc
        if not token:
            raise ValueError(f"FanoutJwt: {self._path} is empty")
        return {"Authorization": f"Bearer {token}"}

    async def close(self) -> None:
        return None
