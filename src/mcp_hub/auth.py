"""Authentik OIDC JWT validation.

The hub validates inbound bearer JWTs against Authentik's published
JWKS. Each agent identity has its own Authentik OAuth client with its
own audience claim, e.g. ``mcp-ironclaw``. The hub extracts the
identity name from the ``aud`` suffix after stripping a configured
prefix (``mcp-``).

Security properties (called out in the architecture doc):

- **JWKS URI is pinned at startup** and never resolved from the JWT's
  ``kid``. A JWT with ``kid`` that looks like a URL is treated as a
  lookup key into the cached JWKS dict, not a fetch target. This is
  the single most important defense; one bug here breaks the whole
  auth model.

- **Algorithm allowlist is explicit** (``RS256`` only by default).
  pyjwt is never called with ``algorithms=None`` or omitted.

- **Issuer (``iss``) is validated** explicitly via pyjwt's
  ``issuer=`` param. Defense against token reuse from another
  Authentik client.

- **Audience prefix is validated manually** because pyjwt's built-in
  audience check is exact-match, not prefix-match. We disable
  ``verify_aud`` and check ourselves.

- **JWKS cache: serve-stale-on-warm-fail**. If JWKS fetch fails after
  we have a warm cache, we serve the cached version and log loudly.
  Cold-start failures propagate as :class:`AuthFailed`. This means
  Authentik briefly going down does NOT take the MCP plane down;
  Authentik being down at startup DOES.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import secrets
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import httpx
import jwt

from .errors import ErrorCode

if TYPE_CHECKING:
    from starlette.requests import Request

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class AuthFailed(Exception):
    """Raised when JWT validation fails for any reason.

    The :attr:`code` is always :attr:`ErrorCode.AUTH_FAILED` for now
    (the architecture's error taxonomy collapses all auth failures into
    one code; the audit ``error_code`` field carries the detail in
    free-text via the message).
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Identity:
    """The resolved calling identity, plus the raw inbound bearer when present.

    ``bearer_token`` is the credential the request carried (the JWT, in OIDC
    mode). HTTP-fanout strategies that forward the caller's token — JwtPassthrough
    and SecretBearer's as-agent path — read it from context. Non-OIDC modes that
    have no forwardable token leave it ``None``.
    """

    name: str
    claims: dict[str, Any]
    bearer_token: str | None = None


# ---------------------------------------------------------------------------
# Inbound authenticator Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class InboundAuthenticator(Protocol):
    """Resolves the calling identity from an inbound HTTP request.

    Implementations own the full "request → Identity" step (header extraction
    included), so :class:`mcp_hub.middleware.IdentityMiddleware` is agnostic to
    the auth mechanism (OIDC JWT, static token, trusted proxy, ...). Raise
    :class:`AuthFailed` on any failure; the middleware maps it to an MCP auth
    error. Must be coroutine-safe — one instance is shared across all in-flight
    requests.
    """

    async def authenticate(self, request: Request) -> Identity: ...

    async def close(self) -> None: ...


def _extract_bearer(request: Request) -> str:
    """Pull the token out of ``Authorization: Bearer <token>`` or raise."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise AuthFailed(ErrorCode.AUTH_FAILED, "missing bearer token")
    token = auth_header[len("bearer ") :].strip()
    if not token:
        raise AuthFailed(ErrorCode.AUTH_FAILED, "empty bearer token")
    return token


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class AuthentikJWTValidator:
    """Validate Authentik-issued JWTs with a pinned JWKS URI."""

    def __init__(
        self,
        *,
        jwks_uri: str,
        issuer: str,
        audience_prefix: str,
        algorithms: list[str] | None = None,
        clock_skew_s: int = 30,
        cache_ttl_s: int = 600,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not jwks_uri.startswith(("https://", "http://")):
            raise ValueError(f"jwks_uri must be http(s)://, got {jwks_uri!r}")
        self._jwks_uri = jwks_uri
        self._issuer = issuer
        self._audience_prefix = audience_prefix
        # Default to RS256 explicitly when omitted. An EMPTY list is a
        # config error — distinguish from None so we don't silently fall
        # back to defaults the caller didn't intend.
        if algorithms is None:
            self._algorithms = ["RS256"]
        elif not algorithms:
            raise ValueError("algorithms must be non-empty")
        else:
            self._algorithms = list(algorithms)
        self._clock_skew_s = clock_skew_s
        self._cache_ttl_s = cache_ttl_s
        self._http = http_client or httpx.AsyncClient(timeout=10.0)
        self._owns_client = http_client is None
        self._jwks: dict[str, Any] | None = None
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    # -----------------------------------------------------------------------
    # JWKS handling
    # -----------------------------------------------------------------------

    async def fetch_jwks(self) -> dict[str, Any]:
        """Return the current JWKS, refreshing the cache if stale.

        Behaviour matrix:

        - Warm cache, fresh (< ``cache_ttl_s`` old) → return cached
        - Warm cache, stale → try to refresh; on failure, serve stale + warn
        - No cache (cold start) → must fetch; failure propagates
        """
        async with self._lock:
            now = time.time()
            if self._jwks is not None and (now - self._fetched_at) < self._cache_ttl_s:
                return self._jwks

            try:
                response = await self._http.get(self._jwks_uri)
                response.raise_for_status()
                jwks = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                if self._jwks is None:
                    # Cold-start failure must propagate; we have nothing to serve.
                    raise AuthFailed(
                        ErrorCode.AUTH_FAILED,
                        f"JWKS fetch failed at cold start: {exc}",
                    ) from exc
                # Warm cache: serve stale, log loudly. Authentik briefly down
                # must not take the MCP plane down with it.
                logger.warning(
                    "jwks_serving_stale: jwks_uri=%s error=%s age_s=%d",
                    self._jwks_uri,
                    exc,
                    int(now - self._fetched_at),
                )
                return self._jwks

            if not isinstance(jwks, dict) or "keys" not in jwks:
                raise AuthFailed(
                    ErrorCode.AUTH_FAILED,
                    f"JWKS response missing 'keys' field: {jwks!r}",
                )

            self._jwks = jwks
            self._fetched_at = now
            return jwks

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    async def validate(self, token: str) -> Identity:
        """Validate ``token`` and return the :class:`Identity` it asserts.

        Raises :class:`AuthFailed` for any failure: bad signature, wrong
        audience prefix, expired, wrong issuer, unsupported alg, kid not
        in JWKS, etc.
        """
        # Step 1: pre-decode the unverified header. We need ``kid`` and
        # ``alg`` BEFORE we have the key to verify the signature. This
        # operation is safe — it parses the header but doesn't trust it.
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthFailed(ErrorCode.AUTH_FAILED, f"malformed JWT: {exc}") from exc

        alg = header.get("alg")
        if alg not in self._algorithms:
            raise AuthFailed(
                ErrorCode.AUTH_FAILED,
                f"unsupported alg: {alg!r}; allowed={self._algorithms}",
            )

        kid = header.get("kid")
        if not isinstance(kid, str):
            raise AuthFailed(ErrorCode.AUTH_FAILED, f"missing or non-string kid: {kid!r}")

        # Step 2: resolve ``kid`` against the cached JWKS. Critical: we
        # NEVER fetch ``kid`` as a URL even if it looks like one. The
        # only fetch happens via fetch_jwks() against the pinned URI.
        jwks = await self.fetch_jwks()
        key_by_kid = {k.get("kid"): k for k in jwks["keys"] if isinstance(k, dict)}
        jwk = key_by_kid.get(kid)
        if jwk is None:
            raise AuthFailed(
                ErrorCode.AUTH_FAILED,
                f"kid {kid!r} not in JWKS at {self._jwks_uri}",
            )

        try:
            key = jwt.PyJWK(jwk).key
        except jwt.PyJWTError as exc:
            raise AuthFailed(ErrorCode.AUTH_FAILED, f"unusable JWK: {exc}") from exc

        # Step 3: pyjwt-verify everything except audience (prefix-match
        # is our concern, not pyjwt's exact-match).
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=self._algorithms,
                issuer=self._issuer,
                leeway=self._clock_skew_s,
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthFailed(ErrorCode.AUTH_FAILED, "token expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthFailed(ErrorCode.AUTH_FAILED, f"invalid issuer: {exc}") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthFailed(ErrorCode.AUTH_FAILED, "invalid signature") from exc
        except jwt.PyJWTError as exc:
            raise AuthFailed(ErrorCode.AUTH_FAILED, f"jwt validation failed: {exc}") from exc

        # Step 4: validate audience prefix. The aud claim may be a
        # string or a list of strings (RFC 7519 allows both).
        identity = _extract_identity_from_aud(claims.get("aud"), self._audience_prefix)
        if identity is None:
            raise AuthFailed(
                ErrorCode.AUTH_FAILED,
                f"audience {claims.get('aud')!r} does not start with "
                f"{self._audience_prefix!r}",
            )

        return Identity(name=identity, claims=claims)

    async def authenticate(self, request: Request) -> Identity:
        """InboundAuthenticator: extract the bearer JWT and validate it.

        Surfaces the raw JWT as ``Identity.bearer_token`` so passthrough /
        as-agent fanout strategies can forward it upstream.
        """
        token = _extract_bearer(request)
        identity = await self.validate(token)
        return replace(identity, bearer_token=token)


# ---------------------------------------------------------------------------
# Non-OIDC authenticators (no IdP required)
# ---------------------------------------------------------------------------


class StaticTokenAuthenticator:
    """InboundAuthenticator: opaque bearer tokens mapped to identities.

    Zero-infra inbound auth — no IdP. Each identity has a high-entropy token
    (loaded from a file, never policy.yaml). The inbound
    ``Authorization: Bearer <token>`` is constant-time compared against every
    known token; an unknown token raises :class:`AuthFailed` (fail-closed).

    The token→identity map is built + validated (every identity must exist in
    policy) by :func:`mcp_hub.factory.build_inbound_auth`.
    """

    def __init__(self, *, token_to_identity: dict[str, str]) -> None:
        # (token, identity) pairs. Lookup compares against ALL of them with no
        # early return, so neither a token value nor the number of configured
        # tokens leaks via timing.
        self._pairs: list[tuple[str, str]] = list(token_to_identity.items())

    async def authenticate(self, request: Request) -> Identity:
        token = _extract_bearer(request)
        matched: str | None = None
        for known_token, identity in self._pairs:
            if secrets.compare_digest(token, known_token):
                matched = identity
        if matched is None:
            raise AuthFailed(ErrorCode.AUTH_FAILED, "unknown static token")
        return Identity(name=matched, claims={}, bearer_token=None)

    async def close(self) -> None:
        return None


class TrustedProxyAuthenticator:
    """InboundAuthenticator: trust an upstream auth proxy's identity header.

    For deployments fronted by oauth2-proxy / Authelia / Caddy ``forward_auth``:
    the proxy authenticates the user and injects ``identity_header``. To stop any
    client that can reach the hub from spoofing that header, the proxy MUST also
    send a shared-secret header (:attr:`SHARED_SECRET_HEADER`) matching the
    configured secret — constant-time compared. Network-isolating the hub to the
    proxy is recommended defense-in-depth. Fail-closed on any check.
    """

    # Header the proxy must set to the shared secret. Fixed name keeps config
    # minimal; the secret itself comes from a file.
    SHARED_SECRET_HEADER = "x-mcp-gateway-auth"  # noqa: S105 (header name, not a secret)

    def __init__(
        self,
        *,
        identity_header: str,
        shared_secret: str,
        valid_identities: frozenset[str],
    ) -> None:
        self._identity_header = identity_header.lower()
        self._shared_secret = shared_secret
        self._valid_identities = valid_identities

    async def authenticate(self, request: Request) -> Identity:
        presented = request.headers.get(self.SHARED_SECRET_HEADER, "")
        if not presented or not secrets.compare_digest(presented, self._shared_secret):
            raise AuthFailed(
                ErrorCode.AUTH_FAILED,
                "trusted-proxy shared secret missing or incorrect",
            )
        identity = request.headers.get(self._identity_header, "").strip()
        if not identity:
            raise AuthFailed(
                ErrorCode.AUTH_FAILED,
                f"trusted-proxy identity header {self._identity_header!r} missing",
            )
        if identity not in self._valid_identities:
            raise AuthFailed(
                ErrorCode.AUTH_FAILED,
                f"trusted-proxy identity {identity!r} is not a known identity",
            )
        return Identity(name=identity, claims={}, bearer_token=None)

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_identity_from_aud(aud: Any, prefix: str) -> str | None:
    """Return the identity suffix if any audience matches ``prefix``."""
    candidates: list[Any]
    if isinstance(aud, str):
        candidates = [aud]
    elif isinstance(aud, list):
        candidates = aud
    else:
        return None
    for c in candidates:
        if isinstance(c, str) and c.startswith(prefix):
            return c.removeprefix(prefix)
    return None


def b64url_uint(n: int) -> str:
    """Encode a non-negative int as base64url with no padding (JWK shape)."""
    byte_length = max((n.bit_length() + 7) // 8, 1)
    raw = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
