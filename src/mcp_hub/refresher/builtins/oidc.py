"""OIDC ``client_credentials`` :class:`TokenSource`.

Mints a fresh OAuth2 access token from an OIDC provider's token endpoint using
the RFC 6749 ``client_credentials`` grant — works with any standards-compliant
IdP (Authentik, Keycloak, Auth0, Zitadel, ...). Reads the client secret from a
file path on each mint so the secret can be rotated underneath us without a
refresher restart (e.g. via docker-secret update).

The minted ``access_token`` is expected to be a JWT; its ``exp`` claim drives the
re-mint schedule (the orchestrator re-mints before expiry). Short token
lifetimes are common — e.g. Authentik's ``access_token_validity`` is effectively
pinned to ~15 min by bug goauthentik/authentik#16621 — so the refresher exists
to keep a fresh token on disk regardless of how short the window is.

Downstream validators (e.g. OpenBao's ``auth/jwt/login``) verify the token
against the IdP's JWKS; this source does not verify signatures itself.

Registered under both ``oidc_client_credentials`` (canonical) and
``authentik_client_credentials`` (back-compat alias) in group
``mcp_hub.token_sources`` (see ``pyproject.toml``).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import jwt

from ..protocols import Token, TokenMintError

logger = logging.getLogger(__name__)


# RFC 6749 §5.1 token response shape:
#   {"access_token": "<jwt>", "token_type": "Bearer",
#    "expires_in": 900, "id_token": "<jwt>", "scope": "..."}
# We don't trust expires_in alone; the JWT's ``exp`` claim is what the
# downstream validator actually enforces. Decoding without verification is fine
# here — the receiver re-verifies — and we'd rather schedule against the real
# expiry than a body field.


class OidcClientCredentialsSource:
    """Mint OAuth2 JWTs from an OIDC token endpoint via ``client_credentials``."""

    name = "oidc_client_credentials"

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret_path: Path | str,
        scope: str | None = None,
        timeout_s: float = 10.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret_path = Path(client_secret_path)
        self._scope = scope
        self._timeout_s = timeout_s
        # If caller supplied a client, don't close it on our close() —
        # they own its lifecycle. Otherwise we own the one we make.
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout_s)

    async def mint(self) -> Token:
        # Read secret fresh each time so docker-secret rotation works
        # without restarting the refresher.
        try:
            client_secret = self._client_secret_path.read_text(
                encoding="utf-8"
            ).strip()
        except FileNotFoundError as exc:
            # Not transient — config is wrong, retry won't help.
            raise TokenMintError(
                f"client_secret_path {self._client_secret_path} does not exist",
                transient=False,
            ) from exc
        except OSError as exc:
            raise TokenMintError(
                f"failed to read client_secret_path {self._client_secret_path}: {exc}"
            ) from exc

        if not client_secret:
            raise TokenMintError(
                f"client_secret_path {self._client_secret_path} is empty",
                transient=False,
            )

        form: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": client_secret,
        }
        if self._scope:
            form["scope"] = self._scope

        try:
            resp = await self._http.post(self._token_url, data=form)
        except httpx.HTTPError as exc:
            raise TokenMintError(
                f"POST {self._token_url} failed: {exc}"
            ) from exc

        # 4xx is generally not transient (auth misconfig, wrong client_id,
        # revoked secret); 5xx is transient (upstream IdP issue).
        if resp.status_code >= 500:
            raise TokenMintError(
                f"POST {self._token_url} returned {resp.status_code}: "
                f"{resp.text[:300]}"
            )
        if resp.status_code >= 400:
            raise TokenMintError(
                f"POST {self._token_url} returned {resp.status_code}: "
                f"{resp.text[:300]}",
                transient=False,
            )

        try:
            body: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise TokenMintError(
                f"POST {self._token_url} returned non-JSON body: "
                f"{resp.text[:300]}"
            ) from exc

        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise TokenMintError(
                f"POST {self._token_url} response missing access_token; "
                f"got keys: {sorted(body)}",
                transient=False,
            )

        # Decode without signature verification — the JWT's exp is what
        # downstream validators (bao) will enforce. We just need it to
        # schedule the next mint correctly.
        try:
            claims = jwt.decode(
                access_token,
                options={"verify_signature": False, "verify_exp": False},
            )
        except jwt.PyJWTError as exc:
            raise TokenMintError(
                f"access_token from {self._token_url} is not a valid JWT: {exc}",
                transient=False,
            ) from exc

        exp = claims.get("exp")
        if not isinstance(exp, (int, float)):
            raise TokenMintError(
                f"access_token from {self._token_url} has no numeric exp claim; "
                f"got claims: {sorted(claims)}",
                transient=False,
            )

        expires_at = datetime.fromtimestamp(exp, tz=UTC)
        ttl = expires_at - datetime.now(UTC)
        if ttl.total_seconds() <= 0:
            # The IdP issued an already-expired token — clock skew or a
            # misconfigured provider. The downstream validator will reject it
            # immediately, so fail loudly here rather than write a useless
            # token to disk.
            raise TokenMintError(
                f"access_token from {self._token_url} is already expired "
                f"(exp={expires_at.isoformat()}, now={datetime.now(UTC).isoformat()}); "
                f"check clock sync"
            )

        logger.info(
            "minted client-credentials token via %s (client_id=%s, ttl=%.0fs, "
            "exp=%s)",
            self._token_url,
            self._client_id,
            ttl.total_seconds(),
            expires_at.isoformat(),
        )
        return Token(value=access_token, expires_at=expires_at)

    async def close(self) -> None:
        if self._owns_client:
            await self._http.aclose()


__all__ = ["OidcClientCredentialsSource"]
