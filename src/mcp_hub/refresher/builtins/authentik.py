"""Authentik ``client_credentials`` :class:`TokenSource`.

Mints a fresh OAuth2 access token from Authentik's token endpoint
using the ``client_credentials`` grant. Reads the client secret from a
file path on each mint so the secret can be rotated underneath us
without a refresher restart (e.g., via docker-secret update).

Authentik's ``access_token_validity`` is per-provider, but bug
goauthentik/authentik#16621 (open through 2025.x) silently no-ops
PATCHes to that field — the default 15-minute lifetime is effectively
mandatory. This source exists to live with that bug: re-mint at 2/3 of
the validity window.

The minted token is a real RS256 JWT with standard OIDC claims (``iss``,
``aud``, ``sub``, ``exp``, ``jti``). bao's ``auth/jwt/login`` validates
it against Authentik's JWKS without further config.

Registered as the entry point ``authentik_client_credentials`` in
group ``mcp_hub.token_sources`` (see ``pyproject.toml``).
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


# Authentik's documented response shape (RFC 6749 §5.1):
#   {"access_token": "<jwt>", "token_type": "Bearer",
#    "expires_in": 900, "id_token": "<jwt>", "scope": "..."}
# We don't trust expires_in alone; the JWT's ``exp`` claim is what bao
# (or any other JWT validator) actually enforces. Decoding without
# verification is fine here — bao re-verifies on the receiving end and
# we'd rather schedule against the real expiry than a body field.


class AuthentikClientCredentialsSource:
    """Mint OAuth2 JWTs from Authentik via ``client_credentials``."""

    name = "authentik_client_credentials"

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
        # revoked secret); 5xx is transient (Authentik upstream issue).
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
            # Authentik issued an already-expired token. Means our clock
            # is wildly skewed, or Authentik is misconfigured. Either
            # way, bao will reject this immediately — fail loudly here
            # rather than write a useless token to disk.
            raise TokenMintError(
                f"access_token from {self._token_url} is already expired "
                f"(exp={expires_at.isoformat()}, now={datetime.now(UTC).isoformat()}); "
                f"check clock sync"
            )

        logger.info(
            "minted Authentik token via %s (client_id=%s, ttl=%.0fs, "
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


__all__ = ["AuthentikClientCredentialsSource"]
