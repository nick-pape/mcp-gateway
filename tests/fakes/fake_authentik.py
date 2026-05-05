"""In-memory Authentik mock.

Generates a fresh RSA keypair on instantiation; serves the public key
as a JWKS document via an :class:`httpx.MockTransport`; signs JWTs with
the private key. Tracks the number of times ``GET <jwks_uri>`` was hit
so tests can assert that a malicious JWT (e.g., ``kid`` pointing to an
attacker URL) does NOT trigger any extra fetches.

Usage::

    fake = FakeAuthentik(jwks_uri="https://auth.example/jwks/", issuer="...")
    client = httpx.AsyncClient(transport=fake.transport)
    validator = AuthentikJWTValidator(
        jwks_uri="https://auth.example/jwks/",
        issuer="...",
        audience_prefix="mcp-",
        http_client=client,
    )
    token = fake.issue(audience="mcp-ironclaw")
    identity = await validator.validate(token)
    assert fake.fetch_count == 1   # JWKS fetched once for verification
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_hub.auth import b64url_uint


class FakeAuthentik:
    """RSA-backed JWT issuer + JWKS server, all in-memory."""

    def __init__(
        self,
        *,
        jwks_uri: str,
        issuer: str,
        kid: str = "test-kid-1",
    ) -> None:
        self._jwks_uri = jwks_uri
        self._issuer = issuer
        self._kid = kid
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._fetch_count = 0
        # Build the JWKS once (the public key is fixed for this instance).
        self._jwks = self._build_jwks()
        # Pre-serialize the private key as PEM for pyjwt.
        self._pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def fetch_count(self) -> int:
        """Number of GET requests to the JWKS URI seen so far."""
        return self._fetch_count

    def reset_fetch_count(self) -> None:
        self._fetch_count = 0

    @property
    def transport(self) -> httpx.MockTransport:
        """An :class:`httpx.MockTransport` to inject into an AsyncClient."""
        return httpx.MockTransport(self._handler)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == self._jwks_uri and request.method == "GET":
            self._fetch_count += 1
            return httpx.Response(200, json=self._jwks)
        # Anything else: 404. If a test ever fetches an unexpected URL,
        # this surfaces as a clear error rather than a silent pass.
        return httpx.Response(404, text=f"unexpected {request.method} {request.url}")

    def _build_jwks(self) -> dict[str, Any]:
        public = self._private_key.public_key().public_numbers()
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "kid": self._kid,
            "alg": "RS256",
            "n": b64url_uint(public.n),
            "e": b64url_uint(public.e),
        }
        return {"keys": [jwk]}

    # -----------------------------------------------------------------------
    # JWT issuance
    # -----------------------------------------------------------------------

    def issue(
        self,
        *,
        audience: str | list[str],
        kid: str | None = None,
        issuer: str | None = None,
        exp_in_s: int = 3600,
        iat_offset_s: int = 0,
        algorithm: str = "RS256",
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Sign and return a JWT with the given claims.

        Defaults issue a happy-path token. Overrides let tests poison
        specific fields (wrong issuer, expired, custom kid pointing to
        a URL, etc.).
        """
        now = int(time.time()) + iat_offset_s
        payload: dict[str, Any] = {
            "iss": issuer if issuer is not None else self._issuer,
            "aud": audience,
            "iat": now,
            "exp": now + exp_in_s,
            "nbf": now,
        }
        if extra_claims:
            payload.update(extra_claims)
        headers = {"kid": kid if kid is not None else self._kid}
        token: str = jwt.encode(
            payload, self._pem, algorithm=algorithm, headers=headers
        )
        return token
