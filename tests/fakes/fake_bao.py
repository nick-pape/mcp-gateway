"""In-memory bao mock for tests.

Implements just enough of the OpenBao API surface that
:class:`mcp_hub.bao_client.BaoClient` exercises:

- ``POST /v1/auth/jwt/login`` — accepts a configured JWT, returns a fake token
- ``GET /v1/secret/data/<path>`` — read KV v2
- ``POST /v1/secret/data/<path>`` — write KV v2
- ``POST /v1/secret/metadata/<path>`` — set ``delete_version_after``
- ``DELETE /v1/secret/metadata/<path>`` — destroy
- Configurable failure injection: 5xx for retry tests, JWT-mismatch
  rejection, etc.

Usage::

    fake = FakeBao(expected_jwt="abc", role_to_token={"mcp-technitium-ironclaw": "ephemeral-token"})
    client = httpx.AsyncClient(transport=fake.transport)
    bao = BaoClient(addr="https://bao.test", jwt_path=tmp/jwt.txt, http_client=client)
"""

from __future__ import annotations

import json as _json
import time
from typing import Any

import httpx


class FakeBao:
    """Minimal OpenBao stand-in usable as an httpx MockTransport handler."""

    def __init__(
        self,
        *,
        expected_jwt: str = "test-jwt",
        role_to_token: dict[str, str] | None = None,
        addr: str = "https://bao.test",
    ) -> None:
        self._addr = addr.rstrip("/")
        self._expected_jwt = expected_jwt
        self._role_to_token: dict[str, str] = role_to_token or {"default-role": "default-token"}
        # In-memory KV store: path -> {"data": {...}, "ttl": int|None, "expires_at": float|None}
        self._kv: dict[str, dict[str, Any]] = {}
        # Token validation: which tokens we recognize.
        self._valid_tokens: set[str] = set(self._role_to_token.values())
        # Failure injection: list of (method, path) tuples to 5xx once each.
        self._fail_once_5xx: list[tuple[str, str]] = []
        # Counters.
        self.login_count: int = 0
        self.read_count: int = 0
        self.write_count: int = 0
        self.delete_count: int = 0

    # -----------------------------------------------------------------------
    # Test helpers
    # -----------------------------------------------------------------------

    def seed(self, path: str, data: dict[str, Any]) -> None:
        """Pre-populate KV v2 storage at ``path``."""
        self._kv[path.lstrip("/")] = {"data": data, "ttl_s": None, "expires_at": None}

    def fail_once(self, *, method: str, path_contains: str) -> None:
        """Cause the next matching request to return 503."""
        self._fail_once_5xx.append((method.upper(), path_contains))

    def get_stored(self, path: str) -> dict[str, Any] | None:
        entry = self._kv.get(path.lstrip("/"))
        if entry is None:
            return None
        # Honor TTL: if expired, treat as missing.
        if entry["expires_at"] is not None and time.time() > entry["expires_at"]:
            return None
        return entry["data"]

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)

    # -----------------------------------------------------------------------
    # Handler
    # -----------------------------------------------------------------------

    def _handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")
        method = request.method

        # Failure injection: serve 503 once for matching requests.
        for entry in list(self._fail_once_5xx):
            method_match, path_contains = entry
            if method == method_match and path_contains in path:
                self._fail_once_5xx.remove(entry)
                return httpx.Response(503, text="injected failure")

        # auth/jwt/login
        if path == "auth/jwt/login" and method == "POST":
            return self._handle_jwt_login(request)

        # KV v2: secret/data/<path>
        if path.startswith("secret/data/"):
            kv_path = path.removeprefix("secret/data/")
            if not self._authn(request):
                return httpx.Response(403, text="permission denied")
            if method == "GET":
                return self._handle_kv_read(kv_path)
            if method == "POST":
                return self._handle_kv_write(kv_path, request)

        # KV v2 metadata: secret/metadata/<path>
        if path.startswith("secret/metadata/"):
            meta_path = path.removeprefix("secret/metadata/")
            if not self._authn(request):
                return httpx.Response(403, text="permission denied")
            if method == "POST":
                return self._handle_metadata_write(meta_path, request)
            if method == "DELETE":
                return self._handle_metadata_delete(meta_path)

        return httpx.Response(404, text=f"unhandled {method} {path}")

    def _authn(self, request: httpx.Request) -> bool:
        token = request.headers.get("X-Vault-Token")
        return token is not None and token in self._valid_tokens

    def _handle_jwt_login(self, request: httpx.Request) -> httpx.Response:
        self.login_count += 1
        body = _parse_json(request)
        role = body.get("role")
        jwt = body.get("jwt")
        if jwt != self._expected_jwt:
            return httpx.Response(403, json={"errors": ["invalid jwt"]})
        if role not in self._role_to_token:
            return httpx.Response(400, json={"errors": [f"unknown role {role!r}"]})
        token = self._role_to_token[role]
        self._valid_tokens.add(token)
        return httpx.Response(
            200,
            json={
                "auth": {
                    "client_token": token,
                    "lease_duration": 3600,
                    "renewable": False,
                },
            },
        )

    def _handle_kv_read(self, kv_path: str) -> httpx.Response:
        self.read_count += 1
        entry = self._kv.get(kv_path)
        if entry is None:
            return httpx.Response(404, json={"errors": []})
        if entry["expires_at"] is not None and time.time() > entry["expires_at"]:
            return httpx.Response(404, json={"errors": []})
        return httpx.Response(
            200,
            json={"data": {"data": entry["data"], "metadata": {"version": 1}}},
        )

    def _handle_kv_write(self, kv_path: str, request: httpx.Request) -> httpx.Response:
        self.write_count += 1
        body = _parse_json(request)
        data = body.get("data", {})
        # Inherit any TTL set via prior metadata write.
        existing = self._kv.get(kv_path, {})
        ttl_s = existing.get("ttl_s")
        expires_at = existing.get("expires_at")
        self._kv[kv_path] = {
            "data": data,
            "ttl_s": ttl_s,
            "expires_at": expires_at if expires_at is not None else (
                time.time() + ttl_s if ttl_s is not None else None
            ),
        }
        return httpx.Response(200, json={"data": {"version": 1}})

    def _handle_metadata_write(self, kv_path: str, request: httpx.Request) -> httpx.Response:
        body = _parse_json(request)
        ttl = body.get("delete_version_after")
        ttl_s: int | None = None
        if isinstance(ttl, str) and ttl.endswith("s"):
            ttl_s = int(ttl.removesuffix("s"))
        existing = self._kv.get(kv_path, {})
        self._kv[kv_path] = {
            "data": existing.get("data"),
            "ttl_s": ttl_s,
            "expires_at": time.time() + ttl_s if ttl_s is not None else None,
        }
        return httpx.Response(204)

    def _handle_metadata_delete(self, kv_path: str) -> httpx.Response:
        self.delete_count += 1
        self._kv.pop(kv_path, None)
        return httpx.Response(204)


def _parse_json(request: httpx.Request) -> dict[str, Any]:
    if not request.content:
        return {}
    try:
        result = _json.loads(request.content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    if isinstance(result, dict):
        return result
    return {}
