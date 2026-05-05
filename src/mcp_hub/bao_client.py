"""Hand-rolled bao (OpenBao / Vault) client.

Shared primitive used by:

- :class:`mcp_hub.secrets.bao.BaoSecretBackend` (Phase 6b) — read-only
  KV v2 access for resolving per-identity service tokens at fanout
  boot, via JWT login each call.

- :class:`mcp_hub.approvers.ntfy.NtfyApprover` (Phase 7) — read/write/
  delete on a transient KV path for HITL ack tokens, with bao-side
  TTL as a crash-safety net.

We deliberately avoid ``hvac`` or other client libs: this surface is
small (~150 LoC), security-critical, and easier to audit by hand. Both
auth and KV operations follow the OpenBao API exactly:

- ``POST /v1/auth/jwt/login`` → ephemeral token
- ``GET /v1/<mount>/data/<path>`` → KV v2 read
- ``POST /v1/<mount>/data/<path>`` → KV v2 write
- ``POST /v1/<mount>/metadata/<path>`` → set ``delete_version_after`` (TTL)
- ``DELETE /v1/<mount>/metadata/<path>`` → destroy all versions

All operations include retry-with-exponential-backoff on transient
5xx / network errors. 4xx errors are NOT retried; they're config bugs.

The ``compare_digest`` helper at module bottom is re-exported so callers
have a single import point for constant-time string compares (used by
:class:`NtfyApprover` to validate ack tokens).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class BaoError(Exception):
    """Any failure interacting with bao.

    Wraps the underlying httpx error or a non-2xx response body so the
    caller can distinguish failure modes. Always treated as fatal at the
    boot path (per fanout eager-or-die); at request time, callers map
    to ``BACKEND_UNREACHABLE`` / ``INTERNAL_ERROR`` per audit semantics.
    """


# Default retry: try up to 3 times, exponential backoff starting at 250ms.
# Caps backoff at ~2s. Network glitches recover; persistent errors don't.
_DEFAULT_RETRIES = 3
_DEFAULT_BACKOFF_BASE_S = 0.25
_DEFAULT_BACKOFF_CAP_S = 2.0

# httpx default timeout is too generous for a homelab. 10s connect+read is
# more than bao normally needs.
_DEFAULT_TIMEOUT_S = 10.0


class BaoClient:
    """Lightweight async client for OpenBao auth + KV v2."""

    def __init__(
        self,
        *,
        addr: str,
        jwt_path: str | Path,
        kv_mount: str = "secret",
        http_client: httpx.AsyncClient | None = None,
        retries: int = _DEFAULT_RETRIES,
        backoff_base_s: float = _DEFAULT_BACKOFF_BASE_S,
        backoff_cap_s: float = _DEFAULT_BACKOFF_CAP_S,
    ) -> None:
        if not addr.startswith(("https://", "http://")):
            raise ValueError(f"addr must be http(s)://, got {addr!r}")
        # Normalize trailing slash so URL joins are consistent.
        self._addr = addr.rstrip("/")
        self._jwt_path = Path(jwt_path)
        self._kv_mount = kv_mount.strip("/")
        self._http = http_client or httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_S)
        self._owns_client = http_client is None
        self._retries = retries
        self._backoff_base_s = backoff_base_s
        self._backoff_cap_s = backoff_cap_s

    async def close(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    # -----------------------------------------------------------------------
    # Auth
    # -----------------------------------------------------------------------

    async def jwt_login(self, *, role: str) -> str:
        """Exchange the configured JWT for an ephemeral bao token.

        Reads the JWT fresh from disk on each call. This is intentional:
        the file may rotate; the cost (one read of a tiny file) is
        negligible compared to the HTTPS round-trip that follows.
        """
        try:
            jwt = self._jwt_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise BaoError(f"cannot read JWT at {self._jwt_path}: {exc}") from exc
        if not jwt:
            raise BaoError(f"JWT file at {self._jwt_path} is empty")

        body = await self._post(
            "auth/jwt/login",
            json={"role": role, "jwt": jwt},
            token=None,
        )
        token = body.get("auth", {}).get("client_token")
        if not isinstance(token, str) or not token:
            raise BaoError(f"JWT login response missing auth.client_token: {body!r}")
        return token

    # -----------------------------------------------------------------------
    # KV v2
    # -----------------------------------------------------------------------

    async def kv_read(self, *, token: str, path: str) -> dict[str, Any]:
        """Read the latest version of a KV v2 secret.

        Returns the inner ``data.data`` mapping (the application-level
        fields). Wrapper metadata is not surfaced.
        """
        path = path.lstrip("/")
        body = await self._get(f"{self._kv_mount}/data/{path}", token=token)
        data = body.get("data", {}).get("data")
        if not isinstance(data, dict):
            raise BaoError(f"KV read at {path!r}: response missing data.data ({body!r})")
        return data

    async def kv_write(
        self,
        *,
        token: str,
        path: str,
        data: dict[str, Any],
        ttl_s: int | None = None,
    ) -> None:
        """Write a KV v2 secret with optional TTL.

        When ``ttl_s`` is set, we configure ``delete_version_after`` on
        the secret's metadata FIRST so the data write inherits it.
        bao auto-deletes the version after ttl_s. This is the crash
        safety net for HITL pending state — even if the hub dies, bao
        cleans up.
        """
        path = path.lstrip("/")
        if ttl_s is not None:
            await self._post(
                f"{self._kv_mount}/metadata/{path}",
                json={"delete_version_after": f"{ttl_s}s"},
                token=token,
            )
        await self._post(
            f"{self._kv_mount}/data/{path}",
            json={"data": data},
            token=token,
        )

    async def kv_delete(self, *, token: str, path: str) -> None:
        """Permanently destroy all versions of a KV v2 secret.

        Idempotent: bao returns 204 whether the path existed or not.
        """
        path = path.lstrip("/")
        await self._delete(f"{self._kv_mount}/metadata/{path}", token=token)

    # -----------------------------------------------------------------------
    # HTTP helpers
    # -----------------------------------------------------------------------

    async def _get(self, path: str, *, token: str) -> dict[str, Any]:
        return await self._request("GET", path, token=token, json=None)

    async def _post(
        self, path: str, *, json: dict[str, Any] | None, token: str | None
    ) -> dict[str, Any]:
        return await self._request("POST", path, token=token, json=json)

    async def _delete(self, path: str, *, token: str) -> dict[str, Any]:
        return await self._request("DELETE", path, token=token, json=None)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None,
        json: dict[str, Any] | None,
    ) -> dict[str, Any]:
        url = f"{self._addr}/v1/{path.lstrip('/')}"
        headers: dict[str, str] = {}
        if token is not None:
            headers["X-Vault-Token"] = token

        last_exc: Exception | None = None
        for attempt in range(self._retries):
            if attempt > 0:
                # Exponential backoff with full jitter, capped.
                base = min(self._backoff_base_s * (2 ** (attempt - 1)), self._backoff_cap_s)
                # secrets.SystemRandom for non-bias even when small range.
                delay = secrets.SystemRandom().uniform(0, base)
                await asyncio.sleep(delay)

            try:
                response = await self._http.request(
                    method, url, headers=headers, json=json
                )
            except httpx.HTTPError as exc:
                last_exc = exc
                logger.warning("bao request failed (attempt %d): %s", attempt + 1, exc)
                continue

            # 4xx = config error, never retry. 5xx = transient, retry.
            if 500 <= response.status_code < 600:
                last_exc = BaoError(
                    f"bao {method} {path} returned {response.status_code}: "
                    f"{response.text[:200]}"
                )
                logger.warning("bao 5xx on attempt %d: %s", attempt + 1, last_exc)
                continue

            if not response.is_success:
                # 4xx — fail fast, do not retry.
                raise BaoError(
                    f"bao {method} {path} returned {response.status_code}: "
                    f"{response.text[:500]}"
                )

            # 2xx, 204 has no body.
            if response.status_code == 204 or not response.content:
                return {}
            try:
                parsed: dict[str, Any] = response.json()
                return parsed
            except ValueError as exc:
                raise BaoError(
                    f"bao {method} {path}: response not JSON ({exc})"
                ) from exc

        # All retries exhausted.
        if last_exc is not None:
            raise BaoError(
                f"bao {method} {path}: exhausted {self._retries} retries; "
                f"last error: {last_exc}"
            ) from last_exc
        raise BaoError(f"bao {method} {path}: exhausted retries")


# ---------------------------------------------------------------------------
# Constant-time compare helper (used by Phase 7 for ack tokens)
# ---------------------------------------------------------------------------


def compare_digest(a: str, b: str) -> bool:
    """Constant-time string equality.

    Wraps :func:`secrets.compare_digest` to give callers a single import
    point and to make it greppable that we're using a constant-time
    compare for ack-token validation.
    """
    return secrets.compare_digest(a, b)
