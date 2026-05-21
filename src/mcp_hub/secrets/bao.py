"""bao-backed SecretBackend.

Used at fanout boot time to resolve per-(mcp, identity) secrets:

1. JWT-login at bao to get an ephemeral token bound to the role
   ``role_template.format(mcp=..., identity=...)``. Default template is
   ``mcp-{mcp}-{identity}`` (e.g., ``mcp-technitium-ironclaw``).
2. KV v2 read at ``ref.path`` (relative to the configured mount).
3. Extract the requested ``ref.field`` from the secret's data.
4. Return as :class:`ResolvedSecret`.

The fanout calls this once per identity at boot. We intentionally
re-login per resolve (rather than caching tokens) because the operation
is rare (boot + restart) and tokens stay short-lived. There's nothing
to cache.

The path convention in policy YAML is **relative to the KV mount**::

    secrets:
      technitium:
        path: services/technitium/ironclaw    # NOT "secret/data/..."
        field: api_token

The ``secret/data/`` API prefix is added by :class:`BaoClient` based
on its ``kv_mount`` config (default ``secret``).
"""

from __future__ import annotations

from mcp_hub.bao_client import BaoClient, BaoError
from mcp_hub.interfaces import (
    ResolvedSecret,
    SecretRef,
    SecretResolutionError,
)

_DEFAULT_ROLE_TEMPLATE = "mcp-{mcp}-{identity}"


class BaoSecretBackend:
    """SecretBackend that resolves via a :class:`BaoClient`."""

    name: str = "bao"

    def __init__(
        self,
        *,
        bao_client: BaoClient,
        role_template: str = _DEFAULT_ROLE_TEMPLATE,
        auth_method: str = "jwt",
        static_token: str | None = None,
    ) -> None:
        if auth_method not in ("jwt", "token"):
            raise ValueError(
                f"bao auth_method must be 'jwt' or 'token', got {auth_method!r}"
            )
        if auth_method == "token" and not static_token:
            raise ValueError("bao auth_method='token' requires a static_token")
        self._bao = bao_client
        self._role_template = role_template
        self._auth_method = auth_method
        self._static_token = static_token

    async def resolve(
        self,
        *,
        mcp: str,
        identity: str,
        ref: SecretRef,
    ) -> ResolvedSecret:
        role = self._role_template.format(mcp=mcp, identity=identity)
        try:
            if self._auth_method == "token":
                assert self._static_token is not None  # guaranteed by __init__
                token = self._static_token
            else:
                token = await self._bao.jwt_login(role=role)
            data = await self._bao.kv_read(token=token, path=ref.path)
        except BaoError as exc:
            raise SecretResolutionError(
                f"bao resolve failed for role={role!r} path={ref.path!r}: {exc}"
            ) from exc

        if ref.field not in data:
            raise SecretResolutionError(
                f"bao secret at {ref.path!r} is missing field {ref.field!r}; "
                f"available fields: {sorted(data)}"
            )
        value = data[ref.field]
        if not isinstance(value, str):
            raise SecretResolutionError(
                f"bao secret {ref.path!r}.{ref.field!r} is not a string "
                f"(type={type(value).__name__})"
            )
        return ResolvedSecret(value=value)

    async def close(self) -> None:
        await self._bao.close()
