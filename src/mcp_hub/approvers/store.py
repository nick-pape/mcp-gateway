"""Transient key/value store for HITL pending state.

Push-based approvers (e.g. ntfy) stage a short-lived pending-approval record,
keyed by a per-request nonce, while they wait for the human to tap. This
abstracts that store so the approver isn't hardwired to a backend:

- :class:`InMemoryTransientStore` (default) — a dict with TTL expiry. Fine for a
  single-instance hub; the only thing it gives up vs. an external store is
  crash-safety across restarts (a hub restart drops in-flight approvals, which
  fail closed on timeout anyway).
- :class:`BaoTransientStore` — Vault/OpenBao KV with bao-side TTL, for HA /
  crash-safe deployments.

So HITL no longer requires Vault: with the in-memory store the whole hub runs
with zero external secret store.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from mcp_hub.bao_client import BaoClient, BaoError

logger = logging.getLogger(__name__)


class TransientStoreError(Exception):
    """A transient-store write failed (e.g. staging the pending entry)."""


@runtime_checkable
class TransientStore(Protocol):
    """TTL'd key -> mapping store for short-lived approval state."""

    async def put(self, key: str, value: Mapping[str, Any], *, ttl_s: int) -> None: ...
    async def get(self, key: str) -> dict[str, Any] | None: ...
    async def delete(self, key: str) -> None: ...
    async def close(self) -> None: ...


class InMemoryTransientStore:
    """Process-local store with TTL expiry. The default; no external dependency."""

    def __init__(self) -> None:
        self._d: dict[str, tuple[dict[str, Any], float]] = {}

    async def put(self, key: str, value: Mapping[str, Any], *, ttl_s: int) -> None:
        self._d[key] = (dict(value), time.monotonic() + ttl_s)

    async def get(self, key: str) -> dict[str, Any] | None:
        entry = self._d.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            self._d.pop(key, None)
            return None
        return dict(value)

    async def delete(self, key: str) -> None:
        self._d.pop(key, None)

    async def close(self) -> None:
        self._d.clear()


_DEFAULT_PATH_TEMPLATE = "hitl/pending/{key}"


class BaoTransientStore:
    """Vault/OpenBao KV-backed store with bao-side TTL (crash-safe)."""

    def __init__(
        self,
        *,
        bao_client: BaoClient,
        bao_role: str,
        path_template: str = _DEFAULT_PATH_TEMPLATE,
    ) -> None:
        self._bao = bao_client
        self._role = bao_role
        self._path_template = path_template

    def _path(self, key: str) -> str:
        # Accept both {key} (canonical) and {nonce} (legacy) placeholders.
        return self._path_template.format(key=key, nonce=key)

    async def put(self, key: str, value: Mapping[str, Any], *, ttl_s: int) -> None:
        try:
            token = await self._bao.jwt_login(role=self._role)
            await self._bao.kv_write(
                token=token, path=self._path(key), data=dict(value), ttl_s=ttl_s
            )
        except BaoError as exc:
            raise TransientStoreError(str(exc)) from exc

    async def get(self, key: str) -> dict[str, Any] | None:
        try:
            token = await self._bao.jwt_login(role=self._role)
            return await self._bao.kv_read(token=token, path=self._path(key))
        except BaoError:
            # Missing / expired / already-consumed → treat as absent.
            return None

    async def delete(self, key: str) -> None:
        try:
            token = await self._bao.jwt_login(role=self._role)
            await self._bao.kv_delete(token=token, path=self._path(key))
        except BaoError:
            logger.warning("BaoTransientStore: delete failed (bao TTL will evict)")

    async def close(self) -> None:
        await self._bao.close()
