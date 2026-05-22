"""Tests for the HITL TransientStore implementations."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from mcp_hub.approvers.store import (
    BaoTransientStore,
    InMemoryTransientStore,
    TransientStore,
)
from mcp_hub.bao_client import BaoClient
from tests.fakes.fake_bao import FakeBao

BAO_ADDR = "https://bao.test"


async def test_in_memory_put_get_delete() -> None:
    store = InMemoryTransientStore()
    assert isinstance(store, TransientStore)
    await store.put("k", {"ack_token": "x"}, ttl_s=60)
    assert await store.get("k") == {"ack_token": "x"}
    await store.delete("k")
    assert await store.get("k") is None
    await store.close()


async def test_in_memory_get_missing_returns_none() -> None:
    store = InMemoryTransientStore()
    assert await store.get("nope") is None


async def test_in_memory_ttl_expiry() -> None:
    store = InMemoryTransientStore()
    await store.put("k", {"a": "1"}, ttl_s=0)  # expires immediately
    await asyncio.sleep(0.01)
    assert await store.get("k") is None


async def test_bao_store_roundtrip(tmp_path: Path) -> None:
    jwt = tmp_path / "jwt"
    jwt.write_text("test-jwt")
    fake = FakeBao(expected_jwt="test-jwt", role_to_token={"mcp-hitl": "tok"})
    bao = BaoClient(
        addr=BAO_ADDR, jwt_path=jwt, http_client=httpx.AsyncClient(transport=fake.transport)
    )
    store = BaoTransientStore(bao_client=bao, bao_role="mcp-hitl")
    assert isinstance(store, TransientStore)

    await store.put("nonce1", {"ack_token": "secret"}, ttl_s=300)
    got = await store.get("nonce1")
    assert got is not None and got["ack_token"] == "secret"

    await store.delete("nonce1")
    assert await store.get("nonce1") is None  # missing -> None, not an error
    await store.close()
