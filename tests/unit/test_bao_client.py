"""Tests for BaoClient against the in-memory FakeBao."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from mcp_hub.bao_client import BaoClient, BaoError, compare_digest
from tests.fakes.fake_bao import FakeBao

BAO_ADDR = "https://bao.test"


@pytest.fixture
def jwt_file(tmp_path: Path) -> Path:
    p = tmp_path / "jwt"
    p.write_text("test-jwt")
    return p


@pytest.fixture
def fake() -> FakeBao:
    return FakeBao(
        expected_jwt="test-jwt",
        role_to_token={
            "mcp-technitium-ironclaw": "tok-technitium-ironclaw",
            "default-role": "tok-default",
        },
    )


@pytest.fixture
def client(fake: FakeBao, jwt_file: Path) -> BaoClient:
    return BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake.transport),
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_rejects_non_http_addr(jwt_file: Path) -> None:
    with pytest.raises(ValueError, match="addr must be http"):
        BaoClient(addr="ftp://nope", jwt_path=jwt_file)


# ---------------------------------------------------------------------------
# JWT login
# ---------------------------------------------------------------------------


async def test_jwt_login_returns_token(client: BaoClient, fake: FakeBao) -> None:
    token = await client.jwt_login(role="mcp-technitium-ironclaw")
    assert token == "tok-technitium-ironclaw"
    assert fake.login_count == 1
    await client.close()


async def test_jwt_login_unknown_role_raises(client: BaoClient) -> None:
    with pytest.raises(BaoError, match="returned 400"):
        await client.jwt_login(role="not-a-real-role")
    await client.close()


async def test_jwt_login_wrong_jwt_raises(jwt_file: Path, fake: FakeBao) -> None:
    """If the on-disk JWT doesn't match what bao expects (rotated?), 403s."""
    jwt_file.write_text("wrong-jwt")
    client = BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake.transport),
    )
    with pytest.raises(BaoError, match="returned 403"):
        await client.jwt_login(role="mcp-technitium-ironclaw")
    await client.close()


async def test_jwt_login_missing_file(tmp_path: Path, fake: FakeBao) -> None:
    client = BaoClient(
        addr=BAO_ADDR,
        jwt_path=tmp_path / "nope",
        http_client=httpx.AsyncClient(transport=fake.transport),
    )
    with pytest.raises(BaoError, match="cannot read JWT"):
        await client.jwt_login(role="default-role")
    await client.close()


async def test_jwt_login_empty_file(jwt_file: Path, fake: FakeBao) -> None:
    jwt_file.write_text("")
    client = BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake.transport),
    )
    with pytest.raises(BaoError, match="empty"):
        await client.jwt_login(role="default-role")
    await client.close()


async def test_jwt_login_reads_jwt_freshly_each_call(
    client: BaoClient, jwt_file: Path, fake: FakeBao
) -> None:
    """JWT rotation between calls is picked up without restart."""
    await client.jwt_login(role="default-role")
    # Rotate the JWT and the expected value on bao.
    jwt_file.write_text("rotated-jwt")
    fake._expected_jwt = "rotated-jwt"
    # Should still work after rotation.
    token = await client.jwt_login(role="default-role")
    assert token == "tok-default"
    await client.close()


# ---------------------------------------------------------------------------
# KV v2 read
# ---------------------------------------------------------------------------


async def test_kv_read_returns_data(client: BaoClient, fake: FakeBao) -> None:
    fake.seed("services/technitium/ironclaw", {"api_token": "secret-value"})
    token = await client.jwt_login(role="mcp-technitium-ironclaw")
    data = await client.kv_read(token=token, path="services/technitium/ironclaw")
    assert data == {"api_token": "secret-value"}
    await client.close()


async def test_kv_read_missing_path_raises(client: BaoClient) -> None:
    token = await client.jwt_login(role="default-role")
    with pytest.raises(BaoError, match="returned 404"):
        await client.kv_read(token=token, path="nope/notthere")
    await client.close()


async def test_kv_read_bad_token_raises(client: BaoClient) -> None:
    with pytest.raises(BaoError, match="returned 403"):
        await client.kv_read(token="bogus-token", path="services/x/y")
    await client.close()


# ---------------------------------------------------------------------------
# KV v2 write + TTL
# ---------------------------------------------------------------------------


async def test_kv_write_persists(client: BaoClient, fake: FakeBao) -> None:
    token = await client.jwt_login(role="default-role")
    await client.kv_write(token=token, path="hitl/pending/abc", data={"ack": "value"})
    assert fake.get_stored("hitl/pending/abc") == {"ack": "value"}
    await client.close()


async def test_kv_write_with_ttl_sets_metadata_first(
    client: BaoClient, fake: FakeBao
) -> None:
    """When ttl_s is set, BaoClient writes metadata BEFORE data."""
    token = await client.jwt_login(role="default-role")
    await client.kv_write(
        token=token, path="hitl/pending/xyz", data={"ack": "value"}, ttl_s=300
    )
    # After write, the entry exists in the store.
    assert fake.get_stored("hitl/pending/xyz") == {"ack": "value"}
    # And it has a TTL that future-expires.
    entry = fake._kv["hitl/pending/xyz"]
    assert entry["ttl_s"] == 300
    assert entry["expires_at"] is not None
    await client.close()


# ---------------------------------------------------------------------------
# KV v2 delete (idempotent)
# ---------------------------------------------------------------------------


async def test_kv_delete_removes_entry(client: BaoClient, fake: FakeBao) -> None:
    fake.seed("hitl/pending/abc", {"ack": "value"})
    token = await client.jwt_login(role="default-role")
    await client.kv_delete(token=token, path="hitl/pending/abc")
    assert fake.get_stored("hitl/pending/abc") is None
    await client.close()


async def test_kv_delete_missing_path_succeeds(client: BaoClient, fake: FakeBao) -> None:
    """Idempotent: deleting a non-existent path is a no-op (204)."""
    token = await client.jwt_login(role="default-role")
    await client.kv_delete(token=token, path="hitl/pending/never-existed")
    # No error; counter increments.
    assert fake.delete_count == 1
    await client.close()


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------


async def test_5xx_retried_then_succeeds(
    client: BaoClient, fake: FakeBao
) -> None:
    """Single 5xx hit is retried and the next attempt succeeds."""
    fake.seed("services/technitium/ironclaw", {"api_token": "x"})
    fake.fail_once(method="GET", path_contains="services/technitium/ironclaw")
    token = await client.jwt_login(role="mcp-technitium-ironclaw")
    data = await client.kv_read(token=token, path="services/technitium/ironclaw")
    assert data == {"api_token": "x"}
    await client.close()


async def test_4xx_not_retried(jwt_file: Path, fake: FakeBao) -> None:
    """4xx errors fail fast: no retry loop, no exponential backoff."""
    client = BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake.transport),
        retries=5,  # if it retried, it would do many login attempts
    )
    with pytest.raises(BaoError, match="returned 400"):
        await client.jwt_login(role="not-real")
    # login_count should be exactly 1 — no retries on 4xx.
    assert fake.login_count == 1
    await client.close()


async def test_persistent_5xx_exhausts_retries(
    jwt_file: Path, fake: FakeBao
) -> None:
    """Three consecutive 5xx hits exhaust retries and raise BaoError."""
    client = BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake.transport),
        retries=3,
        backoff_base_s=0.001,  # speed the test up
        backoff_cap_s=0.001,
    )
    fake.seed("x/y", {"a": "b"})
    # Inject 3 failures so all retries fail.
    for _ in range(3):
        fake.fail_once(method="GET", path_contains="x/y")
    token = await client.jwt_login(role="default-role")
    with pytest.raises(BaoError, match="exhausted"):
        await client.kv_read(token=token, path="x/y")
    await client.close()


# ---------------------------------------------------------------------------
# compare_digest helper
# ---------------------------------------------------------------------------


def test_compare_digest_equal_strings() -> None:
    assert compare_digest("abc123", "abc123") is True


def test_compare_digest_unequal_strings() -> None:
    assert compare_digest("abc123", "abc124") is False


def test_compare_digest_different_lengths() -> None:
    assert compare_digest("short", "much-longer-string") is False
