"""Tests for BaoSecretBackend (Phase 6b)."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from mcp_hub.bao_client import BaoClient
from mcp_hub.interfaces import SecretBackend, SecretRef, SecretResolutionError
from mcp_hub.secrets.bao import BaoSecretBackend
from tests.fakes.fake_bao import FakeBao

BAO_ADDR = "https://bao.test"


@pytest.fixture
def jwt_file(tmp_path: Path) -> Path:
    p = tmp_path / "fanout_jwt"
    p.write_text("test-jwt")
    return p


@pytest.fixture
def fake() -> FakeBao:
    return FakeBao(
        expected_jwt="test-jwt",
        role_to_token={
            "mcp-technitium-ironclaw": "tok-tech-iron",
            "mcp-technitium-paperless-bot": "tok-tech-paper",
        },
    )


@pytest.fixture
def backend(fake: FakeBao, jwt_file: Path) -> BaoSecretBackend:
    bao = BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake.transport),
    )
    return BaoSecretBackend(bao_client=bao)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_bao_backend_satisfies_secret_backend_protocol(
    backend: BaoSecretBackend,
) -> None:
    assert isinstance(backend, SecretBackend)
    assert backend.name == "bao"


async def test_token_auth_uses_static_token_no_login() -> None:
    """auth_method='token' resolves with a static Vault token (no jwt_login)."""
    fake = FakeBao(role_to_token={"unused": "static-tok"})
    fake.seed("services/x/y", {"api_token": "secret-value"})
    bao = BaoClient(
        addr=BAO_ADDR, http_client=httpx.AsyncClient(transport=fake.transport)
    )
    backend = BaoSecretBackend(
        bao_client=bao, auth_method="token", static_token="static-tok"
    )
    got = await backend.resolve(
        mcp="x", identity="y", ref=SecretRef(path="services/x/y", field="api_token")
    )
    assert got.value == "secret-value"
    assert fake.login_count == 0  # token mode does not jwt-login
    await backend.close()


def test_token_auth_requires_static_token() -> None:
    bao = BaoClient(
        addr=BAO_ADDR, http_client=httpx.AsyncClient(transport=FakeBao().transport)
    )
    with pytest.raises(ValueError, match="static_token"):
        BaoSecretBackend(bao_client=bao, auth_method="token")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_resolve_happy_path(
    backend: BaoSecretBackend, fake: FakeBao
) -> None:
    fake.seed("services/technitium/ironclaw", {"api_token": "real-secret"})
    ref = SecretRef(path="services/technitium/ironclaw", field="api_token")
    resolved = await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref)
    assert resolved.value == "real-secret"
    await backend.close()


async def test_resolve_uses_correct_role_per_identity(
    backend: BaoSecretBackend, fake: FakeBao
) -> None:
    """Distinct (mcp, identity) tuples produce distinct bao roles + tokens."""
    fake.seed("services/technitium/ironclaw", {"api_token": "iron-secret"})
    fake.seed("services/technitium/paperless-bot", {"api_token": "paper-secret"})

    ref_iron = SecretRef(path="services/technitium/ironclaw", field="api_token")
    ref_paper = SecretRef(path="services/technitium/paperless-bot", field="api_token")

    iron = await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref_iron)
    paper = await backend.resolve(
        mcp="technitium", identity="paperless-bot", ref=ref_paper
    )
    assert iron.value == "iron-secret"
    assert paper.value == "paper-secret"
    # Two distinct logins, two distinct tokens issued by bao.
    assert fake.login_count == 2
    await backend.close()


# ---------------------------------------------------------------------------
# Error mapping (BaoError -> SecretResolutionError)
# ---------------------------------------------------------------------------


async def test_unknown_role_maps_to_secret_resolution_error(
    backend: BaoSecretBackend,
) -> None:
    """An identity whose role doesn't exist in bao -> SecretResolutionError."""
    ref = SecretRef(path="services/x/y", field="api_token")
    with pytest.raises(SecretResolutionError, match="returned 400"):
        await backend.resolve(mcp="technitium", identity="unknown-agent", ref=ref)
    await backend.close()


async def test_missing_field_in_secret(
    backend: BaoSecretBackend, fake: FakeBao
) -> None:
    """The secret exists but lacks the requested field."""
    fake.seed("services/technitium/ironclaw", {"different_field": "value"})
    ref = SecretRef(path="services/technitium/ironclaw", field="api_token")
    with pytest.raises(SecretResolutionError, match="missing field 'api_token'"):
        await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref)
    await backend.close()


async def test_field_value_not_string(
    backend: BaoSecretBackend, fake: FakeBao
) -> None:
    """A non-string field value (e.g., dict) is rejected — won't fit a token file."""
    fake.seed("services/technitium/ironclaw", {"api_token": {"nested": "obj"}})
    ref = SecretRef(path="services/technitium/ironclaw", field="api_token")
    with pytest.raises(SecretResolutionError, match="not a string"):
        await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref)
    await backend.close()


async def test_missing_path_maps_to_secret_resolution_error(
    backend: BaoSecretBackend,
) -> None:
    """A 404 from bao surfaces as SecretResolutionError."""
    ref = SecretRef(path="services/technitium/ironclaw", field="api_token")
    with pytest.raises(SecretResolutionError, match="returned 404"):
        await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref)
    await backend.close()


# ---------------------------------------------------------------------------
# Custom role template
# ---------------------------------------------------------------------------


async def test_custom_role_template(jwt_file: Path) -> None:
    """A non-default role template formats correctly."""
    fake = FakeBao(
        expected_jwt="test-jwt",
        role_to_token={"custom-technitium-ironclaw": "tok-x"},
    )
    bao = BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake.transport),
    )
    backend = BaoSecretBackend(
        bao_client=bao, role_template="custom-{mcp}-{identity}"
    )
    fake.seed("services/x", {"api_token": "v"})
    ref = SecretRef(path="services/x", field="api_token")
    resolved = await backend.resolve(mcp="technitium", identity="ironclaw", ref=ref)
    assert resolved.value == "v"
    await backend.close()
