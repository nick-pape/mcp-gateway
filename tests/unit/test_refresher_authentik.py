"""Tests for AuthentikClientCredentialsSource."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import httpx
import jwt
import pytest

from mcp_hub.refresher import TokenMintError
from mcp_hub.refresher.builtins.authentik import AuthentikClientCredentialsSource

TOKEN_URL = "https://auth.example/application/o/token/"
CLIENT_ID = "mcp-fanout-svc"


def _make_jwt(*, exp_in_s: int = 900) -> str:
    """Hand-roll an unsigned JWT with the required claims.

    The source decodes without signature verification (it doesn't have
    Authentik's public key — bao does the real verification). So an
    HS256 with a known secret is fine; we just need valid structure.
    """
    payload = {
        "iss": "https://auth.example/",
        "aud": "mcp-fanout-svc",
        "sub": "mcp-fanout-svc",
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_in_s,
    }
    return jwt.encode(payload, "secret", algorithm="HS256")


@pytest.fixture
def secret_path(tmp_path: Path) -> Path:
    p = tmp_path / "client_secret"
    p.write_text("supersecret\n")  # trailing newline to test stripping
    return p


def _transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _source(secret_path: Path, transport: httpx.MockTransport) -> AuthentikClientCredentialsSource:
    return AuthentikClientCredentialsSource(
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret_path=secret_path,
        scope="openid mcp-fanout-svc",
        http_client=httpx.AsyncClient(transport=transport),
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_mint_returns_token_with_decoded_exp(secret_path: Path) -> None:
    captured: dict[str, str] = {}
    test_jwt = _make_jwt(exp_in_s=900)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == TOKEN_URL
        # urlencoded form
        captured.update(dict(httpx.QueryParams(request.content.decode())))
        return httpx.Response(200, json={"access_token": test_jwt, "token_type": "Bearer", "expires_in": 900})

    src = _source(secret_path, _transport(handler))
    try:
        token = await src.mint()
    finally:
        await src.close()

    assert token.value == test_jwt
    # exp should be ~900s in the future
    ttl = token.time_to_expiry().total_seconds()
    assert 800 < ttl <= 900
    # form had the right fields, including stripped secret
    assert captured["grant_type"] == "client_credentials"
    assert captured["client_id"] == CLIENT_ID
    assert captured["client_secret"] == "supersecret"
    assert captured["scope"] == "openid mcp-fanout-svc"


async def test_mint_omits_scope_when_unset(secret_path: Path) -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(dict(httpx.QueryParams(request.content.decode())))
        return httpx.Response(200, json={"access_token": _make_jwt(), "token_type": "Bearer"})

    src = AuthentikClientCredentialsSource(
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret_path=secret_path,
        scope=None,
        http_client=httpx.AsyncClient(transport=_transport(handler)),
    )
    try:
        await src.mint()
    finally:
        await src.close()
    assert "scope" not in captured


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


async def test_4xx_is_non_transient(secret_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    src = _source(secret_path, _transport(handler))
    try:
        with pytest.raises(TokenMintError) as ei:
            await src.mint()
    finally:
        await src.close()
    assert ei.value.transient is False


async def test_5xx_is_transient(secret_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    src = _source(secret_path, _transport(handler))
    try:
        with pytest.raises(TokenMintError) as ei:
            await src.mint()
    finally:
        await src.close()
    assert ei.value.transient is True


async def test_network_error_is_transient(secret_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    src = _source(secret_path, _transport(handler))
    try:
        with pytest.raises(TokenMintError) as ei:
            await src.mint()
    finally:
        await src.close()
    assert ei.value.transient is True


async def test_missing_access_token_field(secret_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    src = _source(secret_path, _transport(handler))
    try:
        with pytest.raises(TokenMintError, match="missing access_token"):
            await src.mint()
    finally:
        await src.close()


async def test_non_jwt_access_token(secret_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": "not-a-jwt"})

    src = _source(secret_path, _transport(handler))
    try:
        with pytest.raises(TokenMintError, match="not a valid JWT"):
            await src.mint()
    finally:
        await src.close()


async def test_jwt_without_exp_claim(secret_path: Path) -> None:
    bad = jwt.encode({"iss": "x"}, "secret", algorithm="HS256")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": bad})

    src = _source(secret_path, _transport(handler))
    try:
        with pytest.raises(TokenMintError, match="no numeric exp"):
            await src.mint()
    finally:
        await src.close()


async def test_already_expired_token_rejected(secret_path: Path) -> None:
    expired = _make_jwt(exp_in_s=-60)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": expired})

    src = _source(secret_path, _transport(handler))
    try:
        with pytest.raises(TokenMintError, match="already expired"):
            await src.mint()
    finally:
        await src.close()


async def test_missing_secret_file_non_transient(tmp_path: Path) -> None:
    src = AuthentikClientCredentialsSource(
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret_path=tmp_path / "nope",
        scope=None,
        http_client=httpx.AsyncClient(transport=_transport(lambda _: httpx.Response(200))),
    )
    try:
        with pytest.raises(TokenMintError, match="does not exist") as ei:
            await src.mint()
    finally:
        await src.close()
    assert ei.value.transient is False


async def test_empty_secret_file_non_transient(tmp_path: Path) -> None:
    p = tmp_path / "empty"
    p.write_text("")
    src = AuthentikClientCredentialsSource(
        token_url=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret_path=p,
        scope=None,
        http_client=httpx.AsyncClient(transport=_transport(lambda _: httpx.Response(200))),
    )
    try:
        with pytest.raises(TokenMintError, match="is empty") as ei:
            await src.mint()
    finally:
        await src.close()
    assert ei.value.transient is False


async def test_secret_re_read_each_mint(secret_path: Path) -> None:
    """Rotation underneath should be picked up without restart."""
    secrets_seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode()))
        secrets_seen.append(form["client_secret"])
        return httpx.Response(200, json={"access_token": _make_jwt()})

    src = _source(secret_path, _transport(handler))
    try:
        await src.mint()
        # Rotate the secret on disk, mid-life.
        secret_path.write_text("rotated\n")
        await src.mint()
    finally:
        await src.close()

    assert secrets_seen == ["supersecret", "rotated"]
