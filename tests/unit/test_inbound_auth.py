"""Tests for the non-OIDC inbound auth modes (#7).

Covers:
- StaticTokenAuthenticator (opaque bearer tokens -> identities)
- TrustedProxyAuthenticator (identity header gated by a shared secret)
- AuthConfig.mode schema validation (per-mode required + cross-mode rejection)
- build_inbound_auth dispatch (oidc / static_token / trusted_proxy)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from mcp_hub.auth import (
    AuthFailed,
    OidcJwtValidator,
    StaticTokenAuthenticator,
    TrustedProxyAuthenticator,
)
from mcp_hub.factory import build_inbound_auth
from mcp_hub.policy import AuthConfig


def _req(headers: dict[str, str]) -> Request:
    """A minimal Starlette request carrying the given headers."""
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "headers": raw})


# ---------------------------------------------------------------------------
# StaticTokenAuthenticator
# ---------------------------------------------------------------------------


async def test_static_token_resolves_identity() -> None:
    auth = StaticTokenAuthenticator(
        token_to_identity={"tok-abc": "alfred", "tok-xyz": "grocery"}
    )
    ident = await auth.authenticate(_req({"Authorization": "Bearer tok-xyz"}))
    assert ident.name == "grocery"
    # Static tokens are not forwardable upstream — no bearer surfaced.
    assert ident.bearer_token is None
    await auth.close()


async def test_static_token_unknown_token_raises() -> None:
    auth = StaticTokenAuthenticator(token_to_identity={"tok-abc": "alfred"})
    with pytest.raises(AuthFailed, match="unknown static token"):
        await auth.authenticate(_req({"Authorization": "Bearer not-a-token"}))


async def test_static_token_missing_bearer_raises() -> None:
    auth = StaticTokenAuthenticator(token_to_identity={"tok-abc": "alfred"})
    with pytest.raises(AuthFailed, match="missing bearer token"):
        await auth.authenticate(_req({}))


# ---------------------------------------------------------------------------
# TrustedProxyAuthenticator
# ---------------------------------------------------------------------------


def _proxy() -> TrustedProxyAuthenticator:
    return TrustedProxyAuthenticator(
        identity_header="X-Auth-Request-User",
        shared_secret="s3cr3t",
        valid_identities=frozenset({"alfred", "grocery"}),
    )


async def test_trusted_proxy_resolves_with_secret_and_known_identity() -> None:
    ident = await _proxy().authenticate(
        _req({"x-mcp-gateway-auth": "s3cr3t", "X-Auth-Request-User": "alfred"})
    )
    assert ident.name == "alfred"
    assert ident.bearer_token is None


async def test_trusted_proxy_missing_secret_raises() -> None:
    with pytest.raises(AuthFailed, match="shared secret"):
        await _proxy().authenticate(_req({"X-Auth-Request-User": "alfred"}))


async def test_trusted_proxy_wrong_secret_raises() -> None:
    with pytest.raises(AuthFailed, match="shared secret"):
        await _proxy().authenticate(
            _req({"x-mcp-gateway-auth": "WRONG", "X-Auth-Request-User": "alfred"})
        )


async def test_trusted_proxy_missing_identity_header_raises() -> None:
    with pytest.raises(AuthFailed, match="identity header"):
        await _proxy().authenticate(_req({"x-mcp-gateway-auth": "s3cr3t"}))


async def test_trusted_proxy_unknown_identity_raises() -> None:
    with pytest.raises(AuthFailed, match="not a known identity"):
        await _proxy().authenticate(
            _req({"x-mcp-gateway-auth": "s3cr3t", "X-Auth-Request-User": "stranger"})
        )


# ---------------------------------------------------------------------------
# AuthConfig.mode schema validation
# ---------------------------------------------------------------------------


def test_authconfig_defaults_to_oidc() -> None:
    cfg = AuthConfig(issuer="https://i/", jwks_uri="https://j/", audience_prefix="mcp-")
    assert cfg.mode == "oidc"


def test_authconfig_oidc_missing_fields_rejected() -> None:
    with pytest.raises(ValidationError, match="requires"):
        AuthConfig()


def test_authconfig_static_token_requires_token_file() -> None:
    with pytest.raises(ValidationError, match="requires"):
        AuthConfig(mode="static_token")
    AuthConfig(mode="static_token", token_file="/etc/mcp-gateway/tokens.yaml")  # ok


def test_authconfig_trusted_proxy_requires_header_and_secret() -> None:
    with pytest.raises(ValidationError, match="requires"):
        AuthConfig(mode="trusted_proxy", identity_header="X-User")  # no secret
    AuthConfig(
        mode="trusted_proxy", identity_header="X-User", shared_secret_file="/s"
    )  # ok


def test_authconfig_cross_mode_field_rejected() -> None:
    with pytest.raises(ValidationError, match="does not use"):
        AuthConfig(
            mode="static_token",
            token_file="/etc/mcp-gateway/tokens.yaml",
            issuer="https://leftover/",
        )


def test_authconfig_oidc_requires_identity_strategy() -> None:
    # issuer present but neither audience_prefix nor identity_claim.
    with pytest.raises(ValidationError, match="identity strategy"):
        AuthConfig(issuer="https://i/")


def test_authconfig_oidc_identity_claim_only_ok() -> None:
    # No jwks_uri (discovery), no audience_prefix, identity from a claim.
    cfg = AuthConfig(issuer="https://i/", identity_claim="sub")
    assert cfg.mode == "oidc"
    assert cfg.jwks_uri is None


def test_authconfig_identity_claim_is_oidc_only() -> None:
    with pytest.raises(ValidationError, match="does not use"):
        AuthConfig(mode="static_token", token_file="/x", identity_claim="sub")


# ---------------------------------------------------------------------------
# build_inbound_auth dispatch
# ---------------------------------------------------------------------------


async def test_build_inbound_auth_oidc() -> None:
    cfg = AuthConfig(issuer="https://i/", jwks_uri="https://j/", audience_prefix="mcp-")
    auth = build_inbound_auth(cfg, identities=frozenset({"alfred"}))
    assert isinstance(auth, OidcJwtValidator)
    await auth.close()


async def test_build_inbound_auth_oidc_identity_claim_discovery() -> None:
    # issuer-only + identity_claim: jwks_uri discovered lazily, identity from sub.
    cfg = AuthConfig(issuer="https://i/", identity_claim="sub")
    auth = build_inbound_auth(cfg, identities=frozenset({"alfred"}))
    assert isinstance(auth, OidcJwtValidator)
    await auth.close()


async def test_build_inbound_auth_static_token(tmp_path: Path) -> None:
    tokens = tmp_path / "tokens.yaml"
    tokens.write_text("alfred: tok-abc\ngrocery: tok-xyz\n")
    cfg = AuthConfig(mode="static_token", token_file=str(tokens))
    auth = build_inbound_auth(cfg, identities=frozenset({"alfred", "grocery"}))
    ident = await auth.authenticate(_req({"Authorization": "Bearer tok-xyz"}))
    assert ident.name == "grocery"
    await auth.close()


def test_build_inbound_auth_static_token_unknown_identity(tmp_path: Path) -> None:
    tokens = tmp_path / "tokens.yaml"
    tokens.write_text("stranger: tok-abc\n")
    cfg = AuthConfig(mode="static_token", token_file=str(tokens))
    with pytest.raises(ValueError, match="not defined in policy"):
        build_inbound_auth(cfg, identities=frozenset({"alfred"}))


def test_build_inbound_auth_static_token_empty_file(tmp_path: Path) -> None:
    tokens = tmp_path / "tokens.yaml"
    tokens.write_text("{}\n")
    cfg = AuthConfig(mode="static_token", token_file=str(tokens))
    with pytest.raises(ValueError, match="defines no tokens"):
        build_inbound_auth(cfg, identities=frozenset({"alfred"}))


async def test_build_inbound_auth_trusted_proxy(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("s3cr3t\n")
    cfg = AuthConfig(
        mode="trusted_proxy",
        identity_header="X-Auth-Request-User",
        shared_secret_file=str(secret),
    )
    auth = build_inbound_auth(cfg, identities=frozenset({"alfred"}))
    ident = await auth.authenticate(
        _req({"x-mcp-gateway-auth": "s3cr3t", "X-Auth-Request-User": "alfred"})
    )
    assert ident.name == "alfred"
    await auth.close()
