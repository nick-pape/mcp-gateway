"""Tests for AuthentikJWTValidator.

Covers all the security-critical findings from the adversary review:

- ``kid`` pointing to a URL must NOT trigger an outbound fetch
- ``iss`` (issuer) is validated
- Algorithm allowlist is enforced (no ``algorithms=None``)
- JWKS cold-start failure propagates
- JWKS warm-cache + fetch failure serves stale + logs
- Wrong audience prefix → AuthFailed
- Expired token → AuthFailed
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest

from mcp_hub.auth import (
    AuthentikJWTValidator,
    AuthFailed,
    _extract_identity_from_aud,
)
from mcp_hub.errors import ErrorCode
from tests.fakes.fake_authentik import FakeAuthentik

JWKS_URI = "https://auth.test/application/o/mcp-pape-house/jwks/"
ISSUER = "https://auth.test/application/o/mcp-pape-house/"
AUDIENCE_PREFIX = "mcp-"


@pytest.fixture
def fake() -> FakeAuthentik:
    return FakeAuthentik(jwks_uri=JWKS_URI, issuer=ISSUER)


@pytest.fixture
def validator(fake: FakeAuthentik) -> AuthentikJWTValidator:
    client = httpx.AsyncClient(transport=fake.transport)
    return AuthentikJWTValidator(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience_prefix=AUDIENCE_PREFIX,
        http_client=client,
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_validator_rejects_non_http_jwks_uri() -> None:
    with pytest.raises(ValueError, match="jwks_uri must be http"):
        AuthentikJWTValidator(
            jwks_uri="ftp://nope/",
            issuer=ISSUER,
            audience_prefix=AUDIENCE_PREFIX,
        )


def test_validator_rejects_empty_algorithms() -> None:
    with pytest.raises(ValueError, match="algorithms must be non-empty"):
        AuthentikJWTValidator(
            jwks_uri=JWKS_URI,
            issuer=ISSUER,
            audience_prefix=AUDIENCE_PREFIX,
            algorithms=[],
        )


# ---------------------------------------------------------------------------
# Audience extraction (pure helper)
# ---------------------------------------------------------------------------


def test_extract_identity_from_string_aud() -> None:
    assert _extract_identity_from_aud("mcp-ironclaw", "mcp-") == "ironclaw"


def test_extract_identity_from_list_aud_picks_matching() -> None:
    assert _extract_identity_from_aud(["other", "mcp-ironclaw"], "mcp-") == "ironclaw"


def test_extract_identity_returns_none_for_no_match() -> None:
    assert _extract_identity_from_aud("other-thing", "mcp-") is None
    assert _extract_identity_from_aud(["a", "b"], "mcp-") is None
    assert _extract_identity_from_aud(None, "mcp-") is None
    assert _extract_identity_from_aud(123, "mcp-") is None


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_validate_happy_path(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    token = fake.issue(audience="mcp-ironclaw")
    identity = await validator.validate(token)
    assert identity.name == "ironclaw"
    assert identity.claims["iss"] == ISSUER
    assert identity.claims["aud"] == "mcp-ironclaw"
    await validator.close()


async def test_validate_aud_as_list(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    token = fake.issue(audience=["other-aud", "mcp-paperless-bot"])
    identity = await validator.validate(token)
    assert identity.name == "paperless-bot"
    await validator.close()


async def test_jwks_fetched_only_once_within_ttl(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    """Subsequent validates within cache_ttl_s do not refetch."""
    fake.reset_fetch_count()
    token = fake.issue(audience="mcp-ironclaw")
    await validator.validate(token)
    await validator.validate(token)
    await validator.validate(token)
    assert fake.fetch_count == 1
    await validator.close()


# ---------------------------------------------------------------------------
# Security: kid resolution must be local
# ---------------------------------------------------------------------------


async def test_kid_pointing_to_url_is_NOT_fetched(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    """The CRITICAL test: a JWT with kid set to a URL must NOT cause
    the validator to fetch that URL or any URL beyond the pinned JWKS.
    """
    # Pre-warm the cache so a later fetch would be visible as +1.
    pre_token = fake.issue(audience="mcp-ironclaw")
    await validator.validate(pre_token)
    fetch_count_before = fake.fetch_count

    # Now an attacker JWT with kid set to a URL — pointing to the same
    # JWKS URI even, to maximize damage if fetched. Either way, the
    # validator must reject without any further fetch.
    attacker_token = fake.issue(
        audience="mcp-ironclaw",
        kid="https://attacker.example/jwks.json",
    )
    with pytest.raises(AuthFailed, match="not in JWKS"):
        await validator.validate(attacker_token)

    # Zero additional fetches: even though kid LOOKED like a URL, the
    # validator only consulted the cache. The fake handler 404s any
    # non-JWKS URL, so even an accidental fetch would have surfaced
    # already, but we double-assert via the counter.
    assert fake.fetch_count == fetch_count_before
    await validator.close()


# ---------------------------------------------------------------------------
# Security: issuer validation
# ---------------------------------------------------------------------------


async def test_wrong_issuer_rejected(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    token = fake.issue(audience="mcp-ironclaw", issuer="https://attacker.test/")
    with pytest.raises(AuthFailed, match="invalid issuer"):
        await validator.validate(token)
    await validator.close()


# ---------------------------------------------------------------------------
# Security: algorithm allowlist
# ---------------------------------------------------------------------------


async def test_default_algorithms_is_RS256_only(fake: FakeAuthentik) -> None:
    """Constructing with default algorithms accepts RS256 and only RS256."""
    client = httpx.AsyncClient(transport=fake.transport)
    validator = AuthentikJWTValidator(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience_prefix=AUDIENCE_PREFIX,
        http_client=client,
    )
    # Happy path with RS256 works:
    await validator.validate(fake.issue(audience="mcp-ironclaw"))
    await validator.close()


async def test_unsupported_algorithm_rejected(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    """A JWT with alg=HS256 must be rejected when only RS256 is allowed."""
    # Construct a header-poisoned JWT directly: encode with HS256.
    import jwt as pyjwt_lib

    token = pyjwt_lib.encode(
        {"iss": ISSUER, "aud": "mcp-ironclaw", "exp": 9999999999},
        "shared-secret",
        algorithm="HS256",
        headers={"kid": "test-kid-1"},
    )
    with pytest.raises(AuthFailed, match="unsupported alg"):
        await validator.validate(token)
    await validator.close()


# ---------------------------------------------------------------------------
# Audience prefix validation
# ---------------------------------------------------------------------------


async def test_wrong_audience_prefix_rejected(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    token = fake.issue(audience="other-prefix-ironclaw")
    with pytest.raises(AuthFailed, match="does not start with"):
        await validator.validate(token)
    await validator.close()


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


async def test_expired_token_rejected(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    # Issue a token whose exp is already in the past, beyond our skew.
    token = fake.issue(
        audience="mcp-ironclaw",
        iat_offset_s=-3700,  # iat 3700s ago
        exp_in_s=60,  # exp 60s after iat → still 3640s ago
    )
    with pytest.raises(AuthFailed, match="expired"):
        await validator.validate(token)
    await validator.close()


# ---------------------------------------------------------------------------
# Bad signature
# ---------------------------------------------------------------------------


async def test_bad_signature_rejected(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    token = fake.issue(audience="mcp-ironclaw")
    # Flip a byte in the signature (last segment after the second '.').
    head, payload, sig = token.rsplit(".", 2)
    tampered = f"{head}.{payload}.{sig[:-2]}AA"  # mutate last 2 chars
    with pytest.raises(AuthFailed):
        await validator.validate(tampered)
    await validator.close()


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


async def test_malformed_token_rejected(validator: AuthentikJWTValidator) -> None:
    with pytest.raises(AuthFailed, match="malformed"):
        await validator.validate("not-a-jwt")
    await validator.close()


# ---------------------------------------------------------------------------
# JWKS cache behavior
# ---------------------------------------------------------------------------


async def test_jwks_cold_start_failure_propagates(
    fake: FakeAuthentik,
) -> None:
    """If the very first JWKS fetch fails, validate must raise AuthFailed."""

    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Authentik is sad")

    client = httpx.AsyncClient(transport=httpx.MockTransport(failing_handler))
    validator = AuthentikJWTValidator(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience_prefix=AUDIENCE_PREFIX,
        http_client=client,
    )
    token = fake.issue(audience="mcp-ironclaw")
    with pytest.raises(AuthFailed, match="cold start"):
        await validator.validate(token)
    await validator.close()


async def test_jwks_warm_cache_serves_stale_on_failure(
    fake: FakeAuthentik,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """After a successful fetch, a later failure serves the cached JWKS."""
    # Build a transport that succeeds the first time and fails subsequent.
    state = {"calls": 0}

    def flaky_handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        if state["calls"] == 1:
            return httpx.Response(200, json=fake._jwks)
        return httpx.Response(503, text="downstream is sad")

    client = httpx.AsyncClient(transport=httpx.MockTransport(flaky_handler))
    validator = AuthentikJWTValidator(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience_prefix=AUDIENCE_PREFIX,
        cache_ttl_s=0,  # force re-fetch attempt on every call
        http_client=client,
    )

    token = fake.issue(audience="mcp-ironclaw")
    # First call: warms the cache (transport returns 200).
    await validator.validate(token)
    # Second call: cache is stale (TTL=0), so we attempt fetch, which 503s.
    # We expect serve-stale-on-warm-fail: validate succeeds, log fires.
    with caplog.at_level(logging.WARNING, logger="mcp_hub.auth"):
        await validator.validate(token)
    assert any("jwks_serving_stale" in r.message for r in caplog.records)
    await validator.close()


async def test_jwks_response_missing_keys_field_rejected(fake: FakeAuthentik) -> None:
    def malformed_jwks_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not_keys_at_all": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(malformed_jwks_handler))
    validator = AuthentikJWTValidator(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience_prefix=AUDIENCE_PREFIX,
        http_client=client,
    )
    token = fake.issue(audience="mcp-ironclaw")
    with pytest.raises(AuthFailed, match="missing 'keys'"):
        await validator.validate(token)
    await validator.close()


# ---------------------------------------------------------------------------
# Error code wiring
# ---------------------------------------------------------------------------


async def test_authfailed_carries_error_code(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    """All AuthFailed instances carry the AUTH_FAILED ErrorCode for audit."""
    token = fake.issue(audience="other-prefix-ironclaw")
    with pytest.raises(AuthFailed) as exc_info:
        await validator.validate(token)
    assert exc_info.value.code == ErrorCode.AUTH_FAILED
    await validator.close()


# ---------------------------------------------------------------------------
# Audience claim weirdness
# ---------------------------------------------------------------------------


async def test_no_audience_claim_rejected(
    fake: FakeAuthentik, validator: AuthentikJWTValidator
) -> None:
    """A JWT issued without aud cannot match any prefix and must fail."""
    import jwt as pyjwt_lib

    # Issue a token bypassing FakeAuthentik's defaults so we can omit aud.
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "iat": 1000,
        "exp": 99999999999,
    }
    token = pyjwt_lib.encode(
        payload,
        fake._pem,
        algorithm="RS256",
        headers={"kid": "test-kid-1"},
    )
    with pytest.raises(AuthFailed, match="does not start with"):
        await validator.validate(token)
    await validator.close()
