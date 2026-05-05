#!/usr/bin/env python3
"""Idempotent bao bootstrap for mcp.pape.house.

Reads ``policy.yaml`` and configures bao:

1. Enables the JWT auth method (idempotent — no-op if already enabled)
2. Configures it against the Authentik OIDC discovery URL from policy
3. Creates one **policy** per ``(mcp, identity)`` granting read on the
   identity's secret path
4. Creates one **JWT role** per ``(mcp, identity)`` bound to the
   ``mcp-fanout-svc`` subject and the new policy
5. If ``approver.name == ntfy``, creates an HITL policy + role granting
   read/write/delete on ``hitl/pending/*`` (the transient KV the
   NtfyApprover uses for ack-token storage)

Re-run is safe — bao's KV/policy/role endpoints are upsert.

Usage::

    BAO_ADDR=https://secrets.pape.house \\
    BAO_TOKEN=<admin-token> \\
    uv run python scripts/bootstrap_bao.py /etc/mcp-pape-house/policy.yaml

The admin token must have policy + auth-method capabilities. This is
explicitly a one-time / occasional bootstrap; do not bake the admin
token into the container or anywhere it could be reused.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import yaml


HITL_POLICY_NAME = "mcp-hitl"
HITL_ROLE_NAME = "mcp-hitl"
FANOUT_SUBJECT = "mcp-fanout-svc"
FANOUT_AUDIENCE = "mcp-fanout-svc"
DEFAULT_TOKEN_TTL = "1h"


# ---------------------------------------------------------------------------
# bao primitives — just thin wrappers around the HTTP API
# ---------------------------------------------------------------------------


def _post(client: httpx.Client, path: str, body: dict[str, Any] | None = None) -> httpx.Response:
    return client.post(path, json=body or {})


def _put(client: httpx.Client, path: str, body: dict[str, Any] | None = None) -> httpx.Response:
    return client.put(path, json=body or {})


def ensure_jwt_auth_enabled(client: httpx.Client) -> None:
    """Mount the JWT auth method at /jwt; no-op if already mounted."""
    r = _post(client, "/v1/sys/auth/jwt", {"type": "jwt"})
    if r.status_code == 400 and "path is already in use" in r.text:
        print("  jwt auth method already enabled")
        return
    r.raise_for_status()
    print("  jwt auth method enabled")


def configure_jwt_auth(
    client: httpx.Client,
    *,
    issuer: str,
    jwks_uri: str,
    oidc_discovery_url: str | None,
) -> None:
    """Point bao's JWT auth method at Authentik.

    Authentik with ``issuer_mode=global`` publishes the same ``iss``
    claim across all providers (e.g., ``https://auth.pape.house/``) but
    discovery is still per-application. So we configure bao with:

    - ``oidc_discovery_url`` (per-app) — if given; bao uses this to
      auto-discover the JWKS URL. The discovery doc returns the global
      issuer string, and bao binds JWTs to that.
    - ``jwks_url`` — fallback when no discovery URL is provided; bao
      validates against this directly. ``bound_issuer`` ensures JWTs
      with a matching ``iss`` claim are accepted.
    """
    if oidc_discovery_url:
        body = {"oidc_discovery_url": oidc_discovery_url.rstrip("/")}
    else:
        body = {"jwks_url": jwks_uri, "bound_issuer": issuer}
    r = _post(client, "/v1/auth/jwt/config", body)
    r.raise_for_status()
    print(f"  jwt auth configured (issuer={issuer})")


def upsert_policy(client: httpx.Client, name: str, hcl: str) -> None:
    """Create or replace a bao policy by name."""
    r = _put(client, f"/v1/sys/policies/acl/{name}", {"policy": hcl})
    r.raise_for_status()
    print(f"  policy upserted: {name}")


def upsert_jwt_role(
    client: httpx.Client,
    name: str,
    *,
    policies: list[str],
    bound_subject: str = FANOUT_SUBJECT,
    bound_audiences: list[str] | None = None,
    ttl: str = DEFAULT_TOKEN_TTL,
) -> None:
    """Create or replace a JWT role by name."""
    body = {
        "role_type": "jwt",
        "user_claim": "sub",
        "bound_subject": bound_subject,
        "bound_audiences": bound_audiences or [FANOUT_AUDIENCE],
        "policies": policies,
        "token_ttl": ttl,
        "token_max_ttl": ttl,
    }
    r = _post(client, f"/v1/auth/jwt/role/{name}", body)
    r.raise_for_status()
    print(f"  jwt role upserted: {name}")


# ---------------------------------------------------------------------------
# Policy doc generators
# ---------------------------------------------------------------------------


def secret_read_policy(secret_path: str) -> str:
    """Read-only on a single KV v2 path."""
    # KV v2 reads use the "secret/data/<path>" prefix; metadata is separate.
    return f'''
path "secret/data/{secret_path.lstrip("/")}" {{
  capabilities = ["read"]
}}
'''.strip()


def hitl_transient_policy() -> str:
    """Read/write/delete on hitl/pending/* (used by NtfyApprover)."""
    return '''
path "secret/data/hitl/pending/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/hitl/pending/*" {
  capabilities = ["create", "read", "update", "delete"]
}
'''.strip()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def bootstrap(policy_path: Path, addr: str, token: str) -> int:
    raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        print(f"FATAL: {policy_path} top-level must be a mapping", file=sys.stderr)
        return 1

    headers = {"X-Vault-Token": token}
    with httpx.Client(base_url=addr.rstrip("/"), headers=headers, timeout=10.0) as c:
        print(f"== bao @ {addr} ==")

        print("[1] JWT auth method")
        ensure_jwt_auth_enabled(c)
        configure_jwt_auth(
            c,
            issuer=raw["auth"]["issuer"],
            jwks_uri=raw["auth"]["jwks_uri"],
            oidc_discovery_url=raw["auth"].get("oidc_discovery_url"),
        )

        print("[2] Per-(mcp, identity) policies + roles")
        identities: dict[str, Any] = raw.get("identities", {})
        for identity_name, identity in identities.items():
            for mcp_name, secret in identity.get("secrets", {}).items():
                role_name = f"mcp-{mcp_name}-{identity_name}"
                upsert_policy(c, role_name, secret_read_policy(secret["path"]))
                upsert_jwt_role(c, role_name, policies=[role_name])

        print("[3] HITL transient store")
        if raw.get("approver", {}).get("name") == "ntfy":
            upsert_policy(c, HITL_POLICY_NAME, hitl_transient_policy())
            upsert_jwt_role(c, HITL_ROLE_NAME, policies=[HITL_POLICY_NAME])
        else:
            print("  approver != ntfy; skipping HITL policy/role")

    print()
    print("bootstrap complete. Verify with:")
    print(f"  bao read auth/jwt/config")
    print(f"  bao list sys/policies/acl")
    print(f"  bao list auth/jwt/role")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: bootstrap_bao.py <path/to/policy.yaml>", file=sys.stderr)
        return 1
    policy_path = Path(sys.argv[1])
    if not policy_path.is_file():
        print(f"FATAL: {policy_path} does not exist", file=sys.stderr)
        return 1

    addr = os.environ.get("BAO_ADDR", "").strip()
    token = os.environ.get("BAO_TOKEN", "").strip()
    if not addr:
        print("FATAL: BAO_ADDR not set", file=sys.stderr)
        return 1
    if not token:
        print("FATAL: BAO_TOKEN not set", file=sys.stderr)
        return 1

    try:
        return bootstrap(policy_path, addr, token)
    except httpx.HTTPStatusError as exc:
        print(
            f"FATAL: bao API returned {exc.response.status_code} for "
            f"{exc.request.method} {exc.request.url}: {exc.response.text[:500]}",
            file=sys.stderr,
        )
        return 2
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        print(f"FATAL: bao API call failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
