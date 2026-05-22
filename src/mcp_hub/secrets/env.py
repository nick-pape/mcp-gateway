"""Environment-variable SecretBackend (testing / dev only).

Reads secrets from process environment variables. Useful for unit tests
and local dev where bao is unavailable. Selected via:

.. code-block:: yaml

    secret_backend:
      name: env

The env var name is derived from ``mcp`` and ``identity``:
``<MCP>_<IDENTITY>`` uppercased, with non-alphanumeric characters
replaced by underscore. For example, ``mcp=technitium identity=ironclaw``
→ ``TECHNITIUM_IRONCLAW``.

The ``ref.field`` and ``ref.path`` are ignored (env-var namespace is flat).
This is **not** a production backend — production must use bao.
"""

from __future__ import annotations

import os
import re

from mcp_hub.interfaces import (
    ResolvedSecret,
    SecretRef,
    SecretResolutionError,
)

# Anything not [A-Z0-9] becomes underscore. Hyphens, dots, slashes, etc.
_ENV_VAR_SANITIZE = re.compile(r"[^A-Z0-9]+")


def env_var_name(mcp: str, identity: str) -> str:
    """Compute the env var name for a (mcp, identity) tuple."""
    raw = f"{mcp}_{identity}".upper()
    return _ENV_VAR_SANITIZE.sub("_", raw).strip("_")


class EnvSecretBackend:
    """SecretBackend that reads from the process environment."""

    name: str = "env"

    async def resolve(
        self,
        *,
        mcp: str,
        identity: str,
        ref: SecretRef,
        jwt: str | None = None,
    ) -> ResolvedSecret:
        # env backend has no per-caller auth; the as-agent ``jwt`` is ignored.
        del jwt
        env = env_var_name(mcp, identity)
        value = os.environ.get(env)
        if value is None:
            raise SecretResolutionError(
                f"env var {env!r} not set (looking up secret for "
                f"mcp={mcp!r} identity={identity!r})"
            )
        return ResolvedSecret(value=value)

    async def close(self) -> None:
        # No resources to release.
        return None
