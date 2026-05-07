"""HEB-specific bootstrap.

Reads HEB_EMAIL and HEB_PASSWORD from env (orchestrator-injected from bao
via ContainerFanout's ``secrets_to_env`` mapping), persists them to
texas-grocery-mcp's CredentialStore, then exec's into the wrapper-image
base entrypoint that spawns the actual stdio MCP child.

Idempotent: rewriting the credentials on each spawn is fine — same input,
same output. Re-spawn after a bao rotation Just Works.

Why a bootstrap step rather than letting the MCP read env directly:
texas-grocery-mcp's auth path expects credentials saved via its
CredentialStore (keyring or Fernet-encrypted file fallback). It does not
read HEB_EMAIL/HEB_PASSWORD env vars. We bridge that gap once at
container start, then drop the env vars from our own process so the
spawned MCP child doesn't have them in its environment either.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Defer the import until after we've validated env, so a missing
# texas_grocery_mcp install fails with a clearer top-level error.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("heb-bootstrap")


def _required_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        log.error(
            "%s is unset; expected the orchestrator to inject it from bao", name
        )
        sys.exit(2)
    return val


def main() -> None:
    email = _required_env("HEB_EMAIL")
    password = _required_env("HEB_PASSWORD")

    # Where texas-grocery-mcp keeps state. Default ~/.texas-grocery-mcp.
    auth_dir_str = os.environ.get("HEB_AUTH_DIR", "~/.texas-grocery-mcp")
    auth_dir = Path(auth_dir_str).expanduser()
    auth_dir.mkdir(parents=True, exist_ok=True)

    from texas_grocery_mcp.auth.credentials import CredentialStore

    store = CredentialStore(auth_dir)
    result = store.save(email=email, password=password)
    method = result.get("method", "unknown") if isinstance(result, dict) else "unknown"
    log.info(
        "HEB credentials persisted via %s (auth_dir=%s)", method, auth_dir,
    )

    # Don't leave HEB_EMAIL/HEB_PASSWORD in the env we hand off to the
    # wrapper entrypoint + spawned stdio child. The MCP reads from
    # CredentialStore, not env; clearing them avoids accidental leakage if
    # any tool ever echoes os.environ back to a caller.
    os.environ.pop("HEB_EMAIL", None)
    os.environ.pop("HEB_PASSWORD", None)

    # Hand off to the wrapper entrypoint (lives at /app/entrypoint.py in
    # the image; the wrapper-image base copies it there). Use execvp so
    # we don't pile a dead Python process under it.
    os.execvp("python", ["python", "/app/entrypoint.py"])


if __name__ == "__main__":
    main()
