"""Env-driven config + docker-secret file reads."""

from __future__ import annotations

import os
from pathlib import Path


def _read_secret(env_var: str) -> str:
    path = os.environ.get(env_var)
    if not path:
        raise RuntimeError(f"env var {env_var} not set")
    p = Path(path)
    if not p.is_file():
        raise RuntimeError(f"secret file {p} does not exist")
    return p.read_text(encoding="utf-8").strip()


QDRANT_URL = os.environ["QDRANT_URL"].rstrip("/")
QDRANT_API_KEY = _read_secret("QDRANT_API_KEY_FILE")

EMBED_API_BASE = os.environ["EMBED_API_BASE"].rstrip("/")
EMBED_MODEL = os.environ["EMBED_MODEL"]

LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

# Default collection name (overridable per call via the search tool's
# `collection` argument). One org-wide collection; per-source filtering
# happens via payload `source` field, gated per-identity by the hub.
DEFAULT_COLLECTION = os.environ.get("DEFAULT_COLLECTION", "homelab")
