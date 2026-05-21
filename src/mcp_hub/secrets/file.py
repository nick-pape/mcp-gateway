"""File-backed SecretBackend — the hub manages its own secrets locally.

No external secret store: secrets live in one JSON/YAML file the operator
manages. The natural pair with SOPS/age — point this at the decrypted file
(or one your deploy decrypts at boot). Selected via:

.. code-block:: yaml

    secret_backend:
      name: file
      config:
        path: /etc/mcp-gateway/secrets.yaml

File format — a mapping of secret ``path`` → ``{field: value}``, matching the
``path``/``field`` each identity's ``secrets:`` block references:

.. code-block:: yaml

    services/technitium/ironclaw:
      api_token: "tk_..."
    services/heb/grocery-agent:
      heb_email: "..."
      heb_password: "..."

Unlike the flat ``env`` backend this honors ``ref.path`` + ``ref.field``.
Loaded once at construction (fail-fast on a missing/malformed file). Keep the
file ``0400`` and root-owned.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_hub.interfaces import ResolvedSecret, SecretRef, SecretResolutionError


class FileSecretBackend:
    """SecretBackend that reads from a local JSON/YAML secrets file."""

    name: str = "file"

    def __init__(self, *, path: str | Path) -> None:
        self._path = Path(path)
        try:
            raw = self._path.read_text()
        except OSError as exc:
            raise SecretResolutionError(
                f"file backend: cannot read secrets file {self._path}: {exc}"
            ) from exc
        try:
            data: Any = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise SecretResolutionError(
                f"file backend: {self._path} is not valid YAML/JSON: {exc}"
            ) from exc
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise SecretResolutionError(
                f"file backend: {self._path} top-level must be a mapping of "
                f"path -> {{field: value}}; got {type(data).__name__}"
            )
        self._data: dict[str, Any] = data

    async def resolve(
        self,
        *,
        mcp: str,
        identity: str,
        ref: SecretRef,
    ) -> ResolvedSecret:
        entry = self._data.get(ref.path)
        if not isinstance(entry, dict) or ref.field not in entry:
            raise SecretResolutionError(
                f"file backend: no secret at path={ref.path!r} field={ref.field!r} "
                f"in {self._path} (mcp={mcp!r} identity={identity!r})"
            )
        return ResolvedSecret(value=str(entry[ref.field]))

    async def close(self) -> None:
        # Nothing to release — the file is read once at construction.
        return None
