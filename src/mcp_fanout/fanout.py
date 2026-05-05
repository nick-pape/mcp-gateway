"""The Fanout — multi-identity stdio MCP multiplexer.

Each :class:`Fanout` instance manages **N stdio children** for one
backend MCP type (e.g., ``technitium``), one per registered identity.
Identities are wired in at construction; the Fanout resolves each
identity's secret via the supplied :class:`SecretBackend`, writes it to
a per-identity token file, and spawns the stdio child with the file path
in a configured env variable.

Eager-or-die: any failure during boot — secret resolution, file write,
process spawn — aborts the whole stack. This is design choice 2 in the
plan: live token rotation is out of scope for v1; restart to recover.

This module is the future :pypi:`mcp-fanout` standalone package; it has
no dependencies on the rest of the hub except via the ``SecretBackend``
Protocol it consumes.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_hub.interfaces import SecretBackend, SecretRef, SecretResolutionError

from .child import ChildProcess
from .exceptions import (
    BackendChildDead,
    ChildSpawnFailed,
    FanoutError,
    IdentityNotFound,
)
from .uid_alloc import spawn_command, uid_separation_supported

logger = logging.getLogger(__name__)


# Default cap: 4 MiB per single tool response. Larger than any reasonable
# MCP response, smaller than something that would balloon hub RSS.
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class IdentityConfig:
    """Per-identity wiring for one Fanout instance.

    - ``identity`` — the agent name; matches a key in the hub's policy
    - ``uid`` — distinct UID to ``gosu`` into when spawning this child
      (Linux+root only; ignored on dev hosts)
    - ``ref`` — passed to the SecretBackend to look up the secret
    - ``secret_env_name`` — env var the child reads to find its secret
      file (e.g., ``TECHNITIUM_TOKEN_FILE``)
    """

    identity: str
    uid: int
    ref: SecretRef
    secret_env_name: str


class Fanout:
    """Multi-identity stdio MCP multiplexer for one backend MCP.

    Usage::

        fanout = Fanout(
            mcp_name="technitium",
            command=["node", "/app/mcps/technitium/dist/index.js"],
            identities=[
                IdentityConfig("ironclaw", 1001, ref, "TECHNITIUM_TOKEN_FILE"),
                IdentityConfig("claude-code-dev", 1003, ref, "TECHNITIUM_TOKEN_FILE"),
            ],
            secret_backend=BaoSecretBackend(...),
            runtime_dir=Path("/run"),
        )
        await fanout.start_eager_or_die()
        result = await fanout.call(identity="ironclaw", request={...})
        await fanout.close()
    """

    def __init__(
        self,
        *,
        mcp_name: str,
        command: Sequence[str],
        identities: Sequence[IdentityConfig],
        secret_backend: SecretBackend,
        runtime_dir: Path,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        if not identities:
            raise ValueError(f"Fanout({mcp_name!r}) needs at least one identity")
        # Disjointness check on identities — duplicate names would lose calls.
        names = [i.identity for i in identities]
        if len(set(names)) != len(names):
            raise ValueError(
                f"Fanout({mcp_name!r}) has duplicate identities: {sorted(names)}"
            )
        self._mcp_name = mcp_name
        self._command = list(command)
        self._identities = {i.identity: i for i in identities}
        self._secret_backend = secret_backend
        self._runtime_dir = runtime_dir
        self._max_response_bytes = max_response_bytes
        self._extra_env = dict(extra_env or {})
        self._children: dict[str, ChildProcess] = {}
        self._token_files: list[Path] = []

    @property
    def mcp_name(self) -> str:
        return self._mcp_name

    @property
    def identities(self) -> tuple[str, ...]:
        return tuple(self._identities)

    async def start_eager_or_die(self) -> None:
        """Resolve every identity's secret and spawn its child, or fail.

        On any failure, partial state is cleaned up before the exception
        propagates.
        """
        if not uid_separation_supported():
            logger.warning(
                "Fanout(%s): UID separation NOT supported on this host. "
                "Children will share UID; /proc/environ leak between siblings is possible. "
                "Production deploys MUST be Linux+root with gosu.",
                self._mcp_name,
            )
        try:
            for cfg in self._identities.values():
                await self._spawn(cfg)
        except Exception:
            # Best-effort cleanup of partial state, then re-raise.
            await self.close()
            raise

    async def _spawn(self, cfg: IdentityConfig) -> None:
        # 1. Resolve the secret.
        try:
            resolved = await self._secret_backend.resolve(
                mcp=self._mcp_name, identity=cfg.identity, ref=cfg.ref
            )
        except SecretResolutionError as exc:
            raise ChildSpawnFailed(
                f"Fanout({self._mcp_name}): secret resolution failed for "
                f"identity={cfg.identity!r}: {exc}"
            ) from exc

        # 2. Write the per-identity token file atomically (mode 0400, owned
        #    by cfg.uid on Linux).
        token_path = self._runtime_dir / f"{cfg.identity}-{self._mcp_name}-token"
        _write_secret_file(token_path, resolved.value, cfg.uid)
        self._token_files.append(token_path)

        # 3. Spawn the child via gosu (or no-op on dev hosts).
        # PATH is inherited so the child can resolve "gosu" + any tools
        # the MCP shells out to. Other parent env vars are NOT inherited:
        # the child must declare what it needs explicitly via extra_env.
        parent_path = os.environ.get(
            "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )
        env = {
            "PATH": parent_path,
            **self._extra_env,
            cfg.secret_env_name: str(token_path),
        }
        argv = spawn_command(self._command, cfg.uid)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                # Inherit stderr so child diagnostics land in our logs.
                # Capturing here would risk filling the pipe buffer if
                # the child is chatty and we never read; inherited
                # stderr is the simplest correct behavior. Production
                # MCPs that prefix stderr with [audit]/[warning] etc.
                # show up directly in `docker logs`.
                stderr=None,
                env=env,
            )
        except OSError as exc:
            raise ChildSpawnFailed(
                f"Fanout({self._mcp_name}): failed to spawn child for "
                f"identity={cfg.identity!r}: {exc}"
            ) from exc

        child = ChildProcess(
            process=process,
            identity=cfg.identity,
            max_response_bytes=self._max_response_bytes,
        )

        # 4. MCP initialization handshake. Required by spec before any
        #    tools/list or tools/call can succeed. Most production MCP
        #    servers (TS SDK, Python SDK) hard-require it; without it
        #    they read the request and close stdout.
        try:
            init_response = await child.send(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "clientInfo": {
                            "name": "mcp-fanout",
                            "version": "0.0.0",
                        },
                    },
                }
            )
            if "error" in init_response:
                raise ChildSpawnFailed(
                    f"Fanout({self._mcp_name}): initialize failed for "
                    f"identity={cfg.identity!r}: {init_response['error']}"
                )
            await child.send_notification(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
        except BackendChildDead as exc:
            raise ChildSpawnFailed(
                f"Fanout({self._mcp_name}): initialize handshake failed for "
                f"identity={cfg.identity!r}: {exc}"
            ) from exc

        self._children[cfg.identity] = child

    async def call(self, *, identity: str, request: dict[str, Any]) -> dict[str, Any]:
        """Forward a JSON-RPC request to the child for ``identity``.

        Raises :class:`IdentityNotFound` if the identity wasn't registered,
        :class:`BackendChildDead` if the child has died or misbehaves.
        """
        child = self._children.get(identity)
        if child is None:
            raise IdentityNotFound(
                f"Fanout({self._mcp_name}): unknown identity {identity!r}; "
                f"registered: {sorted(self._children)}"
            )
        return await child.send(request)

    async def close(self) -> None:
        """Terminate all children and remove all token files. Idempotent."""
        for child in list(self._children.values()):
            with suppress(BackendChildDead):
                await child.close()
        self._children.clear()
        for path in self._token_files:
            _safe_unlink(path)
        self._token_files.clear()
        with suppress(Exception):
            await self._secret_backend.close()


def _safe_unlink(path: Path) -> None:
    """Unlink a file, handling Windows ``FILE_ATTRIBUTE_READONLY``.

    Idempotent (no-op if absent).

    On POSIX, mode 0o400 doesn't block unlink (deletion needs parent-dir
    write). On Windows, the read-only attribute blocks ``DeleteFile`` —
    so we drop it (chmod 0o600) and retry once.
    """
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except PermissionError:
        with suppress(Exception):
            path.chmod(0o600)
        with suppress(FileNotFoundError):
            path.unlink()


def _write_secret_file(path: Path, value: str, uid: int) -> None:
    """Atomically write ``value`` to ``path`` with restrictive perms.

    On Linux: write mode 0o600, then ``chmod 0o400`` + ``chown uid``. The
    brief 0o600-owned-by-hub-UID window is acceptable because only the
    hub itself has access in that window (no third-party code in the
    container).

    On non-Linux dev (Windows): mode 0o600 is the floor; we can't do UID
    separation anyway. UID separation is the production security
    property — see ``architecture.md`` for the threat model.

    Uses ``os.open(O_CREAT | O_EXCL | O_WRONLY)`` so the file is never
    observable in a half-written state.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Remove any stale file from a prior run; O_EXCL would otherwise fail.
    _safe_unlink(path)

    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, value.encode("utf-8"))
    finally:
        os.close(fd)

    # Tighten on Linux+root only — that's the configuration where the
    # gosu'd child runs as a distinct UID and needs the secret restricted
    # via mode 0400 + chown. Without uid separation (dev hosts), the
    # child inherits the writer's UID and can read mode 0600 anyway.
    #
    # Errors here are FATAL: if uid separation is supposed to be on but
    # chown fails (CAP_CHOWN missing), the gosu'd child won't be able to
    # read its token. Failing loud surfaces the missing capability.
    if uid_separation_supported():
        try:
            os.chmod(str(path), 0o400)
            os.chown(str(path), uid, uid)
        except (PermissionError, OSError) as exc:
            raise FanoutError(
                f"failed to set 0400 + chown {uid}:{uid} on {path}: {exc}; "
                f"this usually means the container is missing CAP_CHOWN"
            ) from exc
