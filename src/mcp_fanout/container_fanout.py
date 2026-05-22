"""On-demand container orchestrator for stdio MCPs wrapped as HTTPS+JWT.

Mirrors the external interface of :class:`HttpFanout` (and the stdio
:class:`Fanout`) so the rest of the hub can treat all three uniformly via
the ``FanoutLike`` union in ``server.py``.

Internally:

- Holds a per-(mcp x identity) registry of running wrapper containers.
- On the first :meth:`call` for an identity, lazily spawns a container
  via the configured Docker remote API (a local or remote Docker host).
- Per-spawn env injection — including bao-resolved secrets — happens
  once at container start. Tokens never hit disk inside the container;
  they live only in process memory of the spawned wrapper + its child.
- Forwards each :meth:`call` to the spawned container's ``/mcp`` over
  HTTP, attaching auth headers from the configured strategy
  (typically :class:`mcp_hub.auth_strategies.JwtPassthrough`).
- A periodic background loop evicts containers that have been idle past
  ``idle_timeout_s``. In-flight calls are refcount-protected against
  eviction (``in_flight`` per handle).

Scope handling:

- ``scope = "per-identity"`` (default) — one container per identity. The
  registry key is the identity string.
- ``scope = "shared"`` — one container regardless of caller. The registry
  key is a fixed sentinel.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx

# docker-py is sync; we wrap calls in asyncio.to_thread.
try:  # pragma: no cover - import path validated at runtime
    import docker
    import docker.errors
    from docker.models.containers import Container
except ImportError as _import_exc:  # pragma: no cover
    docker = None
    Container = Any
    _DOCKER_IMPORT_ERROR: ImportError | None = _import_exc
else:
    _DOCKER_IMPORT_ERROR = None

from mcp_hub.auth_strategies import AuthStrategy
from mcp_hub.interfaces import SecretBackend, SecretRef, SecretResolutionError

from .exceptions import HttpUpstreamFailed, IdentityNotFound

logger = logging.getLogger(__name__)


# --- Defaults --------------------------------------------------------------

DEFAULT_IDLE_TIMEOUT_S: float = 1200.0       # 20 min
DEFAULT_SPAWN_TIMEOUT_S: float = 60.0
DEFAULT_REQUEST_TIMEOUT_S: float = 180.0  # tolerates HEB Playwright self-heal (~30-60s sweep)
DEFAULT_EVICTION_INTERVAL_S: float = 60.0
DEFAULT_CONTAINER_PORT: int = 8080
DEFAULT_AUDIENCE_TEMPLATE: str = "mcp-{identity}"
SHARED_KEY: str = "__shared__"


# --- Volume mount spec ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class VolumeMountSpec:
    """One Docker named-volume mount for a spawned container.

    ``volume_name_template`` may contain ``{identity}``; the orchestrator
    formats it at spawn time. Volumes are auto-created by Docker on first
    mount; the orchestrator does NOT remove them on container teardown,
    so session state persists across spawn/evict cycles.

    Used only by MCPs that legitimately need persistent state beyond an
    env-injected token (e.g. HEB's Playwright cookies + auth.json). Most
    MCPs leave this empty.
    """

    container_path: str
    volume_name_template: str


# --- ContainerHandle -------------------------------------------------------


class _ContainerHandle:
    """Runtime state for one spawned container.

    ``in_flight`` is incremented before each upstream POST and decremented
    after; the eviction loop skips handles with ``in_flight > 0``. This
    avoids racing eviction against an in-progress tool call.
    """

    __slots__ = ("container", "host", "in_flight", "last_active", "port", "started_at")

    def __init__(self, *, container: Container, port: int, host: str) -> None:
        self.container = container
        self.port = port
        self.host = host
        now = time.monotonic()
        self.started_at: float = now
        self.last_active: float = now
        self.in_flight: int = 0

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/mcp"


# --- ContainerFanout -------------------------------------------------------


class ContainerFanout:
    """On-demand container orchestrator for stdio MCPs wrapped as HTTPS+JWT.

    Construct via :func:`mcp_hub.factory.build_fanout` from a policy entry
    of the form::

        mcps:
          <name>:
            transport: container
            image: <docker-image>
            scope: per-identity      # or "shared"
            idle_timeout: minutes=20
            env:
              MCP_COMMAND: "..."
              # ... pass-through env for the spawned wrapper + child ...
            secrets_to_env:
              HEB_PROXY_TOKEN: "services/heb/{identity}#api_token"
            auth:
              type: jwt_passthrough
    """

    def __init__(
        self,
        *,
        mcp_name: str,
        image: str,
        scope: str,
        identities: Sequence[str],
        oidc_issuer: str,
        oidc_discovery_url: str,
        env: dict[str, str],
        secrets_to_env: dict[str, SecretRef],
        auth_strategy: AuthStrategy,
        secret_backend: SecretBackend,
        docker_client: Any,
        volumes_per_identity: Sequence[VolumeMountSpec] = (),
        audience_template: str = DEFAULT_AUDIENCE_TEMPLATE,
        idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
        spawn_timeout_s: float = DEFAULT_SPAWN_TIMEOUT_S,
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
        eviction_interval_s: float = DEFAULT_EVICTION_INTERVAL_S,
        container_host: str = "host.docker.internal",
        container_port: int = DEFAULT_CONTAINER_PORT,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if _DOCKER_IMPORT_ERROR is not None:  # pragma: no cover
            raise RuntimeError(
                "ContainerFanout requires the docker package; install with `uv add docker` "
                f"(import failed: {_DOCKER_IMPORT_ERROR})"
            )
        if scope not in ("per-identity", "shared"):
            raise ValueError(f"ContainerFanout: invalid scope {scope!r}")
        if not identities:
            raise ValueError(f"ContainerFanout({mcp_name!r}) needs at least one identity")
        if len(set(identities)) != len(identities):
            raise ValueError(
                f"ContainerFanout({mcp_name!r}) has duplicate identities: {sorted(identities)}"
            )
        # audience_template requirements track the schema rule: per-identity
        # scope MUST template {identity} (each container is spawned for one
        # identity and the JWT must match its OIDC_AUDIENCE); shared scope
        # may use a literal value because the per-call JWT comes from a
        # hub-side strategy (e.g., FanoutJwt) accepted via OIDC_BOOT_AUDIENCE.
        if scope == "per-identity" and "{identity}" not in audience_template:
            raise ValueError(
                f"ContainerFanout({mcp_name!r}, scope=per-identity) "
                f"audience_template must contain {{identity}} placeholder, "
                f"got: {audience_template!r}"
            )

        self._mcp_name = mcp_name
        self._image = image
        self._scope = scope
        self._identities: tuple[str, ...] = tuple(identities)
        self._oidc_issuer = oidc_issuer
        self._oidc_discovery_url = oidc_discovery_url
        self._audience_template = audience_template
        self._env = dict(env)
        self._secrets_to_env = dict(secrets_to_env)
        self._volumes_per_identity: tuple[VolumeMountSpec, ...] = tuple(volumes_per_identity)
        self._auth = auth_strategy
        self._secrets = secret_backend
        self._docker = docker_client
        self._idle_timeout_s = idle_timeout_s
        self._spawn_timeout_s = spawn_timeout_s
        self._request_timeout_s = request_timeout_s
        self._eviction_interval_s = eviction_interval_s
        self._container_host = container_host
        self._container_port = container_port
        self._owns_http: bool = http_client is None
        self._http: httpx.AsyncClient | None = http_client

        self._handles: dict[str, _ContainerHandle] = {}
        self._handle_lock = asyncio.Lock()
        self._eviction_task: asyncio.Task[None] | None = None
        self._started: bool = False

    # ------------------------------------------------------------------ #
    # External API mirroring HttpFanout
    # ------------------------------------------------------------------ #

    @property
    def mcp_name(self) -> str:
        return self._mcp_name

    @property
    def identities(self) -> tuple[str, ...]:
        return self._identities

    async def start_eager_or_die(self) -> None:
        """Validate Docker reachability + image existence; do NOT pre-spawn.

        Containers are spawned lazily on first :meth:`call` per identity.
        Failing this method aborts hub startup, same as the stdio Fanout
        and HttpFanout.
        """
        if self._started:
            return
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=self._request_timeout_s,
                    write=10.0,
                    pool=10.0,
                ),
            )
            self._owns_http = True

        try:
            try:
                await asyncio.to_thread(self._docker.ping)
            except Exception as exc:
                raise HttpUpstreamFailed(
                    f"ContainerFanout({self._mcp_name}): docker ping failed: {exc}"
                ) from exc
            try:
                await asyncio.to_thread(self._docker.images.get, self._image)
            except docker.errors.ImageNotFound as exc:
                raise HttpUpstreamFailed(
                    f"ContainerFanout({self._mcp_name}): image {self._image!r} not "
                    f"found on docker host; build or pull it before starting the hub"
                ) from exc
            except docker.errors.APIError as exc:
                raise HttpUpstreamFailed(
                    f"ContainerFanout({self._mcp_name}): docker images.get failed: {exc}"
                ) from exc
        except HttpUpstreamFailed:
            # Don't leak the http client we just opened on a startup failure.
            if self._owns_http and self._http is not None:
                with contextlib.suppress(Exception):
                    await self._http.aclose()
                self._http = None
            raise

        # Adopt any containers spawned by a previous hub lifetime. Without
        # this, the in-memory _handles dict starts empty and every restart
        # orphans the previous lifetime's containers (the eviction loop
        # only iterates _handles, so it never sees them). Adoption runs
        # BEFORE the eviction task starts to avoid racing with eviction
        # over the same handle dict.
        await self._adopt_existing()

        self._eviction_task = asyncio.create_task(
            self._eviction_loop(), name=f"container-fanout-evict-{self._mcp_name}"
        )
        self._started = True
        logger.info(
            "ContainerFanout(%s) initialized (image=%s scope=%s identities=%s "
            "idle_timeout=%.0fs)",
            self._mcp_name, self._image, self._scope,
            list(self._identities), self._idle_timeout_s,
        )

    async def call(
        self,
        *,
        identity: str,
        request: dict[str, Any],
        request_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Forward a JSON-RPC request to this identity's spawned container."""
        if not self._started:
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): not started; call "
                f"start_eager_or_die() first"
            )
        if identity not in self._identities:
            raise IdentityNotFound(
                f"ContainerFanout({self._mcp_name}): unknown identity {identity!r}; "
                f"registered: {sorted(self._identities)}"
            )
        request_context = request_context or {}

        handle = await self._get_or_spawn(identity, request_context)
        handle.in_flight += 1
        try:
            return await self._post(handle, identity, request, request_context)
        finally:
            handle.in_flight -= 1
            handle.last_active = time.monotonic()

    async def close(self) -> None:
        """Stop and remove all spawned containers; cancel eviction; close HTTP."""
        if self._eviction_task is not None:
            self._eviction_task.cancel()
            with contextlib.suppress(BaseException):
                await self._eviction_task
            self._eviction_task = None

        async with self._handle_lock:
            handles = list(self._handles.items())
            self._handles.clear()
        for _key, handle in handles:
            await self._remove_container(handle)

        if self._owns_http and self._http is not None:
            with contextlib.suppress(Exception):
                await self._http.aclose()
        self._http = None
        self._started = False

        with contextlib.suppress(Exception):
            await self._auth.close()

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _spawn_key(self, identity: str) -> str:
        return identity if self._scope == "per-identity" else SHARED_KEY

    async def _get_or_spawn(
        self, identity: str, request_context: dict[str, Any]
    ) -> _ContainerHandle:
        key = self._spawn_key(identity)
        async with self._handle_lock:
            existing = self._handles.get(key)
            if existing is not None and await self._is_container_alive(existing):
                return existing
            if existing is not None:
                logger.warning(
                    "ContainerFanout(%s): existing container for key=%s is dead; respawning",
                    self._mcp_name, key,
                )
                with contextlib.suppress(Exception):
                    await self._remove_container(existing)
                self._handles.pop(key, None)
            handle = await self._spawn_container(identity, request_context)
            self._handles[key] = handle
            return handle

    def _build_volumes(self, identity: str) -> dict[str, dict[str, str]]:
        """Format volume_name_template per identity and return the docker-py volumes dict."""
        if not self._volumes_per_identity:
            return {}
        # For shared scope, format with identity="shared" so any literal
        # `{identity}` (an unusual choice for shared scope) resolves
        # deterministically. Schema validates that per-identity scope MUST
        # have the placeholder, so we don't double-check here.
        format_key = identity if self._scope == "per-identity" else "shared"
        volumes: dict[str, dict[str, str]] = {}
        for vm in self._volumes_per_identity:
            name = vm.volume_name_template.format(identity=format_key)
            volumes[name] = {"bind": vm.container_path, "mode": "rw"}
        return volumes

    async def _spawn_container(
        self, identity: str, request_context: dict[str, Any]
    ) -> _ContainerHandle:
        env = await self._build_env(identity)
        volumes = self._build_volumes(identity)
        labels = {
            "managed-by": "mcp-container-fanout",
            "mcp": self._mcp_name,
            "scope": self._scope,
            "identity": identity if self._scope == "per-identity" else "shared",
        }
        name = (
            f"mcp-{self._mcp_name}-"
            f"{identity if self._scope == 'per-identity' else 'shared'}-"
            f"{int(time.time())}"
        )
        run_kwargs: dict[str, Any] = {
            "image": self._image,
            "detach": True,
            "environment": env,
            "ports": {f"{self._container_port}/tcp": None},
            "labels": labels,
            "name": name,
            # Resource hygiene defaults — override per-MCP via env if needed.
            "mem_limit": "2g",
            # Don't auto-restart; the orchestrator owns lifecycle.
        }
        if volumes:
            run_kwargs["volumes"] = volumes
        try:
            container: Container = await asyncio.to_thread(
                self._docker.containers.run, **run_kwargs,
            )
        except docker.errors.APIError as exc:
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): docker run failed for "
                f"identity={identity!r}: {exc}"
            ) from exc

        try:
            await asyncio.to_thread(container.reload)
            ports_map = container.attrs["NetworkSettings"]["Ports"]
            binding = ports_map.get(f"{self._container_port}/tcp") or []
            if not binding:
                raise HttpUpstreamFailed(
                    f"ContainerFanout({self._mcp_name}): no port binding on spawned "
                    f"container for identity={identity}"
                )
            host_port = int(binding[0]["HostPort"])
        except (docker.errors.APIError, KeyError, ValueError, TypeError) as exc:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(container.remove, force=True)
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): inspect failed: {exc}"
            ) from exc

        handle = _ContainerHandle(
            container=container, port=host_port, host=self._container_host
        )
        try:
            await self._wait_ready(handle)
            # MCP protocol handshake: every freshly-spawned upstream needs
            # ``initialize`` + ``notifications/initialized`` before any
            # other request. FastMCP-based servers (texas-grocery-mcp etc.)
            # explicitly reject pre-initialize requests; even non-FastMCP
            # MCPs are within their rights to require the handshake.
            await self._initialize_handshake(handle, identity, request_context)
        except HttpUpstreamFailed:
            with contextlib.suppress(Exception):
                await self._remove_container(handle)
            raise
        logger.info(
            "ContainerFanout(%s): spawned %s for identity=%s scope=%s at %s",
            self._mcp_name, getattr(container, "short_id", "?"),
            identity, self._scope, handle.url,
        )
        return handle

    async def _initialize_handshake(
        self,
        handle: _ContainerHandle,
        identity: str,
        request_context: dict[str, Any],
    ) -> None:
        """Run the MCP initialize handshake against a freshly-spawned container.

        MCP spec: client sends ``initialize`` request, server responds; client
        then sends ``notifications/initialized`` (no id, no response). After
        that, normal tool calls are accepted. The wrapper image's stdio child
        won't accept tool calls until this runs.
        """
        init_resp = await self._post(
            handle,
            identity,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "clientInfo": {
                        "name": "mcp-fanout-container",
                        "version": "0.0.0",
                    },
                },
            },
            request_context,
        )
        if "error" in init_resp:
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): initialize handshake "
                f"failed: {init_resp['error']}"
            )
        # Best-effort fire-and-forget notification per spec; failure is
        # logged but doesn't kill the spawn (some servers tolerate skipping).
        with contextlib.suppress(HttpUpstreamFailed):
            await self._post(
                handle,
                identity,
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                request_context,
            )

    async def _build_env(self, identity: str) -> dict[str, str]:
        """Compose the env dict the spawned container starts with.

        Order: OIDC_* (computed) → policy.env → resolved bao secrets. Later
        keys win — but we don't ship policy.env keys named OIDC_*, so the
        computed values are effectively authoritative.
        """
        env: dict[str, str] = {
            "OIDC_ISSUER": self._oidc_issuer,
            "OIDC_DISCOVERY_URL": self._oidc_discovery_url,
            "OIDC_AUDIENCE": self._audience_template.format(identity=identity),
            **self._env,
        }
        for env_var, ref in self._secrets_to_env.items():
            try:
                resolved = await self._secrets.resolve(
                    mcp=self._mcp_name,
                    identity=identity,
                    ref=SecretRef(
                        path=ref.path.format(identity=identity),
                        field=ref.field,
                    ),
                )
            except SecretResolutionError as exc:
                raise HttpUpstreamFailed(
                    f"ContainerFanout({self._mcp_name}): could not resolve secret "
                    f"{env_var}={ref.path}#{ref.field} for identity={identity}: {exc}"
                ) from exc
            env[env_var] = resolved.value
        return env

    async def _wait_ready(self, handle: _ContainerHandle) -> None:
        """Poll the spawned container's /ready endpoint until 200 or timeout."""
        assert self._http is not None
        deadline = time.monotonic() + self._spawn_timeout_s
        last_err: str = "no response"
        while time.monotonic() < deadline:
            try:
                resp = await self._http.get(
                    f"http://{handle.host}:{handle.port}/ready",
                    timeout=2.0,
                )
                if resp.status_code == 200:
                    return
                last_err = f"HTTP {resp.status_code}: {resp.text[:200]!r}"
            except httpx.HTTPError as exc:
                last_err = f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(0.5)
        raise HttpUpstreamFailed(
            f"ContainerFanout({self._mcp_name}): container did not become ready "
            f"within {self._spawn_timeout_s}s; last error: {last_err}"
        )

    async def _post(
        self,
        handle: _ContainerHandle,
        identity: str,
        request: dict[str, Any],
        request_context: dict[str, Any],
    ) -> dict[str, Any]:
        assert self._http is not None
        try:
            auth_headers = await self._auth.auth_header(
                identity=identity, request_context=request_context
            )
        except Exception as exc:
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): auth strategy "
                f"{self._auth.name!r} failed for identity={identity!r}: {exc}"
            ) from exc
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **auth_headers,
        }
        try:
            resp = await self._http.post(
                handle.url,
                json=request,
                headers=headers,
                timeout=self._request_timeout_s,
            )
        except httpx.HTTPError as exc:
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): POST to {handle.url} failed: {exc}"
            ) from exc

        if resp.status_code == 202:
            # Notification path — wrapper acks with 202 + empty body
            return {}
        if resp.status_code >= 400:
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): upstream HTTP "
                f"{resp.status_code}: {resp.text[:300]!r}"
            )
        try:
            parsed = resp.json()
        except (ValueError, UnicodeDecodeError) as exc:
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): non-JSON response: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise HttpUpstreamFailed(
                f"ContainerFanout({self._mcp_name}): non-object response: "
                f"{type(parsed).__name__}"
            )
        return parsed

    async def _is_container_alive(self, handle: _ContainerHandle) -> bool:
        try:
            await asyncio.to_thread(handle.container.reload)
            return getattr(handle.container, "status", None) == "running"
        except docker.errors.NotFound:
            return False
        except docker.errors.APIError as exc:
            logger.warning(
                "ContainerFanout(%s): status check failed: %s",
                self._mcp_name, exc,
            )
            return False

    async def _remove_container(self, handle: _ContainerHandle) -> None:
        try:
            await asyncio.to_thread(handle.container.remove, force=True)
            logger.info(
                "ContainerFanout(%s): removed %s",
                self._mcp_name, getattr(handle.container, "short_id", "?"),
            )
        except docker.errors.NotFound:
            pass
        except docker.errors.APIError as exc:
            logger.warning(
                "ContainerFanout(%s): remove %s failed: %s",
                self._mcp_name, getattr(handle.container, "short_id", "?"), exc,
            )

    async def _adopt_existing(self) -> None:
        """Reattach to containers spawned by a previous hub lifetime.

        Self-heals the most common orphan source: hub restarts wipe
        ``self._handles`` (in-memory), so without adoption every restart
        spawns a fresh container while leaving the previous one running
        indefinitely (the eviction loop only iterates ``self._handles``).

        Filters on the labels written at spawn time (see
        :meth:`_spawn_container`): ``managed-by=mcp-container-fanout`` AND
        ``mcp=<self._mcp_name>``. For each spawn key (identity for
        per-identity scope, ``SHARED_KEY`` for shared), keeps the newest
        running container with a port binding and removes the rest.

        Best-effort: any Docker error logs a warning and returns without
        raising. Adoption never blocks hub startup — if it can't list
        containers, the fanout just starts with an empty handle dict.

        Notes:
        - No ``_initialize_handshake`` is re-run. The adopted container
          was initialized in its previous lifetime; ZeroClaw / MCP
          servers handle re-init at their own layer if needed. First
          failing call after adoption surfaces a dead handle and
          :meth:`_get_or_spawn` respawns.
        - ``last_active`` is initialized to ``time.monotonic()`` (now):
          the monotonic clock can't represent times from before the hub
          started. An adopted container therefore gets one full
          ``idle_timeout_s`` window before eviction, regardless of how
          long it had been idle pre-restart. Trade-off: today's orphan
          survives ~one more idle window after adoption before cleanup;
          acceptable since the loop disposes of it automatically.
        """
        label_filter: dict[str, list[str]] = {
            "label": [
                "managed-by=mcp-container-fanout",
                f"mcp={self._mcp_name}",
            ]
        }
        try:
            existing = await asyncio.to_thread(
                self._docker.containers.list, all=True, filters=label_filter
            )
        except docker.errors.APIError as exc:
            logger.warning(
                "ContainerFanout(%s): adoption list failed: %s; starting "
                "with empty handles", self._mcp_name, exc,
            )
            return

        # Group candidate containers by spawn key. For per-identity scope,
        # the key is the identity label (drop containers labeled with an
        # unknown identity — they're orphans from a removed identity).
        # For shared scope, every candidate maps to SHARED_KEY.
        by_key: dict[str, list[Any]] = {}
        for c in existing:
            try:
                await asyncio.to_thread(c.reload)
            except docker.errors.NotFound:
                continue
            except docker.errors.APIError as exc:
                logger.warning(
                    "ContainerFanout(%s): adoption reload %s failed: %s; skipping",
                    self._mcp_name, getattr(c, "short_id", "?"), exc,
                )
                continue
            labels = ((c.attrs or {}).get("Config") or {}).get("Labels") or {}
            identity_label = labels.get("identity", "")
            if self._scope == "per-identity":
                if identity_label not in self._identities:
                    logger.info(
                        "ContainerFanout(%s): removing orphan container %s "
                        "(unknown identity=%r)",
                        self._mcp_name, getattr(c, "short_id", "?"),
                        identity_label,
                    )
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(c.remove, force=True)
                    continue
                key = identity_label
            else:
                key = SHARED_KEY
            by_key.setdefault(key, []).append(c)

        for key, candidates in by_key.items():
            # Sort newest-first by Docker's Created timestamp string
            # (ISO-8601 sortable). Ties (same second) are stable.
            candidates.sort(
                key=lambda c: (c.attrs or {}).get("Created", ""),
                reverse=True,
            )
            winner = candidates[0]
            losers = candidates[1:]
            status = getattr(winner, "status", None)
            ports_map = (
                ((winner.attrs or {}).get("NetworkSettings") or {}).get("Ports")
                or {}
            )
            binding = ports_map.get(f"{self._container_port}/tcp") or []
            if status != "running" or not binding:
                logger.info(
                    "ContainerFanout(%s): newest candidate %s for key=%s "
                    "is unusable (status=%r, has_binding=%s); removing all "
                    "%d candidates",
                    self._mcp_name, getattr(winner, "short_id", "?"),
                    key, status, bool(binding), len(candidates),
                )
                for c in candidates:
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(c.remove, force=True)
                continue
            try:
                host_port = int(binding[0]["HostPort"])
            except (KeyError, ValueError, TypeError) as exc:
                logger.info(
                    "ContainerFanout(%s): cannot parse port binding on %s "
                    "for key=%s (%s); removing all %d candidates",
                    self._mcp_name, getattr(winner, "short_id", "?"),
                    key, exc, len(candidates),
                )
                for c in candidates:
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(c.remove, force=True)
                continue
            handle = _ContainerHandle(
                container=winner, port=host_port, host=self._container_host
            )
            self._handles[key] = handle
            logger.info(
                "ContainerFanout(%s): adopted existing container %s for "
                "key=%s at %s (idle window starts now)",
                self._mcp_name, getattr(winner, "short_id", "?"),
                key, handle.url,
            )
            for loser in losers:
                logger.info(
                    "ContainerFanout(%s): removing duplicate container %s "
                    "for key=%s (kept newer %s)",
                    self._mcp_name, getattr(loser, "short_id", "?"),
                    key, getattr(winner, "short_id", "?"),
                )
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(loser.remove, force=True)

    async def _eviction_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._eviction_interval_s)
                await self._evict_idle()
        except asyncio.CancelledError:
            return

    async def _evict_idle(self) -> None:
        now = time.monotonic()
        async with self._handle_lock:
            to_evict: list[tuple[str, _ContainerHandle]] = []
            for key, handle in self._handles.items():
                if handle.in_flight > 0:
                    continue
                if (now - handle.last_active) >= self._idle_timeout_s:
                    to_evict.append((key, handle))
            for key, _handle in to_evict:
                self._handles.pop(key, None)
        # Remove outside the lock — Docker calls block; releasing the lock
        # lets new spawn requests for OTHER identities proceed concurrently.
        for key, handle in to_evict:
            logger.info(
                "ContainerFanout(%s): evicting key=%s (idle %.0fs, started %.0fs ago)",
                self._mcp_name, key,
                now - handle.last_active, now - handle.started_at,
            )
            await self._remove_container(handle)
