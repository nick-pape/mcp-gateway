"""Tests for :class:`mcp_fanout.ContainerFanout`.

Mocks the Docker SDK and a :class:`SecretBackend` to exercise the
on-demand spawn / per-identity isolation / eviction / lifecycle paths
without touching a real Docker daemon. The /ready and /mcp endpoints
inside spawned containers are stubbed via :class:`httpx.MockTransport`
keyed on the container's host:port URL.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from mcp_fanout import (
    ContainerFanout,
    HttpUpstreamFailed,
    IdentityNotFound,
    VolumeMountSpec,
)
from mcp_hub.interfaces import (
    ResolvedSecret,
    SecretRef,
    SecretResolutionError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StaticBearer:
    """Stub AuthStrategy returning a configured Bearer token verbatim."""

    name: str = "static_bearer"

    def __init__(self, token: str = "dummy-jwt") -> None:
        self._token = token
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    async def auth_header(
        self, *, identity: str, request_context: dict[str, Any]
    ) -> dict[str, str]:
        self.calls.append((identity, dict(request_context)))
        return {"Authorization": f"Bearer {self._token}"}

    async def close(self) -> None:
        self.closed = True


class _StubSecretBackend:
    """In-memory SecretBackend keyed by (mcp, identity, path, field)."""

    name: str = "stub"

    def __init__(self, *, secrets: dict[tuple[str, str, str, str], str] | None = None) -> None:
        self._secrets = dict(secrets or {})
        self.resolutions: list[tuple[str, str, str, str]] = []
        self.fail_for: set[tuple[str, str, str, str]] = set()

    async def resolve(
        self,
        *,
        mcp: str,
        identity: str,
        ref: SecretRef,
        jwt: str | None = None,
    ) -> ResolvedSecret:
        del jwt
        key = (mcp, identity, ref.path, ref.field)
        self.resolutions.append(key)
        if key in self.fail_for:
            raise SecretResolutionError(f"stub: forced fail for {key}")
        if key not in self._secrets:
            raise SecretResolutionError(f"stub: no secret for {key}")
        return ResolvedSecret(value=self._secrets[key])

    async def close(self) -> None:
        return None


class _FakeContainer:
    """Mimics docker.models.containers.Container's attribute surface.

    Optional kwargs let adoption tests pre-construct containers with
    custom labels / Created timestamps / status / port bindings — the
    spawn path supplies only name + host_port via the normal defaults.
    """

    def __init__(
        self,
        *,
        name: str,
        host_port: int,
        status: str = "running",
        labels: dict[str, str] | None = None,
        created: str = "2026-05-16T00:00:00.000000000Z",
        include_port_binding: bool = True,
    ) -> None:
        self.name = name
        self.short_id = name[:12]
        self.status = status
        ports: dict[str, list[dict[str, str]]] = {}
        if include_port_binding:
            ports = {"8080/tcp": [{"HostPort": str(host_port)}]}
        self.attrs: dict[str, Any] = {
            "Created": created,
            "Config": {"Labels": dict(labels or {})},
            "NetworkSettings": {"Ports": ports},
        }
        self._host_port = host_port
        self.removed: bool = False
        self.removed_force: bool = False
        self.reload_calls: int = 0

    def reload(self) -> None:
        self.reload_calls += 1

    def remove(self, *, force: bool = False) -> None:
        self.removed = True
        self.removed_force = force


class _FakeDockerClient:
    """Mimics docker.DockerClient minimal surface used by ContainerFanout."""

    def __init__(
        self,
        *,
        image_present: bool = True,
        ping_ok: bool = True,
        pre_existing: list[_FakeContainer] | None = None,
        list_raises: Exception | None = None,
    ) -> None:
        self._image_present = image_present
        self._ping_ok = ping_ok
        self._pre_existing: list[_FakeContainer] = list(pre_existing or [])
        self._list_raises = list_raises
        self.spawned: list[_FakeContainer] = []
        self.run_calls: list[dict[str, Any]] = []  # kwargs of each containers.run call
        self.list_calls: list[dict[str, Any]] = []  # kwargs of each containers.list call
        self._port_seq = 12000
        self.images = MagicMock()
        self.images.get = self._images_get
        self.containers = MagicMock()
        self.containers.run = self._containers_run
        self.containers.list = self._containers_list

    def ping(self) -> bool:
        if not self._ping_ok:
            import docker.errors

            raise docker.errors.APIError("ping failed (forced)")
        return True

    def _images_get(self, image: str) -> Any:
        if not self._image_present:
            import docker.errors

            raise docker.errors.ImageNotFound(f"image not found: {image}")
        return MagicMock(id=f"sha256:{image}")

    def _containers_run(self, **kwargs: Any) -> _FakeContainer:
        # Record the kwargs for assertions (we replaced containers.run with
        # a plain method, so MagicMock's call_args isn't available).
        self.run_calls.append(dict(kwargs))
        name = kwargs.get("name", f"container-{self._port_seq}")
        self._port_seq += 1
        c = _FakeContainer(name=name, host_port=self._port_seq)
        self.spawned.append(c)
        return c

    def _containers_list(self, **kwargs: Any) -> list[_FakeContainer]:
        # Adoption calls containers.list(all=True, filters={"label": [...]}).
        # We honor `all` (include stopped) trivially since the test fakes
        # don't model "list excludes stopped". For `filters.label`, every
        # entry must be present in the container's labels (Docker semantics).
        self.list_calls.append(dict(kwargs))
        if self._list_raises is not None:
            raise self._list_raises
        wanted = kwargs.get("filters", {}).get("label", [])
        wanted_pairs = [w.split("=", 1) for w in wanted if "=" in w]

        def matches(c: _FakeContainer) -> bool:
            labels = ((c.attrs or {}).get("Config") or {}).get("Labels") or {}
            return all(labels.get(k) == v for k, v in wanted_pairs)

        return [c for c in self._pre_existing if matches(c)]


class _RoutedTransport:
    """httpx MockTransport that routes by URL path.

    The fanout calls ``GET http://<host>:<port>/ready`` and
    ``POST http://<host>:<port>/mcp``. We respond per-path; tests can
    override per-port if they want to simulate spawn-not-ready.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.ready_status_per_port: dict[int, int] = {}
        self.mcp_responses: list[tuple[int, dict[str, Any] | str]] = []
        self.default_ready_status: int = 200

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        port = int(request.url.port or 0)
        if request.url.path == "/ready":
            status = self.ready_status_per_port.get(port, self.default_ready_status)
            return httpx.Response(status, json={"status": "ready"})
        if request.url.path == "/mcp":
            if not self.mcp_responses:
                return httpx.Response(
                    200, json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
                )
            status, body = self.mcp_responses.pop(0)
            if isinstance(body, dict):
                return httpx.Response(status, json=body)
            return httpx.Response(status, text=body)
        return httpx.Response(404, text=f"unexpected path: {request.url.path}")


def _make_fanout(
    *,
    docker_client: _FakeDockerClient,
    secret_backend: _StubSecretBackend,
    routed: _RoutedTransport,
    scope: str = "per-identity",
    identities: list[str] | None = None,
    secrets_to_env: dict[str, SecretRef] | None = None,
    env: dict[str, str] | None = None,
    volumes_per_identity: list[VolumeMountSpec] | None = None,
    idle_timeout_s: float = 60.0,
    spawn_timeout_s: float = 5.0,
    eviction_interval_s: float = 0.05,  # tests advance time manually; keep low
    auth: _StaticBearer | None = None,
) -> ContainerFanout:
    return ContainerFanout(
        mcp_name="heb",
        image="mcp-pape-house/heb-mcp-wrapper:test",
        scope=scope,
        identities=identities or ["alice", "bob"],
        oidc_issuer="https://auth.example/",
        oidc_discovery_url="https://auth.example/application/o/mcp-fanout-svc",
        env=env or {},
        secrets_to_env=secrets_to_env or {},
        volumes_per_identity=volumes_per_identity or [],
        auth_strategy=auth or _StaticBearer(),
        secret_backend=secret_backend,
        docker_client=docker_client,
        idle_timeout_s=idle_timeout_s,
        spawn_timeout_s=spawn_timeout_s,
        eviction_interval_s=eviction_interval_s,
        container_host="127.0.0.1",
        http_client=httpx.AsyncClient(transport=routed.transport()),
    )


# ---------------------------------------------------------------------------
# start_eager_or_die
# ---------------------------------------------------------------------------


async def test_start_eager_or_die_success() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient(ping_ok=True, image_present=True)
    secrets = _StubSecretBackend()
    fan = _make_fanout(docker_client=docker, secret_backend=secrets, routed=routed)
    await fan.start_eager_or_die()
    assert fan.identities == ("alice", "bob")
    assert fan.mcp_name == "heb"
    await fan.close()


async def test_start_eager_or_die_ping_failure() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient(ping_ok=False)
    secrets = _StubSecretBackend()
    fan = _make_fanout(docker_client=docker, secret_backend=secrets, routed=routed)
    with pytest.raises(HttpUpstreamFailed, match="docker ping failed"):
        await fan.start_eager_or_die()


async def test_start_eager_or_die_missing_image() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient(image_present=False)
    secrets = _StubSecretBackend()
    fan = _make_fanout(docker_client=docker, secret_backend=secrets, routed=routed)
    with pytest.raises(HttpUpstreamFailed, match="not found"):
        await fan.start_eager_or_die()


# ---------------------------------------------------------------------------
# Spawn-on-call + per-identity vs shared scope
# ---------------------------------------------------------------------------


async def test_call_spawns_per_identity_on_first_call() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(docker_client=docker, secret_backend=secrets, routed=routed)
    await fan.start_eager_or_die()

    resp = await fan.call(
        identity="alice",
        request={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        request_context={},
    )
    assert resp == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert len(docker.spawned) == 1, "first call to alice must spawn one container"

    # Same identity → reuses
    await fan.call(
        identity="alice",
        request={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        request_context={},
    )
    assert len(docker.spawned) == 1, "second alice call must reuse"

    # Different identity → new container
    await fan.call(
        identity="bob",
        request={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        request_context={},
    )
    assert len(docker.spawned) == 2, "bob call must spawn its own container"

    await fan.close()


async def test_call_shared_scope_uses_one_container_for_all_identities() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed, scope="shared"
    )
    await fan.start_eager_or_die()

    await fan.call(identity="alice", request={"jsonrpc": "2.0", "id": 1}, request_context={})
    await fan.call(identity="bob", request={"jsonrpc": "2.0", "id": 2}, request_context={})

    assert len(docker.spawned) == 1, "shared scope must spawn exactly one container"
    await fan.close()


async def test_call_unknown_identity_raises() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(docker_client=docker, secret_backend=secrets, routed=routed)
    await fan.start_eager_or_die()
    with pytest.raises(IdentityNotFound):
        await fan.call(identity="charlie", request={"id": 1}, request_context={})
    await fan.close()


async def test_call_before_start_raises() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(docker_client=docker, secret_backend=secrets, routed=routed)
    with pytest.raises(HttpUpstreamFailed, match="not started"):
        await fan.call(identity="alice", request={"id": 1}, request_context={})


# ---------------------------------------------------------------------------
# Env injection: OIDC_* + policy env + bao secrets
# ---------------------------------------------------------------------------


async def test_spawn_injects_oidc_and_secrets_into_container_env() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend(
        secrets={
            ("heb", "alice", "services/heb/alice", "api_token"): "alice-token-XYZ",
        }
    )
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        env={"HEB_DEFAULT_STORE": "590", "MCP_COMMAND": "texas-grocery-mcp"},
        secrets_to_env={
            "HEB_PROXY_TOKEN": SecretRef(path="services/heb/{identity}", field="api_token"),
        },
    )
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"jsonrpc": "2.0", "id": 1}, request_context={})

    # Inspect what containers.run was called with
    assert len(docker.run_calls) == 1
    kwargs = docker.run_calls[0]
    env = kwargs["environment"]
    assert env["OIDC_ISSUER"] == "https://auth.example/"
    assert env["OIDC_DISCOVERY_URL"] == "https://auth.example/application/o/mcp-fanout-svc"
    assert env["OIDC_AUDIENCE"] == "mcp-alice"
    assert env["HEB_DEFAULT_STORE"] == "590"
    assert env["MCP_COMMAND"] == "texas-grocery-mcp"
    assert env["HEB_PROXY_TOKEN"] == "alice-token-XYZ"

    # Secret resolution recorded with the formatted (per-identity) path
    assert ("heb", "alice", "services/heb/alice", "api_token") in secrets.resolutions
    await fan.close()


async def test_secret_resolution_failure_propagates_as_http_upstream_failed() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    secrets.fail_for.add(("heb", "alice", "services/heb/alice", "api_token"))
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        secrets_to_env={
            "HEB_PROXY_TOKEN": SecretRef(path="services/heb/{identity}", field="api_token"),
        },
    )
    await fan.start_eager_or_die()
    with pytest.raises(HttpUpstreamFailed, match="could not resolve secret"):
        await fan.call(identity="alice", request={"id": 1}, request_context={})
    await fan.close()


# ---------------------------------------------------------------------------
# Eviction
# ---------------------------------------------------------------------------


async def test_eviction_removes_idle_containers() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        idle_timeout_s=0.05,
        eviction_interval_s=0.02,
    )
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"id": 1}, request_context={})
    assert len(docker.spawned) == 1
    container = docker.spawned[0]
    # Wait long enough for a couple of eviction ticks past idle_timeout
    await asyncio.sleep(0.25)
    assert container.removed is True, "idle container should have been evicted"
    await fan.close()


async def test_eviction_skips_in_flight_handles() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        idle_timeout_s=0.0,         # everything is "idle past timeout" by default
        eviction_interval_s=0.02,
    )
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"id": 1}, request_context={})
    container = docker.spawned[0]
    # Hand-bump in_flight to simulate a long-running call
    handle = fan._handles[fan._spawn_key("alice")]
    handle.in_flight = 1
    await asyncio.sleep(0.15)
    assert container.removed is False, "in-flight handle must not be evicted"
    handle.in_flight = 0
    await asyncio.sleep(0.15)
    assert container.removed is True, "idle handle is evicted after in_flight returns to 0"
    await fan.close()


# ---------------------------------------------------------------------------
# Wait-for-ready + spawn-failure cleanup
# ---------------------------------------------------------------------------


async def test_spawn_fails_if_ready_never_returns_200() -> None:
    routed = _RoutedTransport()
    routed.default_ready_status = 503
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        spawn_timeout_s=0.3,
    )
    await fan.start_eager_or_die()
    with pytest.raises(HttpUpstreamFailed, match="did not become ready"):
        await fan.call(identity="alice", request={"id": 1}, request_context={})
    # The failed-spawn container should have been force-removed
    assert len(docker.spawned) == 1
    assert docker.spawned[0].removed is True
    await fan.close()


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


async def test_close_tears_down_all_containers() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(docker_client=docker, secret_backend=secrets, routed=routed)
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"id": 1}, request_context={})
    await fan.call(identity="bob", request={"id": 2}, request_context={})
    assert len(docker.spawned) == 2

    await fan.close()

    for c in docker.spawned:
        assert c.removed is True


# ---------------------------------------------------------------------------
# Auth header forwarding
# ---------------------------------------------------------------------------


async def test_spawn_with_volumes_passes_per_identity_volume_to_docker() -> None:
    """Volume name templates resolve to identity-specific names; docker-py shape is right."""
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        volumes_per_identity=[
            VolumeMountSpec(
                container_path="/home/appuser/.texas-grocery-mcp",
                volume_name_template="heb-state-{identity}",
            ),
        ],
    )
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"jsonrpc": "2.0", "id": 1}, request_context={})
    assert len(docker.run_calls) == 1
    volumes = docker.run_calls[0].get("volumes")
    assert volumes is not None, "volumes kwarg should be passed to docker.containers.run"
    assert volumes == {
        "heb-state-alice": {
            "bind": "/home/appuser/.texas-grocery-mcp",
            "mode": "rw",
        },
    }
    await fan.close()


async def test_spawn_with_volumes_distinct_per_identity() -> None:
    """Two identities → two containers → two distinct volume names."""
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        volumes_per_identity=[
            VolumeMountSpec(container_path="/data", volume_name_template="x-{identity}"),
        ],
    )
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"id": 1}, request_context={})
    await fan.call(identity="bob", request={"id": 2}, request_context={})
    assert len(docker.run_calls) == 2
    assert docker.run_calls[0]["volumes"] == {"x-alice": {"bind": "/data", "mode": "rw"}}
    assert docker.run_calls[1]["volumes"] == {"x-bob": {"bind": "/data", "mode": "rw"}}
    await fan.close()


async def test_spawn_without_volumes_does_not_pass_volumes_kwarg() -> None:
    """Empty volumes_per_identity: docker.containers.run gets NO `volumes` kwarg."""
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed,
        volumes_per_identity=[],
    )
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"id": 1}, request_context={})
    assert "volumes" not in docker.run_calls[0]
    await fan.close()


async def test_spawn_with_volumes_shared_scope_uses_shared_key() -> None:
    """Shared-scope containers can have static or {identity}-templated names; we format with 'shared'."""
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker,
        secret_backend=secrets,
        routed=routed,
        scope="shared",
        volumes_per_identity=[
            VolumeMountSpec(container_path="/data", volume_name_template="static-name"),
            VolumeMountSpec(container_path="/data2", volume_name_template="x-{identity}"),
        ],
    )
    await fan.start_eager_or_die()
    await fan.call(identity="alice", request={"id": 1}, request_context={})
    volumes = docker.run_calls[0]["volumes"]
    assert volumes["static-name"]["bind"] == "/data"
    assert volumes["x-shared"]["bind"] == "/data2"
    await fan.close()


async def test_auth_strategy_called_with_identity_and_request_context() -> None:
    routed = _RoutedTransport()
    docker = _FakeDockerClient()
    secrets = _StubSecretBackend()
    auth = _StaticBearer(token="xyz")
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed, auth=auth,
    )
    await fan.start_eager_or_die()
    await fan.call(
        identity="alice",
        request={"id": 1},
        request_context={"bearer_token": "agent-jwt"},
    )
    # auth_header was called for alice with the right request_context.
    # First call spawns the container, which triggers initialize +
    # notifications/initialized + the actual user call — three POSTs
    # against /mcp, all routed through auth_header with the same context.
    assert any(call[0] == "alice" and call[1] == {"bearer_token": "agent-jwt"} for call in auth.calls)
    posts = [r for r in routed.requests if r.url.path == "/mcp"]
    assert len(posts) >= 1, "expected at least one /mcp POST (the user call)"
    # Every /mcp POST should carry the same Authorization header — the
    # auth strategy is consulted afresh per request.
    for p in posts:
        assert p.headers["authorization"] == "Bearer xyz"
    await fan.close()


# ---------------------------------------------------------------------------
# Adoption (containers from a previous hub lifetime)
# ---------------------------------------------------------------------------


def _adopt_labels(mcp: str, identity: str, scope: str = "shared") -> dict[str, str]:
    """Mirror the label set _spawn_container writes."""
    return {
        "managed-by": "mcp-container-fanout",
        "mcp": mcp,
        "scope": scope,
        "identity": identity,
    }


async def test_adopts_existing_shared_scope_container() -> None:
    """Pre-existing container with matching labels is adopted; no respawn."""
    routed = _RoutedTransport()
    pre = _FakeContainer(
        name="mcp-fakemcp-shared-1700000000",
        host_port=12345,
        labels=_adopt_labels("heb", "shared"),
        created="2026-05-16T00:00:01Z",
    )
    docker = _FakeDockerClient(pre_existing=[pre])
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed,
        scope="shared", identities=["alice", "bob"],
    )
    await fan.start_eager_or_die()
    from mcp_fanout.container_fanout import SHARED_KEY

    assert SHARED_KEY in fan._handles
    assert fan._handles[SHARED_KEY].container is pre
    assert fan._handles[SHARED_KEY].port == 12345
    assert docker.run_calls == []  # no respawn happened
    assert not pre.removed
    await fan.close()


async def test_adopts_newest_removes_duplicates_shared() -> None:
    """Four pre-existing containers; only the newest survives, three removed."""
    routed = _RoutedTransport()
    oldest = _FakeContainer(
        name="mcp-fakemcp-shared-1700000000", host_port=12000,
        labels=_adopt_labels("heb", "shared"),
        created="2026-05-15T20:00:00Z",
    )
    middle1 = _FakeContainer(
        name="mcp-fakemcp-shared-1700001000", host_port=12001,
        labels=_adopt_labels("heb", "shared"),
        created="2026-05-15T22:00:00Z",
    )
    middle2 = _FakeContainer(
        name="mcp-fakemcp-shared-1700002000", host_port=12002,
        labels=_adopt_labels("heb", "shared"),
        created="2026-05-15T23:30:00Z",
    )
    newest = _FakeContainer(
        name="mcp-fakemcp-shared-1700003000", host_port=12003,
        labels=_adopt_labels("heb", "shared"),
        created="2026-05-16T00:00:00Z",
    )
    docker = _FakeDockerClient(pre_existing=[oldest, middle1, newest, middle2])
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed,
        scope="shared", identities=["alice"],
    )
    await fan.start_eager_or_die()
    from mcp_fanout.container_fanout import SHARED_KEY

    assert fan._handles[SHARED_KEY].container is newest
    assert not newest.removed
    for loser in (oldest, middle1, middle2):
        assert loser.removed, f"{loser.name} should have been removed"
        assert loser.removed_force is True
    await fan.close()


async def test_adoption_drops_unknown_identity_per_identity_scope() -> None:
    """Per-identity fanout removes containers labeled with identities it doesn't know."""
    routed = _RoutedTransport()
    bob_orphan = _FakeContainer(
        name="mcp-fakemcp-bob-1700000000", host_port=12100,
        labels=_adopt_labels("heb", "bob", scope="per-identity"),
        created="2026-05-16T00:00:00Z",
    )
    docker = _FakeDockerClient(pre_existing=[bob_orphan])
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed,
        scope="per-identity", identities=["alice"],
    )
    await fan.start_eager_or_die()
    assert fan._handles == {}
    assert bob_orphan.removed
    assert bob_orphan.removed_force is True
    await fan.close()


async def test_adoption_drops_non_running_containers() -> None:
    """Containers with status != 'running' are not adopted and get removed."""
    routed = _RoutedTransport()
    exited = _FakeContainer(
        name="mcp-fakemcp-shared-1700000000", host_port=12200,
        labels=_adopt_labels("heb", "shared"),
        status="exited",
        created="2026-05-16T00:00:00Z",
    )
    docker = _FakeDockerClient(pre_existing=[exited])
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed,
        scope="shared", identities=["alice"],
    )
    await fan.start_eager_or_die()
    assert fan._handles == {}
    assert exited.removed
    await fan.close()


async def test_adoption_drops_containers_without_port_binding() -> None:
    """Containers with no port binding can't be talked to; remove them."""
    routed = _RoutedTransport()
    no_port = _FakeContainer(
        name="mcp-fakemcp-shared-1700000000", host_port=12300,
        labels=_adopt_labels("heb", "shared"),
        created="2026-05-16T00:00:00Z",
        include_port_binding=False,
    )
    docker = _FakeDockerClient(pre_existing=[no_port])
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker, secret_backend=secrets, routed=routed,
        scope="shared", identities=["alice"],
    )
    await fan.start_eager_or_die()
    assert fan._handles == {}
    assert no_port.removed
    await fan.close()


async def test_adoption_swallows_docker_list_failure() -> None:
    """If docker list raises, startup still succeeds with empty handles."""
    import docker.errors

    routed = _RoutedTransport()
    docker_client = _FakeDockerClient(
        list_raises=docker.errors.APIError("simulated docker outage"),
    )
    secrets = _StubSecretBackend()
    fan = _make_fanout(
        docker_client=docker_client, secret_backend=secrets, routed=routed,
        scope="shared", identities=["alice"],
    )
    await fan.start_eager_or_die()  # MUST NOT raise
    assert fan._handles == {}
    assert docker_client.list_calls, "containers.list should have been attempted"
    await fan.close()
