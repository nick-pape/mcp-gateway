"""Config → backend instances.

The hub picks ``SecretBackend`` and ``Approver`` implementations at
startup based on ``policy.yaml``'s ``secret_backend.name`` and
``approver.name`` strings. This module is the single dispatch point —
all "if name == 'bao': ..." branching lives here, not scattered.

Both production and test fakes are wired here so tests can drop the
hub config into ``{name: env}`` / ``{name: auto}`` and integration-test
the full server without bao or ntfy.

Token-refresher entries (``token_refresh:`` block) are also assembled
here — but their source/sink classes are looked up via the plugin
registry (entry points + dotted-path), not hardcoded. Built-ins ship
in ``mcp_hub.refresher.builtins``.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import httpx

from mcp_fanout import (
    ContainerFanout,
    Fanout,
    HttpFanout,
    IdentityConfig,
    VolumeMountSpec,
)

from .approvers.auto import AutoApprover
from .approvers.ntfy import NtfyApprover
from .approvers.registry import resolve_approver
from .approvers.reject import RejectApprover
from .approvers.store import (
    BaoTransientStore,
    InMemoryTransientStore,
    TransientStore,
)
from .auth_strategies import (
    DEFAULT_BAO_CACHE_TTL_S,
    DEFAULT_FANOUT_JWT_PATH,
    AuthStrategy,
    FanoutJwt,
    JwtPassthrough,
    NoneStrategy,
    SecretBearer,
)
from .bao_client import BaoClient
from .interfaces import Approver, SecretBackend, SecretRef
from .policy import AuthConfig, AuthStrategyConfig, HubConfig, IdentityPolicy, MCPConfig
from .refresher import (
    RefresherManager,
    TokenRefresher,
    resolve_sink,
    resolve_source,
)
from .secrets.bao import BaoSecretBackend
from .secrets.env import EnvSecretBackend
from .secrets.file import FileSecretBackend
from .secrets.registry import resolve_secret_backend


def build_secret_backend(
    config: HubConfig,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> SecretBackend:
    """Instantiate the secret backend selected in ``policy.yaml``.

    The backend *class* is resolved through the ``mcp_hub.secret_backends``
    plugin registry (entry points + dotted-path), so a third-party adapter
    works via ``secret_backend.name: my_pkg.MyBackend`` with no hub change.
    The built-ins (``env``/``file``/``bao``) keep their bespoke construction.
    """
    backend = config.secret_backend
    cls = resolve_secret_backend(backend.name)
    cfg = backend.config or {}

    if cls is EnvSecretBackend:
        return EnvSecretBackend()
    if cls is FileSecretBackend:
        return FileSecretBackend(
            path=_required_str(cfg, "path", "secret_backend.config.path")
        )
    if cls is BaoSecretBackend:
        addr = _required_str(cfg, "addr", "secret_backend.config.addr")
        kv_mount = cfg.get("kv_mount", "secret")
        auth = cfg.get("auth") or {}
        method = auth.get("method", "jwt")
        if method == "jwt":
            # JWT auth (default): the refresher writes a JWT the hub exchanges
            # for a per-(mcp,identity) Vault token. `role_jwt_path` stays
            # top-level for back-compat with existing policy.yaml.
            jwt_path = _required_str(
                cfg, "role_jwt_path", "secret_backend.config.role_jwt_path"
            )
            role_template = cfg.get("role_template", "mcp-{mcp}-{identity}")
            bao = BaoClient(
                addr=addr, jwt_path=jwt_path, kv_mount=kv_mount, http_client=http_client
            )
            return BaoSecretBackend(
                bao_client=bao, role_template=role_template, auth_method="jwt"
            )
        if method == "token":
            # Static-token auth: run Vault/OpenBao with no Authentik/JWT dance.
            # The token is read from a file — never inlined in policy.yaml.
            token_path = _required_str(
                auth, "token_path", "secret_backend.config.auth.token_path"
            )
            try:
                token = Path(token_path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ValueError(
                    f"secret_backend.config.auth.token_path: cannot read "
                    f"{token_path}: {exc}"
                ) from exc
            if not token:
                raise ValueError(
                    f"secret_backend.config.auth.token_path {token_path} is empty"
                )
            bao = BaoClient(addr=addr, kv_mount=kv_mount, http_client=http_client)
            return BaoSecretBackend(
                bao_client=bao, auth_method="token", static_token=token
            )
        raise ValueError(
            f"secret_backend.config.auth.method must be 'jwt' or 'token', got {method!r}"
        )

    # Third-party adapter (entry point or dotted-path): construct from config.
    return cls(**cfg)


def build_approver(
    config: HubConfig,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> Approver:
    """Instantiate the approver selected in ``policy.yaml``.

    The ``ntfy`` approver shares the bao address from ``secret_backend.config``
    (the homelab has one bao instance) but uses its own role + JWT path.
    """
    approver = config.approver
    cls = resolve_approver(approver.name)
    if cls is AutoApprover:
        return AutoApprover()
    if cls is RejectApprover:
        return RejectApprover()
    if cls is NtfyApprover:
        cfg = approver.config
        # Pending-approval store: bao-backed when bao_* config is present
        # (crash-safe across restarts), else in-memory (no external dependency,
        # so HITL needs no Vault). Reuses the secret_backend bao address.
        store: TransientStore
        if cfg.get("bao_jwt_path") or cfg.get("bao_role"):
            bao_addr = cfg.get("bao_addr") or _required_str(
                config.secret_backend.config,
                "addr",
                "secret_backend.config.addr (for approver to share)",
            )
            bao_jwt_path = _required_str(
                cfg, "bao_jwt_path", "approver.config.bao_jwt_path"
            )
            bao_role = _required_str(cfg, "bao_role", "approver.config.bao_role")
            store = BaoTransientStore(
                bao_client=BaoClient(
                    addr=bao_addr, jwt_path=bao_jwt_path, http_client=http_client
                ),
                bao_role=bao_role,
            )
        else:
            store = InMemoryTransientStore()
        # Accept either ``topic_template`` (recommended; supports
        # ``{identity}`` substitution per call) or ``topic`` (legacy
        # static name, no substitution). At least one must be set.
        topic_template = cfg.get("topic_template") or cfg.get("topic")
        if not isinstance(topic_template, str) or not topic_template:
            raise ValueError(
                "approver.config: provide either topic_template "
                "(e.g. 'mcp-hitl-{identity}') or topic (static)"
            )
        return NtfyApprover(
            store=store,
            ntfy_server=_required_str(cfg, "server", "approver.config.server"),
            topic_template=topic_template,
            publish_token_path=_required_str(
                cfg, "publish_token_path", "approver.config.publish_token_path"
            ),
            webhook_base_url=_required_str(
                cfg, "webhook_base_url", "approver.config.webhook_base_url"
            ),
            timeout_default_s=cfg.get("timeout_default_s", 120.0),
            ack_ttl_s=cfg.get("ack_ttl_s", 300),
            rate_limit_per_identity=cfg.get("rate_limit_per_identity", 5),
            http_client=http_client,
        )
    # Third-party approver (entry point or dotted-path): construct from config.
    return cls(**(approver.config or {}))


def _required_str(d: dict[str, object], key: str, label: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise ValueError(f"missing or non-string config value: {label}")
    return v


# ---------------------------------------------------------------------------
# Auth strategies (HTTP fanout)
# ---------------------------------------------------------------------------


def build_auth_strategy(
    *,
    mcp_name: str,
    config: AuthStrategyConfig,
    secret_backend: SecretBackend,
    mcp_identities: frozenset[str] = frozenset(),
    autonomous_identities: frozenset[str] = frozenset(),
) -> AuthStrategy:
    """Construct an :class:`AuthStrategy` from a policy config block.

    Dispatches on ``config.type``. Adding a new strategy: extend this
    function and document the new ``type`` in ``policy.example.yaml``.

    ``mcp_identities`` is the full set of identities registered with this MCP;
    ``autonomous_identities`` is the subset whose policy ``kind`` is
    ``autonomous``. For ``secret_bearer`` with ``as_agent: true`` these drive
    the per-identity as-agent behavior + the boot-capability flag.
    """
    cfg = config.config
    if config.type in ("secret_bearer", "bao_backed_bearer"):
        path_template = _required_str(
            cfg, "path_template", f"mcps.{mcp_name}.auth.config.path_template"
        )
        # field defaults to api_token to match the bao convention used
        # elsewhere in the homelab; explicit override allowed.
        field = cfg.get("field", "api_token")
        if not isinstance(field, str) or not field:
            raise ValueError(
                f"mcps.{mcp_name}.auth.config.field must be a non-empty string"
            )
        cache_ttl_raw = cfg.get("cache_ttl_s", DEFAULT_BAO_CACHE_TTL_S)
        try:
            cache_ttl_s = float(cache_ttl_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"mcps.{mcp_name}.auth.config.cache_ttl_s must be a number"
            ) from exc
        as_agent = cfg.get("as_agent", False)
        if not isinstance(as_agent, bool):
            raise ValueError(
                f"mcps.{mcp_name}.auth.config.as_agent must be a boolean"
            )
        # as-agent fires per-identity: only autonomous-kind identities, and
        # only when this MCP opts in. Delegated identities stay deputy.
        as_agent_identities = autonomous_identities if as_agent else frozenset()
        # Boot can run the deputy handshake unless EVERY identity is as-agent.
        boot_capable = not (
            bool(as_agent_identities) and as_agent_identities >= mcp_identities
        )
        return SecretBearer(
            secret_backend=secret_backend,
            mcp_name=mcp_name,
            path_template=path_template,
            field=field,
            cache_ttl_s=cache_ttl_s,
            as_agent_identities=as_agent_identities,
            boot_capable=boot_capable,
        )
    if config.type == "jwt_passthrough":
        if cfg:
            raise ValueError(
                f"mcps.{mcp_name}.auth.config: jwt_passthrough takes no config"
            )
        return JwtPassthrough()
    if config.type == "fanout_jwt":
        path = cfg.get("path", DEFAULT_FANOUT_JWT_PATH)
        if not isinstance(path, str) or not path:
            raise ValueError(
                f"mcps.{mcp_name}.auth.config.path must be a non-empty string"
            )
        # Reject unknown keys to catch typos at config-load rather than
        # silently ignoring them at runtime.
        unexpected = set(cfg) - {"path"}
        if unexpected:
            raise ValueError(
                f"mcps.{mcp_name}.auth.config: fanout_jwt takes only 'path'; "
                f"unexpected keys: {sorted(unexpected)}"
            )
        return FanoutJwt(path=path)
    if config.type == "none":
        if cfg:
            raise ValueError(
                f"mcps.{mcp_name}.auth.config: none takes no config"
            )
        return NoneStrategy()
    raise ValueError(
        f"mcps.{mcp_name}.auth.type: unknown strategy {config.type!r}"
    )


# ---------------------------------------------------------------------------
# Fanout dispatch
# ---------------------------------------------------------------------------


def _identities_for_http_mcp(
    mcp_name: str,
    identities: dict[str, IdentityPolicy],
) -> list[str]:
    """Identities allowed to call any tool of an HTTP MCP.

    HTTP MCPs don't need a per-identity ``secrets:`` entry (the auth
    strategy's path_template handles that). Membership is therefore
    derived from ``allowed_tools`` globs whose prefix matches the MCP
    name. An identity with ``allowed_tools: ["outline_*"]`` is
    registered with the ``outline`` HttpFanout.

    We use prefix-match-on-glob (split on first ``_``) consistent with
    :meth:`Policy.mcp_name_for_tool`. Wildcard-only globs like ``"*"``
    register the identity for every HTTP MCP, matching the stdio
    semantics where ``allowed_tools: ["*"]`` plus a ``secrets`` entry
    grants access to every MCP listed in secrets.
    """
    out: list[str] = []
    for name, ident in identities.items():
        for glob in ident.allowed_tools:
            prefix = glob.split("_", 1)[0]
            if prefix == mcp_name or prefix == "*":
                out.append(name)
                break
    return out


def build_fanout(
    mcp_name: str,
    mcp_config: MCPConfig,
    *,
    identities: dict[str, IdentityPolicy],
    secret_backend: SecretBackend,
    runtime_dir: Path,
    auth_config: AuthConfig | None = None,
    docker_client: object | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> Fanout | HttpFanout | ContainerFanout:
    """Dispatch to the right Fanout impl based on ``mcp_config.transport``.

    For ``stdio``: builds the per-identity :class:`IdentityConfig` list
    from each identity's ``secrets[mcp_name]`` entry.

    For ``http``: builds an :class:`HttpFanout` with the strategy from
    ``mcp_config.auth``. Identities are derived from ``allowed_tools``
    globs (no per-MCP secret entry required for HTTP).

    For ``container``: builds a :class:`ContainerFanout`. Requires
    ``docker_client`` (caller passes one shared instance — see
    :func:`build_docker_client`) and ``auth_config`` (for OIDC issuer +
    discovery URL injected into spawned wrappers). Identities are
    derived from ``allowed_tools`` globs, same as http transport.
    """
    if mcp_config.transport == "stdio":
        # Mypy: model_validator guaranteed these are non-None for stdio.
        assert mcp_config.command is not None
        assert mcp_config.secret_env_name is not None
        stdio_identities: list[IdentityConfig] = []
        for identity_name, identity_policy in identities.items():
            secret_model = identity_policy.secrets.get(mcp_name)
            if secret_model is None:
                continue
            ref = SecretRef(path=secret_model.path, field=secret_model.field)
            uid = identity_policy.uid_base + mcp_config.uid_offset
            stdio_identities.append(
                IdentityConfig(
                    identity=identity_name,
                    uid=uid,
                    ref=ref,
                    secret_env_name=mcp_config.secret_env_name,
                )
            )
        if not stdio_identities:
            raise ValueError(
                f"MCP {mcp_name!r} (stdio) is configured but no identity has "
                f"a secret entry for it"
            )
        return Fanout(
            mcp_name=mcp_name,
            command=list(mcp_config.command),
            identities=stdio_identities,
            secret_backend=secret_backend,
            runtime_dir=runtime_dir,
            extra_env=mcp_config.extra_env,
        )

    if mcp_config.transport == "http":
        assert mcp_config.url is not None
        assert mcp_config.auth is not None
        http_identities = _identities_for_http_mcp(mcp_name, identities)
        if not http_identities:
            raise ValueError(
                f"MCP {mcp_name!r} (http) is configured but no identity's "
                f"allowed_tools globs cover it (no glob with prefix "
                f"{mcp_name!r} or '*')"
            )
        autonomous = frozenset(
            n for n in http_identities if identities[n].kind == "autonomous"
        )
        strategy = build_auth_strategy(
            mcp_name=mcp_name,
            config=mcp_config.auth,
            secret_backend=secret_backend,
            mcp_identities=frozenset(http_identities),
            autonomous_identities=autonomous,
        )
        # Order delegated-first so HttpFanout's boot identity (identities[0])
        # can run the deputy boot handshake whenever a delegated identity
        # exists (as-agent identities can't authenticate at boot).
        ordered_identities = [
            n for n in http_identities if n not in autonomous
        ] + [n for n in http_identities if n in autonomous]
        return HttpFanout(
            mcp_name=mcp_name,
            url=mcp_config.url,
            auth_strategy=strategy,
            identities=ordered_identities,
            http_client=http_client,
        )

    # container transport
    assert mcp_config.image is not None
    assert mcp_config.auth is not None
    if docker_client is None:
        raise ValueError(
            f"MCP {mcp_name!r} (container) requires a docker client; "
            f"caller must pass docker_client= (typically constructed via "
            f"build_docker_client())"
        )
    if auth_config is None:
        raise ValueError(
            f"MCP {mcp_name!r} (container) requires auth_config= (for OIDC "
            f"issuer + discovery URL passed into spawned wrappers)"
        )
    container_identities = _identities_for_http_mcp(mcp_name, identities)
    if not container_identities:
        raise ValueError(
            f"MCP {mcp_name!r} (container) is configured but no identity's "
            f"allowed_tools globs cover it (no glob with prefix "
            f"{mcp_name!r} or '*')"
        )
    container_autonomous = frozenset(
        n for n in container_identities if identities[n].kind == "autonomous"
    )
    container_strategy = build_auth_strategy(
        mcp_name=mcp_name,
        config=mcp_config.auth,
        secret_backend=secret_backend,
        mcp_identities=frozenset(container_identities),
        autonomous_identities=container_autonomous,
    )
    if auth_config.oidc_discovery_url is None:
        raise ValueError(
            f"MCP {mcp_name!r} (container): policy.auth.oidc_discovery_url "
            f"must be set when any container-transport MCP is configured "
            f"(spawned wrappers fetch JWKS from it)"
        )
    secrets_to_env = {
        env_var: SecretRef(path=ref.path, field=ref.field)
        for env_var, ref in mcp_config.secrets_to_env.items()
    }
    volumes_per_identity = [
        VolumeMountSpec(
            container_path=vm.container_path,
            volume_name_template=vm.volume_name_template,
        )
        for vm in mcp_config.volumes_per_identity
    ]
    return ContainerFanout(
        mcp_name=mcp_name,
        image=mcp_config.image,
        scope=mcp_config.scope,
        identities=container_identities,
        oidc_issuer=auth_config.issuer,
        oidc_discovery_url=auth_config.oidc_discovery_url,
        audience_template=mcp_config.audience_template,
        env=mcp_config.env,
        secrets_to_env=secrets_to_env,
        volumes_per_identity=volumes_per_identity,
        auth_strategy=container_strategy,
        secret_backend=secret_backend,
        docker_client=docker_client,
        idle_timeout_s=mcp_config.idle_timeout_s,
        spawn_timeout_s=mcp_config.spawn_timeout_s,
        eviction_interval_s=mcp_config.eviction_interval_s,
        http_client=http_client,
    )


def build_docker_client(env_overrides: dict[str, str] | None = None) -> object:
    """Construct a Docker SDK client from env (DOCKER_HOST, DOCKER_TLS_VERIFY, DOCKER_CERT_PATH).

    Returns ``Any`` to keep ``factory.py``'s top-level imports clean of the
    docker SDK in case some deploys never enable container-transport MCPs.
    Caller passes the result to :func:`build_fanout` for container MCPs.
    """
    import os

    import docker

    if env_overrides:
        # Apply overrides only for this client construction; restore after.
        # In practice the orchestrator just relies on the deploy-time env
        # of the hub container.
        for k, v in env_overrides.items():
            os.environ[k] = v
    return docker.from_env(version="auto", timeout=10)


# ---------------------------------------------------------------------------
# Token refresher
# ---------------------------------------------------------------------------


_DURATION_UNITS = {"seconds", "minutes", "hours", "days", "weeks"}


def parse_duration(s: str) -> timedelta:
    """Parse a ``"unit=N"`` duration string into a timedelta.

    Examples: ``"seconds=30"``, ``"minutes=10"``, ``"days=1"``. Matches
    the format Authentik uses for its own durations, which is the
    convention the rest of this codebase follows.
    """
    if not isinstance(s, str) or "=" not in s:
        raise ValueError(
            f"duration must be a 'unit=N' string (e.g. 'minutes=10'), got {s!r}"
        )
    unit, _, n_str = s.partition("=")
    unit = unit.strip()
    if unit not in _DURATION_UNITS:
        raise ValueError(
            f"unknown duration unit {unit!r}; valid: {sorted(_DURATION_UNITS)}"
        )
    try:
        n = int(n_str)
    except ValueError as exc:
        raise ValueError(
            f"duration value must be an integer, got {n_str!r}"
        ) from exc
    if n < 0:
        raise ValueError(f"duration must be non-negative, got {n}")
    return timedelta(**{unit: n})


def build_refresher_manager(config: HubConfig) -> RefresherManager:
    """Instantiate every ``token_refresh.<name>`` entry into a manager.

    Plugin classes are looked up via the registry (entry points first,
    dotted-path fallback). Each plugin's ``config`` dict is passed as
    ``**kwargs`` to its constructor — kwarg validation belongs to the
    plugin, not here.
    """
    refreshers: list[TokenRefresher] = []
    for name, rc in config.token_refresh.items():
        try:
            source_cls = resolve_source(rc.source.type)
            source = source_cls(**rc.source.config)
        except Exception as exc:
            raise ValueError(
                f"token_refresh.{name}.source: failed to build source "
                f"{rc.source.type!r}: {exc}"
            ) from exc
        try:
            sink_cls = resolve_sink(rc.sink.type)
            sink = sink_cls(**rc.sink.config)
        except Exception as exc:
            # Source is orphaned but interpreter exit at startup-fail
            # path will tear it down; httpx will warn about the unclosed
            # client, which is the right loud signal for a config bug.
            raise ValueError(
                f"token_refresh.{name}.sink: failed to build sink "
                f"{rc.sink.type!r}: {exc}"
            ) from exc
        refreshers.append(
            TokenRefresher(
                name=name,
                source=source,
                sink=sink,
                rotate_every=parse_duration(rc.rotate_every),
                safety_buffer=parse_duration(rc.safety_buffer),
                initial_backoff=parse_duration(rc.initial_backoff),
                max_backoff=parse_duration(rc.max_backoff),
            )
        )
    return RefresherManager(refreshers=refreshers)
