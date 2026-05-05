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

import httpx

from .approvers.auto import AutoApprover
from .approvers.ntfy import NtfyApprover
from .approvers.reject import RejectApprover
from .bao_client import BaoClient
from .interfaces import Approver, SecretBackend
from .policy import HubConfig
from .refresher import (
    RefresherManager,
    TokenRefresher,
    resolve_sink,
    resolve_source,
)
from .secrets.bao import BaoSecretBackend
from .secrets.env import EnvSecretBackend


def build_secret_backend(
    config: HubConfig,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> SecretBackend:
    """Instantiate the secret backend selected in ``policy.yaml``."""
    backend = config.secret_backend
    name = backend.name
    if name == "env":
        return EnvSecretBackend()
    if name == "bao":
        cfg = backend.config
        addr = _required_str(cfg, "addr", "secret_backend.config.addr")
        jwt_path = _required_str(cfg, "role_jwt_path", "secret_backend.config.role_jwt_path")
        kv_mount = cfg.get("kv_mount", "secret")
        role_template = cfg.get("role_template", "mcp-{mcp}-{identity}")
        bao = BaoClient(
            addr=addr,
            jwt_path=jwt_path,
            kv_mount=kv_mount,
            http_client=http_client,
        )
        return BaoSecretBackend(bao_client=bao, role_template=role_template)
    raise ValueError(f"unknown secret_backend.name: {name!r}")


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
    name = approver.name
    if name == "auto":
        return AutoApprover()
    if name == "reject":
        return RejectApprover()
    if name == "ntfy":
        cfg = approver.config
        # Reuse bao address from secret_backend; per-approver bao_addr override
        # is accepted but uncommon (one bao instance in the homelab).
        bao_addr = cfg.get("bao_addr") or _required_str(
            config.secret_backend.config,
            "addr",
            "secret_backend.config.addr (for approver to share)",
        )
        bao_jwt_path = _required_str(cfg, "bao_jwt_path", "approver.config.bao_jwt_path")
        bao_role = _required_str(cfg, "bao_role", "approver.config.bao_role")
        bao = BaoClient(
            addr=bao_addr,
            jwt_path=bao_jwt_path,
            http_client=http_client,
        )
        return NtfyApprover(
            bao_client=bao,
            bao_role=bao_role,
            ntfy_server=_required_str(cfg, "server", "approver.config.server"),
            ntfy_topic=_required_str(cfg, "topic", "approver.config.topic"),
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
    raise ValueError(f"unknown approver.name: {name!r}")


def _required_str(d: dict[str, object], key: str, label: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise ValueError(f"missing or non-string config value: {label}")
    return v


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
