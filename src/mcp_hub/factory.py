"""Config → backend instances.

The hub picks ``SecretBackend`` and ``Approver`` implementations at
startup based on ``policy.yaml``'s ``secret_backend.name`` and
``approver.name`` strings. This module is the single dispatch point —
all "if name == 'bao': ..." branching lives here, not scattered.

Both production and test fakes are wired here so tests can drop the
hub config into ``{name: env}`` / ``{name: auto}`` and integration-test
the full server without bao or ntfy.
"""

from __future__ import annotations

import httpx

from .approvers.auto import AutoApprover
from .approvers.ntfy import NtfyApprover
from .approvers.reject import RejectApprover
from .bao_client import BaoClient
from .interfaces import Approver, SecretBackend
from .policy import HubConfig
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
