"""Tests for :func:`mcp_hub.factory.build_fanout` and helpers.

The factory is the single dispatch point that turns policy MCP entries
into Fanout / HttpFanout instances. We verify both branches and the
auth-strategy dispatcher.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from mcp_fanout import Fanout, HttpFanout
from mcp_hub.auth_strategies import (
    BaoBackedBearer,
    JwtPassthrough,
    NoneStrategy,
    SecretBearer,
)
from mcp_hub.factory import build_auth_strategy, build_fanout
from mcp_hub.policy import AuthStrategyConfig, HubConfig, MCPConfig
from mcp_hub.secrets.env import EnvSecretBackend
from tests.unit.test_policy import MINIMAL

# ---------------------------------------------------------------------------
# build_auth_strategy
# ---------------------------------------------------------------------------


def test_build_auth_strategy_bao_backed_bearer() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(
        type="bao_backed_bearer",
        config={
            "path_template": "services/outline/{identity}",
            "field": "api_token",
        },
    )
    strategy = build_auth_strategy(
        mcp_name="outline", config=cfg, secret_backend=backend
    )
    assert isinstance(strategy, BaoBackedBearer)


def test_build_auth_strategy_secret_bearer() -> None:
    # `secret_bearer` is the canonical name; `bao_backed_bearer` is the alias.
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(
        type="secret_bearer",
        config={"path_template": "services/outline/{identity}"},
    )
    strategy = build_auth_strategy(
        mcp_name="outline", config=cfg, secret_backend=backend
    )
    assert isinstance(strategy, BaoBackedBearer)  # alias for SecretBearer
    assert strategy.name == "secret_bearer"


# ---------------------------------------------------------------------------
# build_auth_strategy — as-agent derivation
# ---------------------------------------------------------------------------


def test_build_auth_strategy_as_agent_marks_autonomous_identities() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(
        type="secret_bearer",
        config={"path_template": "services/outline/{identity}", "as_agent": True},
    )
    strategy = build_auth_strategy(
        mcp_name="outline",
        config=cfg,
        secret_backend=backend,
        mcp_identities=frozenset({"interactive", "alfred"}),
        autonomous_identities=frozenset({"alfred"}),
    )
    assert isinstance(strategy, SecretBearer)
    # Only the autonomous identity authenticates as-agent.
    assert strategy._as_agent_identities == frozenset({"alfred"})
    # A delegated identity (interactive) exists → boot can run the deputy handshake.
    assert strategy.boot_capable is True


def test_build_auth_strategy_without_as_agent_marks_none() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(
        type="secret_bearer",
        config={"path_template": "services/outline/{identity}"},
    )
    strategy = build_auth_strategy(
        mcp_name="outline",
        config=cfg,
        secret_backend=backend,
        mcp_identities=frozenset({"interactive", "alfred"}),
        autonomous_identities=frozenset({"alfred"}),
    )
    assert isinstance(strategy, SecretBearer)
    # as_agent not set → nobody authenticates as-agent (all deputy).
    assert strategy._as_agent_identities == frozenset()
    assert strategy.boot_capable is True


def test_build_auth_strategy_all_autonomous_not_boot_capable() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(
        type="secret_bearer",
        config={"path_template": "services/outline/{identity}", "as_agent": True},
    )
    strategy = build_auth_strategy(
        mcp_name="outline",
        config=cfg,
        secret_backend=backend,
        mcp_identities=frozenset({"alfred"}),
        autonomous_identities=frozenset({"alfred"}),
    )
    assert isinstance(strategy, SecretBearer)
    # Every identity is as-agent → no delegated identity to boot-handshake with.
    assert strategy.boot_capable is False


def test_build_auth_strategy_as_agent_must_be_bool() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(
        type="secret_bearer",
        config={"path_template": "services/outline/{identity}", "as_agent": "yes"},
    )
    with pytest.raises(ValueError, match="as_agent must be a boolean"):
        build_auth_strategy(mcp_name="outline", config=cfg, secret_backend=backend)


def test_build_auth_strategy_bao_backed_bearer_requires_path_template() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(type="bao_backed_bearer", config={})
    with pytest.raises(ValueError, match="path_template"):
        build_auth_strategy(
            mcp_name="outline", config=cfg, secret_backend=backend
        )


def test_build_auth_strategy_jwt_passthrough() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(type="jwt_passthrough", config={})
    strategy = build_auth_strategy(
        mcp_name="outline", config=cfg, secret_backend=backend
    )
    assert isinstance(strategy, JwtPassthrough)


def test_build_auth_strategy_jwt_passthrough_rejects_config() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(type="jwt_passthrough", config={"x": 1})
    with pytest.raises(ValueError, match="no config"):
        build_auth_strategy(
            mcp_name="outline", config=cfg, secret_backend=backend
        )


def test_build_auth_strategy_unknown_type() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(type="oauth_pkce_flow", config={})
    with pytest.raises(ValueError, match="unknown strategy"):
        build_auth_strategy(
            mcp_name="outline", config=cfg, secret_backend=backend
        )


def test_build_auth_strategy_none() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(type="none", config={})
    strategy = build_auth_strategy(
        mcp_name="ha", config=cfg, secret_backend=backend
    )
    assert isinstance(strategy, NoneStrategy)


def test_build_auth_strategy_none_rejects_config() -> None:
    backend = EnvSecretBackend()
    cfg = AuthStrategyConfig(type="none", config={"x": 1})
    with pytest.raises(ValueError, match="no config"):
        build_auth_strategy(
            mcp_name="ha", config=cfg, secret_backend=backend
        )


# ---------------------------------------------------------------------------
# build_fanout: stdio
# ---------------------------------------------------------------------------


def test_build_fanout_stdio_returns_stdio_fanout(tmp_path: Path) -> None:
    """A stdio-transport MCP entry produces a :class:`Fanout`."""
    cfg = HubConfig.model_validate(MINIMAL)
    backend = EnvSecretBackend()
    fanout = build_fanout(
        "technitium",
        cfg.mcps["technitium"],
        identities=cfg.identities,
        secret_backend=backend,
        runtime_dir=tmp_path,
    )
    assert isinstance(fanout, Fanout)
    assert fanout.mcp_name == "technitium"
    assert "ironclaw" in fanout.identities


def test_build_fanout_stdio_skips_identities_without_secret(
    tmp_path: Path,
) -> None:
    """Identities without a ``secrets:`` entry for the MCP are dropped."""
    raw = copy.deepcopy(MINIMAL)
    raw["identities"]["other"] = {  # type: ignore[index]
        "aud": "mcp-other",
        "uid_base": 9999,
        "allowed_tools": ["technitium_dns_*"],
        "hitl": {"defaults": "auto-approve"},
        "secrets": {},  # no secret for technitium
    }
    cfg = HubConfig.model_validate(raw)
    fanout = build_fanout(
        "technitium",
        cfg.mcps["technitium"],
        identities=cfg.identities,
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
    )
    # 'other' had no secret entry → not registered
    assert isinstance(fanout, Fanout)
    assert "other" not in fanout.identities
    assert "ironclaw" in fanout.identities


# ---------------------------------------------------------------------------
# build_fanout: http
# ---------------------------------------------------------------------------


def test_build_fanout_http_returns_http_fanout(tmp_path: Path) -> None:
    """An http-transport MCP entry produces an :class:`HttpFanout`."""
    raw = copy.deepcopy(MINIMAL)
    raw["mcps"]["outline"] = {  # type: ignore[index]
        "transport": "http",
        "url": "https://outline.example/mcp",
        "auth": {
            "type": "bao_backed_bearer",
            "config": {
                "path_template": "services/outline/{identity}",
                "field": "api_token",
            },
        },
    }
    raw["identities"]["ironclaw"]["allowed_tools"].append("outline_*")  # type: ignore[index]
    cfg = HubConfig.model_validate(raw)
    fanout = build_fanout(
        "outline",
        cfg.mcps["outline"],
        identities=cfg.identities,
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
    )
    assert isinstance(fanout, HttpFanout)
    assert fanout.mcp_name == "outline"
    assert "ironclaw" in fanout.identities


def test_build_fanout_http_includes_identities_with_wildcard_glob(
    tmp_path: Path,
) -> None:
    """An identity with ``allowed_tools: ["*"]`` is registered with every HTTP MCP."""
    raw = copy.deepcopy(MINIMAL)
    raw["mcps"]["outline"] = {  # type: ignore[index]
        "transport": "http",
        "url": "https://outline.example/mcp",
        "auth": {"type": "jwt_passthrough"},
    }
    raw["identities"]["root"] = {  # type: ignore[index]
        "aud": "mcp-root",
        "uid_base": 9999,
        "allowed_tools": ["*"],
        "hitl": {"defaults": "auto-approve"},
        "secrets": {},
    }
    cfg = HubConfig.model_validate(raw)
    fanout = build_fanout(
        "outline",
        cfg.mcps["outline"],
        identities=cfg.identities,
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
    )
    assert isinstance(fanout, HttpFanout)
    assert "root" in fanout.identities


def test_build_fanout_http_no_eligible_identities_raises(tmp_path: Path) -> None:
    """An HTTP MCP with no identity covering it raises a clear error."""
    # Need a 2nd MCP since we cant remove 'technitium' (allowed_tools refers
    # to it). Build a config where 'outline' exists but no glob covers it.
    raw = copy.deepcopy(MINIMAL)
    raw["mcps"]["outline"] = {  # type: ignore[index]
        "transport": "http",
        "url": "https://outline.example/mcp",
        "auth": {"type": "jwt_passthrough"},
    }
    # Don't add an outline_* glob to any identity.
    cfg = HubConfig.model_validate(raw)
    with pytest.raises(ValueError, match="no identity"):
        build_fanout(
            "outline",
            cfg.mcps["outline"],
            identities=cfg.identities,
            secret_backend=EnvSecretBackend(),
            runtime_dir=tmp_path,
        )


def test_build_fanout_unknown_transport_unreachable() -> None:
    """Pydantic's Literal validation prevents unknown transports earlier."""
    # The discriminator is enforced at MCPConfig validation; an invalid
    # transport never reaches build_fanout. We assert the invariant
    # holds at the schema layer.
    with pytest.raises(Exception):
        MCPConfig.model_validate(
            {
                "transport": "websocket",
                "command": ["x"],
                "secret_env_name": "X",
            }
        )


# ---------------------------------------------------------------------------
# build_fanout: container
# ---------------------------------------------------------------------------


def _container_minimal_raw() -> dict[str, object]:
    """Build a copy of MINIMAL with a `heb` container-transport MCP added.

    Adds an identity glob covering it so the dispatcher doesn't reject as
    "no eligible identities".
    """
    raw = copy.deepcopy(MINIMAL)
    raw["auth"]["oidc_discovery_url"] = (  # type: ignore[index]
        "https://auth.example/application/o/mcp-fanout-svc"
    )
    raw["mcps"]["heb"] = {  # type: ignore[index]
        "transport": "container",
        "image": "mcp-pape-house/heb-mcp-wrapper:test",
        "scope": "per-identity",
        "auth": {"type": "jwt_passthrough"},
        "env": {"MCP_COMMAND": "texas-grocery-mcp"},
        "secrets_to_env": {
            "HEB_PROXY_TOKEN": {
                "path": "services/heb/{identity}",
                "field": "api_token",
            },
        },
    }
    raw["identities"]["ironclaw"]["allowed_tools"].append("heb_*")  # type: ignore[index]
    return raw


def test_build_fanout_container_returns_container_fanout(tmp_path: Path) -> None:
    """A container-transport MCP entry produces a :class:`ContainerFanout`."""
    from mcp_fanout import ContainerFanout

    cfg = HubConfig.model_validate(_container_minimal_raw())
    fanout = build_fanout(
        "heb",
        cfg.mcps["heb"],
        identities=cfg.identities,
        secret_backend=EnvSecretBackend(),
        runtime_dir=tmp_path,
        auth_config=cfg.auth,
        docker_client=object(),  # ContainerFanout doesn't ping at construction
    )
    assert isinstance(fanout, ContainerFanout)
    assert fanout.mcp_name == "heb"
    assert "ironclaw" in fanout.identities


def test_build_fanout_container_requires_docker_client(tmp_path: Path) -> None:
    """Container transport without a docker_client kwarg raises clearly."""
    cfg = HubConfig.model_validate(_container_minimal_raw())
    with pytest.raises(ValueError, match="requires a docker client"):
        build_fanout(
            "heb",
            cfg.mcps["heb"],
            identities=cfg.identities,
            secret_backend=EnvSecretBackend(),
            runtime_dir=tmp_path,
            auth_config=cfg.auth,
            docker_client=None,
        )


def test_build_fanout_container_requires_auth_config(tmp_path: Path) -> None:
    """Container transport without auth_config (for OIDC injection) raises clearly."""
    cfg = HubConfig.model_validate(_container_minimal_raw())
    with pytest.raises(ValueError, match="requires auth_config"):
        build_fanout(
            "heb",
            cfg.mcps["heb"],
            identities=cfg.identities,
            secret_backend=EnvSecretBackend(),
            runtime_dir=tmp_path,
            auth_config=None,
            docker_client=object(),
        )


def test_build_fanout_container_requires_oidc_discovery_url(tmp_path: Path) -> None:
    """If no oidc_discovery_url is set on auth, container builds fail clearly."""
    raw = _container_minimal_raw()
    raw["auth"].pop("oidc_discovery_url", None)  # type: ignore[attr-defined]
    cfg = HubConfig.model_validate(raw)
    with pytest.raises(ValueError, match="oidc_discovery_url"):
        build_fanout(
            "heb",
            cfg.mcps["heb"],
            identities=cfg.identities,
            secret_backend=EnvSecretBackend(),
            runtime_dir=tmp_path,
            auth_config=cfg.auth,
            docker_client=object(),
        )
