"""Tests for HTTP-transport MCP entries in policy.yaml.

The schema validation around stdio vs http transport is a usability
gate: bad configs should fail at load, with a message that points at
the missing field.
"""

from __future__ import annotations

import copy

import pytest

from mcp_hub.policy import HubConfig, MCPConfig
from tests.unit.test_policy import MINIMAL


def _http_mcp() -> dict[str, object]:
    """A minimal valid http-transport MCP entry."""
    return {
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


def test_stdio_transport_default_when_omitted() -> None:
    """Existing configs without ``transport:`` continue to validate as stdio."""
    cfg = HubConfig.model_validate(MINIMAL)
    assert cfg.mcps["technitium"].transport == "stdio"


def test_http_mcp_validates() -> None:
    raw = copy.deepcopy(MINIMAL)
    raw["mcps"]["outline"] = _http_mcp()  # type: ignore[index]
    raw["identities"]["ironclaw"]["allowed_tools"].append("outline_*")  # type: ignore[index]
    cfg = HubConfig.model_validate(raw)
    outline = cfg.mcps["outline"]
    assert outline.transport == "http"
    assert outline.url == "https://outline.example/mcp"
    assert outline.auth is not None
    assert outline.auth.type == "bao_backed_bearer"


def test_http_mcp_rejects_stdio_only_command_field() -> None:
    bad = _http_mcp()
    bad["command"] = ["node", "x.js"]
    with pytest.raises(Exception, match="stdio-only"):
        MCPConfig.model_validate(bad)


def test_http_mcp_rejects_stdio_only_secret_env_name() -> None:
    bad = _http_mcp()
    bad["secret_env_name"] = "FOO"
    with pytest.raises(Exception, match="stdio-only"):
        MCPConfig.model_validate(bad)


def test_http_mcp_requires_url() -> None:
    bad = _http_mcp()
    del bad["url"]
    with pytest.raises(Exception, match="url"):
        MCPConfig.model_validate(bad)


def test_http_mcp_requires_auth() -> None:
    bad = _http_mcp()
    del bad["auth"]
    with pytest.raises(Exception, match="auth"):
        MCPConfig.model_validate(bad)


def test_http_mcp_rejects_non_http_url() -> None:
    bad = _http_mcp()
    bad["url"] = "ftp://nope.example"
    with pytest.raises(Exception, match="http"):
        MCPConfig.model_validate(bad)


def test_stdio_mcp_rejects_url_field() -> None:
    bad = {
        "command": ["node", "x.js"],
        "secret_env_name": "X",
        "url": "https://x",
    }
    with pytest.raises(Exception, match="http-only"):
        MCPConfig.model_validate(bad)


def test_jwt_passthrough_strategy_validates() -> None:
    raw = copy.deepcopy(MINIMAL)
    raw["mcps"]["outline"] = {  # type: ignore[index]
        "transport": "http",
        "url": "https://outline.example/mcp",
        "auth": {"type": "jwt_passthrough"},
    }
    raw["identities"]["ironclaw"]["allowed_tools"].append("outline_*")  # type: ignore[index]
    cfg = HubConfig.model_validate(raw)
    assert cfg.mcps["outline"].auth is not None
    assert cfg.mcps["outline"].auth.type == "jwt_passthrough"


# ---------------------------------------------------------------------------
# Container-transport schema
# ---------------------------------------------------------------------------


def _container_mcp() -> dict[str, object]:
    """A minimal valid container-transport MCP entry."""
    return {
        "transport": "container",
        "image": "mcp-pape-house/heb-mcp-wrapper:test",
        "auth": {"type": "jwt_passthrough"},
    }


def test_container_mcp_validates_with_defaults() -> None:
    cfg = MCPConfig.model_validate(_container_mcp())
    assert cfg.transport == "container"
    assert cfg.scope == "per-identity"
    assert cfg.idle_timeout_s == 1200.0
    assert cfg.audience_template == "mcp-{identity}"
    assert cfg.env == {}
    assert cfg.secrets_to_env == {}


def test_container_mcp_validates_with_full_config() -> None:
    raw = _container_mcp() | {
        "scope": "shared",
        "idle_timeout_s": 600.0,
        "spawn_timeout_s": 30.0,
        "eviction_interval_s": 30.0,
        "audience_template": "homelab-{identity}",
        "env": {"MCP_COMMAND": "texas-grocery-mcp", "HEB_DEFAULT_STORE": "590"},
        "secrets_to_env": {
            "HEB_PROXY_TOKEN": {"path": "services/heb/{identity}", "field": "api_token"},
        },
    }
    cfg = MCPConfig.model_validate(raw)
    assert cfg.scope == "shared"
    assert cfg.idle_timeout_s == 600.0
    assert cfg.audience_template == "homelab-{identity}"
    assert cfg.env["HEB_DEFAULT_STORE"] == "590"
    assert "HEB_PROXY_TOKEN" in cfg.secrets_to_env
    assert cfg.secrets_to_env["HEB_PROXY_TOKEN"].path == "services/heb/{identity}"


def test_container_mcp_requires_image() -> None:
    bad = _container_mcp()
    del bad["image"]
    with pytest.raises(Exception, match="image"):
        MCPConfig.model_validate(bad)


def test_container_mcp_requires_auth() -> None:
    bad = _container_mcp()
    del bad["auth"]
    with pytest.raises(Exception, match="auth"):
        MCPConfig.model_validate(bad)


def test_container_mcp_rejects_stdio_command_field() -> None:
    bad = _container_mcp()
    bad["command"] = ["node", "x.js"]
    with pytest.raises(Exception, match="stdio-only"):
        MCPConfig.model_validate(bad)


def test_container_mcp_rejects_http_url_field() -> None:
    bad = _container_mcp()
    bad["url"] = "https://x"
    with pytest.raises(Exception, match="http-only"):
        MCPConfig.model_validate(bad)


def test_container_mcp_rejects_zero_idle_timeout() -> None:
    bad = _container_mcp()
    bad["idle_timeout_s"] = 0
    with pytest.raises(Exception, match="idle_timeout_s"):
        MCPConfig.model_validate(bad)


def test_container_mcp_rejects_audience_template_without_placeholder() -> None:
    bad = _container_mcp()
    bad["audience_template"] = "fixed-audience"
    with pytest.raises(Exception, match="\\{identity\\}"):
        MCPConfig.model_validate(bad)


def test_stdio_mcp_rejects_image_field() -> None:
    bad = {
        "command": ["node", "x.js"],
        "secret_env_name": "X",
        "image": "some-image",
    }
    with pytest.raises(Exception, match="container-only"):
        MCPConfig.model_validate(bad)


def test_http_mcp_rejects_image_field() -> None:
    bad = {
        "transport": "http",
        "url": "https://x.example/mcp",
        "auth": {"type": "jwt_passthrough"},
        "image": "some-image",
    }
    with pytest.raises(Exception, match="container-only"):
        MCPConfig.model_validate(bad)


# ---------------------------------------------------------------------------
# volumes_per_identity (container transport)
# ---------------------------------------------------------------------------


def test_container_mcp_volumes_per_identity_validates() -> None:
    """Per-identity volumes are allowed when scope=per-identity and the template has {identity}."""
    raw = _container_mcp() | {
        "scope": "per-identity",
        "volumes_per_identity": [
            {
                "container_path": "/home/appuser/.texas-grocery-mcp",
                "volume_name_template": "heb-state-{identity}",
            },
        ],
    }
    cfg = MCPConfig.model_validate(raw)
    assert len(cfg.volumes_per_identity) == 1
    assert cfg.volumes_per_identity[0].container_path == "/home/appuser/.texas-grocery-mcp"
    assert cfg.volumes_per_identity[0].volume_name_template == "heb-state-{identity}"


def test_container_mcp_per_identity_rejects_volume_template_without_placeholder() -> None:
    """A per-identity volume mount missing {identity} would collide all identities — reject."""
    bad = _container_mcp() | {
        "scope": "per-identity",
        "volumes_per_identity": [
            {"container_path": "/data", "volume_name_template": "heb-state"},
        ],
    }
    with pytest.raises(Exception, match=r"\{identity\}"):
        MCPConfig.model_validate(bad)


def test_container_mcp_shared_scope_allows_static_volume_name() -> None:
    """Shared-scope containers can use a static volume name (only one container exists)."""
    raw = _container_mcp() | {
        "scope": "shared",
        "volumes_per_identity": [
            {"container_path": "/data", "volume_name_template": "tech-state"},
        ],
    }
    cfg = MCPConfig.model_validate(raw)
    assert cfg.volumes_per_identity[0].volume_name_template == "tech-state"


def test_stdio_mcp_rejects_volumes_field() -> None:
    bad = {
        "command": ["node", "x.js"],
        "secret_env_name": "X",
        "volumes_per_identity": [
            {"container_path": "/data", "volume_name_template": "x"},
        ],
    }
    with pytest.raises(Exception, match="container-only"):
        MCPConfig.model_validate(bad)


def test_http_mcp_rejects_volumes_field() -> None:
    bad = {
        "transport": "http",
        "url": "https://x.example/mcp",
        "auth": {"type": "jwt_passthrough"},
        "volumes_per_identity": [
            {"container_path": "/data", "volume_name_template": "x"},
        ],
    }
    with pytest.raises(Exception, match="container-only"):
        MCPConfig.model_validate(bad)
