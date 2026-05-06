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
