"""Upstream tool properties that aren't Python identifiers (``from``, ``a-b``).

The hub forges a Python signature from each upstream tool's input schema so
FastMCP can validate calls. A property named like a Python keyword used to
raise ``ValueError: 'from' is not a valid parameter name`` at tool
registration, aborting hub startup.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mcp_hub.audit import Audit
from mcp_hub.policy import Policy
from mcp_hub.server import Hub, _python_param_names

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_valid_names_map_to_themselves() -> None:
    assert _python_param_names(["query", "limit", "dryRun"]) == {
        "query": "query",
        "limit": "limit",
        "dryRun": "dryRun",
    }


def test_keywords_and_non_identifiers_get_unique_safe_names() -> None:
    names = _python_param_names(["from", "to", "from_", "dry-run", "1st", "class"])
    assert names["to"] == "to"
    assert names["from_"] == "from_"  # a real property keeps its name...
    assert names["from"] == "from__"  # ...so the renamed keyword can't collide
    assert names["dry-run"] == "dry_run_"
    assert names["1st"] == "p_1st_"
    assert names["class"] == "class_"
    assert len(set(names.values())) == len(names)
    assert all(n.isidentifier() for n in names.values())


class _RecordingFanout:
    mcp_name = "finance"
    identities = ("agent",)

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    async def call(self, *, identity: str, request: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(request)
        return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}}


class _Ctx:
    def get_state(self, key: str) -> Any:
        return {"identity": "agent"}.get(key)


@pytest.fixture
def hub() -> Hub:
    return Hub(
        policy=Policy.from_yaml(REPO_ROOT / "policy.example.minimal.yaml"),
        secret_backend=MagicMock(),
        approver=MagicMock(),
        validator=MagicMock(),
        audit=Audit(),
        runtime_dir=Path("/tmp"),
    )


async def test_keyword_property_registers_and_forwards_upstream_name(
    hub: Hub, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("fastmcp.server.dependencies.get_context", lambda: _Ctx())
    fanout = _RecordingFanout()
    schema = {
        "type": "object",
        "properties": {
            "from": {"type": "string"},
            "to": {"type": "string"},
            "dry-run": {"type": "boolean"},
        },
        "required": ["from"],
    }

    hub._register_one_tool(
        "finance",
        fanout,  # type: ignore[arg-type]  # duck-typed stdio-style fanout
        {"name": "cashFlow", "description": "d", "inputSchema": schema},
    )

    tool = await hub.mcp._tool_manager.get_tool("finance_cashFlow")
    # The agent sees the upstream's own field names.
    assert set(tool.parameters["properties"]) >= {"from", "to", "dry-run"}

    await tool.run({"from": "2026-01-01", "dry-run": True})
    (request,) = fanout.requests
    # Upstream gets its own names back; the unset optional `to` is dropped.
    assert request["params"] == {
        "name": "cashFlow",
        "arguments": {"from": "2026-01-01", "dry-run": True},
    }
