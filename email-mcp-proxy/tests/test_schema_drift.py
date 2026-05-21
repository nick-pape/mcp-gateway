"""Schema-drift test — proves the hand-authored tool-schemas.yaml covers
every (composite-tool, action) the live upstream better-email-mcp exposes.

This is the load-bearing test that catches upstream Jules-agent churn.
If upstream renames an action or adds a new one, the hand-authored map
goes stale and tool calls silently fail (or, worse, get rewritten to
wrong actions). This test surfaces the drift as a CI failure with a
diff showing exactly which (composite, action) pairs we're missing.

Two modes:

- **Live mode** (default in CI): fetches a real tools/list from the
  configured EMAIL_MCP_URL. Skipped if env var EMAIL_MCP_URL_TEST isn't
  set — keeps `pytest tests/test_proxy.py` runnable on a workstation
  without an email-mcp container.

- **Fixture mode**: parses an embedded golden tools/list snapshot.
  Updated whenever we rebase the email-mcp fork; serves as a backstop
  for offline test runs.

The script bot-friendly: emits a clear "MISSING: composite.action"
diff line per drift, so CI logs are searchable.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx
import pytest
import yaml

_PROXY_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROXY_DIR))


SCHEMA_PATH = _PROXY_DIR / "tool-schemas.yaml"

# Embedded snapshot of upstream's tools/list as of 1.29.0-pape.2 fork point.
# Update when rebasing — the live-mode test catches drift between rebases.
GOLDEN_TOOLS_LIST: list[dict[str, object]] = [
    {
        "name": "messages",
        "inputSchema": {
            "properties": {
                "action": {
                    "enum": ["search", "read", "mark_read", "mark_unread", "flag",
                             "unflag", "move", "archive", "trash"],
                }
            }
        },
    },
    {
        "name": "folders",
        "inputSchema": {"properties": {"action": {"enum": ["list"]}}},
    },
    {
        "name": "attachments",
        "inputSchema": {"properties": {"action": {"enum": ["list", "download"]}}},
    },
    {
        "name": "send",
        "inputSchema": {"properties": {"action": {"enum": ["new", "reply", "forward"]}}},
    },
    {
        "name": "config",
        "inputSchema": {
            "properties": {
                "action": {
                    "enum": ["status", "setup_start", "setup_reset", "setup_complete",
                             "set", "cache_clear"],
                }
            }
        },
    },
    {"name": "config__open_relay", "inputSchema": {"properties": {}}},
    {"name": "help", "inputSchema": {"properties": {"tool_name": {"type": "string"}}}},
]


def _extract_actions(tools: list[dict]) -> set[tuple[str, str | None]]:
    """For each upstream tool, derive the set of (composite, action) pairs.

    Tools with an ``inputSchema.properties.action.enum`` produce one
    pair per enum value. Tools without an action enum (leaf tools like
    help, config__open_relay) produce one pair with action=None.
    """
    out: set[tuple[str, str | None]] = set()
    for t in tools:
        name = t["name"]
        action_enum = (
            t.get("inputSchema", {})
            .get("properties", {})
            .get("action", {})
            .get("enum")
        )
        if action_enum:
            for a in action_enum:
                out.add((name, a))
        else:
            out.add((name, None))
    return out


def _our_coverage() -> set[tuple[str, str | None]]:
    with open(SCHEMA_PATH) as f:
        raw = yaml.safe_load(f)
    return {(t["_composite"], t.get("_action")) for t in raw["tools"]}


def test_schema_covers_golden_snapshot():
    upstream = _extract_actions(GOLDEN_TOOLS_LIST)
    ours = _our_coverage()
    missing = upstream - ours
    extra = ours - upstream
    if missing or extra:
        diff = "\n".join(
            [f"  MISSING (hand-authored YAML doesn't cover): {c}.{a}" for c, a in sorted(missing, key=str)]
            + [f"  EXTRA (hand-authored YAML covers a non-upstream pair): {c}.{a}" for c, a in sorted(extra, key=str)]
        )
        pytest.fail(f"schema drift vs golden snapshot:\n{diff}")


@pytest.mark.skipif(
    not os.environ.get("EMAIL_MCP_URL_TEST"),
    reason="live drift test only runs when EMAIL_MCP_URL_TEST + EMAIL_MCP_BEARER_TEST are set",
)
def test_schema_covers_live_upstream():
    """Initialize an MCP session against the live upstream, list tools, compare."""
    url = os.environ["EMAIL_MCP_URL_TEST"].rstrip("/")
    bearer = os.environ.get("EMAIL_MCP_BEARER_TEST", "")
    if not bearer:
        pytest.skip("EMAIL_MCP_BEARER_TEST not set")

    with httpx.Client(base_url=url, timeout=10.0) as c:
        init_r = c.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "schema-drift-test", "version": "0"},
                },
            },
        )
        assert init_r.status_code == 200, init_r.text
        session = init_r.headers["mcp-session-id"]

        # Ack init
        c.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Mcp-Session-Id": session,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

        list_r = c.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Mcp-Session-Id": session,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert list_r.status_code == 200, list_r.text
        # SSE response: parse data: line
        body = list_r.text
        for line in body.splitlines():
            if line.startswith("data: "):
                payload = json.loads(line[len("data: "):])
                tools = payload.get("result", {}).get("tools", [])
                break
        else:
            pytest.fail(f"no SSE data line in response: {body[:500]}")

    upstream = _extract_actions(tools)
    ours = _our_coverage()
    missing = upstream - ours
    extra = ours - upstream
    if missing or extra:
        diff = "\n".join(
            [f"  MISSING: {c}.{a}" for c, a in sorted(missing, key=str)]
            + [f"  EXTRA: {c}.{a}" for c, a in sorted(extra, key=str)]
        )
        pytest.fail(f"schema drift vs live {url}:\n{diff}")
