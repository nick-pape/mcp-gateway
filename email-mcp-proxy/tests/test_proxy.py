"""Unit tests for the email-mcp-proxy rewrite logic.

Pattern mirrors mcp.service.pape.house/tests/unit/test_http_fanout.py —
no real network, no real email-mcp container; httpx.MockTransport stubs
the upstream and asserts on what the proxy emits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

# Make the proxy importable when running pytest from this directory or repo root.
_PROXY_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROXY_DIR))

import proxy as proxy_module  # noqa: E402

# Default schema fixture path — the production tool-schemas.yaml shipped
# next to proxy.py. Tests that need a minimal schema use ``_make_schema``.
SCHEMA_PATH = _PROXY_DIR / "tool-schemas.yaml"


# ---------------------------------------------------------------------------
# Schema-loading
# ---------------------------------------------------------------------------


def test_load_schemas_strips_proxy_metadata():
    tools, name_map = proxy_module.load_schemas(str(SCHEMA_PATH))
    # Every emitted tool entry must NOT contain proxy-only fields
    for t in tools:
        assert "_composite" not in t
        assert "_action" not in t
        assert "name" in t and "description" in t and "inputSchema" in t
    # The map covers every emitted name
    assert {t["name"] for t in tools} == set(name_map.keys())


def test_load_schemas_minimum_coverage():
    """All 7 upstream composites must produce at least one granular entry."""
    _, name_map = proxy_module.load_schemas(str(SCHEMA_PATH))
    composites = {composite for composite, _ in name_map.values()}
    expected = {
        "messages", "folders", "attachments", "send", "config",
        "config__open_relay", "help",
    }
    assert composites == expected


# ---------------------------------------------------------------------------
# rewrite_tools_call (request direction)
# ---------------------------------------------------------------------------


def _name_map_fixture():
    return {
        "messages_search": ("messages", "search"),
        "messages_trash": ("messages", "trash"),
        "send_new": ("send", "new"),
        "help": ("help", None),
        "config__open_relay": ("config__open_relay", None),
    }


def test_rewrite_tools_call_translates_granular_to_composite():
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "messages_search", "arguments": {"query": "UNREAD", "limit": 5}},
    }
    out = proxy_module.rewrite_tools_call(payload, _name_map_fixture())
    assert out["params"]["name"] == "messages"
    assert out["params"]["arguments"] == {
        "action": "search", "query": "UNREAD", "limit": 5,
    }


def test_rewrite_tools_call_destructive_action_threading():
    payload = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "messages_trash", "arguments": {"account": "a@b.c", "uid": 99}},
    }
    out = proxy_module.rewrite_tools_call(payload, _name_map_fixture())
    assert out["params"]["name"] == "messages"
    assert out["params"]["arguments"]["action"] == "trash"
    assert out["params"]["arguments"]["uid"] == 99


def test_rewrite_tools_call_leaf_tool_passes_through():
    # Leaf tools (single-op like help, config__open_relay) — action=None
    payload = {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "help", "arguments": {"tool_name": "messages"}},
    }
    out = proxy_module.rewrite_tools_call(payload, _name_map_fixture())
    assert out["params"]["name"] == "help"
    assert "action" not in out["params"]["arguments"]


def test_rewrite_tools_call_unknown_name_passes_through(caplog):
    payload = {
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "messages_invented_action", "arguments": {}},
    }
    with caplog.at_level("WARNING"):
        out = proxy_module.rewrite_tools_call(payload, _name_map_fixture())
    assert out["params"]["name"] == "messages_invented_action"  # untouched
    assert any("messages_invented_action" in r.message for r in caplog.records)


def test_rewrite_tools_call_non_tools_call_passes_through():
    payload = {"jsonrpc": "2.0", "id": 5, "method": "tools/list"}
    out = proxy_module.rewrite_tools_call(payload, _name_map_fixture())
    assert out == payload


# ---------------------------------------------------------------------------
# rewrite_tools_list_response (response direction)
# ---------------------------------------------------------------------------


def test_rewrite_tools_list_response_substitutes_array():
    upstream = {
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [
            {"name": "messages", "description": "x", "inputSchema": {}},
            {"name": "send", "description": "y", "inputSchema": {}},
        ]},
    }
    granular = [{"name": "messages_search", "description": "z", "inputSchema": {}}]
    out = proxy_module.rewrite_tools_list_response(upstream, granular)
    assert out["result"]["tools"] == granular
    # Other fields preserved
    assert out["jsonrpc"] == "2.0"
    assert out["id"] == 1


def test_rewrite_tools_list_response_passes_through_non_list():
    """Tool-call results, initialize responses, errors etc. untouched."""
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "result": {"content": [{"type": "text", "text": "hi"}]},
    }
    out = proxy_module.rewrite_tools_list_response(payload, [])
    assert out == payload


def test_rewrite_tools_list_response_handles_error_responses():
    payload = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "boom"}}
    out = proxy_module.rewrite_tools_list_response(payload, [])
    assert out == payload


# ---------------------------------------------------------------------------
# End-to-end via FastAPI TestClient + MockTransport
# ---------------------------------------------------------------------------


@pytest.fixture
def proxy_client(monkeypatch, tmp_path):
    """Boot the proxy app with an httpx MockTransport stubbing email-mcp.

    Each test can inspect the captured requests via the fixture-scoped
    list ``captured_requests`` returned alongside the client.
    """
    # Point the proxy at the production schema file shipped next to proxy.py.
    # The proxy.py module-level constant SCHEMA_FILE was read at import time
    # from env; patch the constant directly so the startup hook reloads.
    monkeypatch.setattr(proxy_module, "SCHEMA_FILE", str(SCHEMA_PATH))

    captured_requests: list[httpx.Request] = []
    upstream_response_factory = {"fn": lambda req: httpx.Response(200, json={})}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return upstream_response_factory["fn"](request)

    mock_transport = httpx.MockTransport(_handler)

    # Patch httpx.AsyncClient ctor so app.state.http uses the mock transport.
    real_ctor = httpx.AsyncClient.__init__

    def patched(self, *args, **kwargs):
        kwargs["transport"] = mock_transport
        real_ctor(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)

    client = TestClient(proxy_module.app)
    # Trigger startup hooks
    with client:
        yield client, captured_requests, upstream_response_factory


def test_e2e_tools_call_rewrite_reaches_upstream(proxy_client):
    client, captured, factory = proxy_client
    factory["fn"] = lambda req: httpx.Response(200, json={
        "jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "ok"}]},
    })

    r = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "messages_search", "arguments": {"query": "ALL", "limit": 1}},
    })
    assert r.status_code == 200

    # The /health probe also hits the mock — ignore .well-known calls.
    mcp_calls = [c for c in captured if c.url.path == "/mcp"]
    assert len(mcp_calls) == 1
    body = json.loads(mcp_calls[0].content.decode())
    assert body["params"]["name"] == "messages"
    assert body["params"]["arguments"] == {
        "action": "search", "query": "ALL", "limit": 1,
    }


def test_e2e_tools_list_response_rewritten(proxy_client):
    client, _captured, factory = proxy_client
    # Upstream returns the native 7 composite tools
    factory["fn"] = lambda req: httpx.Response(200, json={
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [
            {"name": "messages", "description": "x", "inputSchema": {}},
            {"name": "folders", "description": "y", "inputSchema": {}},
            {"name": "attachments", "description": "z", "inputSchema": {}},
            {"name": "send", "description": "a", "inputSchema": {}},
            {"name": "config", "description": "b", "inputSchema": {}},
            {"name": "config__open_relay", "description": "c", "inputSchema": {}},
            {"name": "help", "description": "d", "inputSchema": {}},
        ]},
    })

    r = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
    })
    assert r.status_code == 200
    out = r.json()
    names = {t["name"] for t in out["result"]["tools"]}
    # Granular set must include both reads and writes
    assert "messages_search" in names
    assert "messages_trash" in names
    assert "send_new" in names
    assert "help" in names
    # Original composite names absent
    assert "messages" not in names
    assert "send" not in names


def test_e2e_initialize_passes_through_untouched(proxy_client):
    client, captured, factory = proxy_client
    factory["fn"] = lambda req: httpx.Response(200, json={
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "@n24q02m/better-email-mcp", "version": "0.0.0"},
        },
    })
    r = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    })
    assert r.status_code == 200
    assert "serverInfo" in r.json()["result"]
    # Initialize body forwarded verbatim
    mcp_calls = [c for c in captured if c.url.path == "/mcp"]
    body = json.loads(mcp_calls[0].content.decode())
    assert body["method"] == "initialize"


def test_e2e_authorization_header_forwarded(proxy_client):
    client, captured, factory = proxy_client
    factory["fn"] = lambda req: httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
    client.post(
        "/mcp",
        headers={"Authorization": "Bearer dummy.token.value"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    mcp_calls = [c for c in captured if c.url.path == "/mcp"]
    assert mcp_calls[0].headers.get("Authorization") == "Bearer dummy.token.value"


def test_e2e_mcp_session_id_round_trips(proxy_client):
    client, captured, factory = proxy_client
    factory["fn"] = lambda req: httpx.Response(
        200, json={"jsonrpc": "2.0", "id": 1, "result": {}},
        headers={"Mcp-Session-Id": "test-session-abc"},
    )
    r = client.post(
        "/mcp",
        headers={"Mcp-Session-Id": "client-session-xyz"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    # Inbound session id flows through to upstream
    mcp_calls = [c for c in captured if c.url.path == "/mcp"]
    assert mcp_calls[0].headers.get("Mcp-Session-Id") == "client-session-xyz"
    # Upstream's session id (whichever it issued) flows back to client
    assert r.headers.get("Mcp-Session-Id") == "test-session-abc"


def test_e2e_upstream_unreachable_returns_502(proxy_client):
    client, _captured, factory = proxy_client

    def _boom(req):
        raise httpx.ConnectError("no route to host")
    factory["fn"] = _boom

    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 502
    assert "upstream" in r.json()["error"]


def test_health_ok_when_upstream_well_known_ok(proxy_client):
    client, _captured, factory = proxy_client
    factory["fn"] = lambda req: httpx.Response(200, json={"issuer": "x"})
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["granular_tools"] > 0


def test_health_degraded_when_upstream_unreachable(proxy_client):
    client, _captured, factory = proxy_client
    factory["fn"] = lambda req: httpx.Response(503)
    r = client.get("/health")
    assert r.status_code == 503
