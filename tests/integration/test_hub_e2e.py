"""End-to-end integration: Hub composes Fanout + middleware + tool routing.

DEFERRED to Phase 11. The composed Hub flow is exercised end-to-end via
a real Claude Code remote MCP client + real Authentik in Phase 11; the
unit-level coverage of middleware logic lives in
``tests/unit/test_middleware.py`` and is sufficient for the components.

The skeleton below is preserved as a TODO. Two FastMCP integration
specifics need resolving before this becomes a runnable test:

1. FastMCP's ``FunctionTool.from_function`` rejects ``**kwargs``;
   handlers must take explicit params or a single typed dict. The Hub's
   ``server.py`` uses a single ``arguments: dict`` param and overrides
   the schema. This test should follow the same pattern.

2. FastMCP's argument-mapping behavior with a schema overlaid on a
   single-dict-param function needs verification with a real Client
   driving it. Phase 11 (real Claude Code) is the natural validation
   point because it tests the same tool-call wire format we deploy.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(reason="Deferred to Phase 11 (real Claude Code + Authentik smoke)")
def test_hub_e2e_placeholder() -> None:
    pass
