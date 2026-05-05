"""Multi-tenant stdio MCP multiplexer.

Spawns N stdio child processes per MCP type — one per identity — and
routes incoming JSON-RPC requests to the correct child by identity tag.
Designed for eventual standalone OSS publication; until then, lives
alongside the hub that imports it.

Public API::

    from mcp_fanout import Fanout, IdentityConfig
    from mcp_fanout.exceptions import (
        BackendChildDead,
        ChildSpawnFailed,
        IdentityNotFound,
    )
"""

from __future__ import annotations

from .exceptions import (
    BackendChildDead,
    ChildSpawnFailed,
    FanoutError,
    IdentityNotFound,
)
from .fanout import (
    DEFAULT_MAX_RESPONSE_BYTES,
    Fanout,
    IdentityConfig,
)

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "BackendChildDead",
    "ChildSpawnFailed",
    "Fanout",
    "FanoutError",
    "IdentityConfig",
    "IdentityNotFound",
]
