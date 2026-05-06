"""Multi-tenant MCP multiplexers.

The package exposes two fanout implementations sharing one external
shape:

- :class:`Fanout` (stdio) — spawns N stdio child subprocesses, one per
  identity, each running as a distinct UID with a per-identity 0400
  token file. The historical (and only, until V2) backend.
- :class:`HttpFanout` (HTTP) — forwards JSON-RPC over HTTP to a
  federated upstream MCP, injecting per-identity auth headers via a
  pluggable :class:`mcp_hub.auth_strategies.AuthStrategy`.

Both expose ``mcp_name``, ``identities``, ``start_eager_or_die``,
``call``, and ``close``. Server.py duck-types them.

Public API::

    from mcp_fanout import Fanout, HttpFanout, IdentityConfig
    from mcp_fanout.exceptions import (
        BackendChildDead,
        ChildSpawnFailed,
        HttpUpstreamFailed,
        IdentityNotFound,
    )
"""

from __future__ import annotations

from .exceptions import (
    BackendChildDead,
    ChildSpawnFailed,
    FanoutError,
    HttpUpstreamFailed,
    IdentityNotFound,
)
from .fanout import (
    DEFAULT_MAX_RESPONSE_BYTES,
    Fanout,
    IdentityConfig,
)
from .http_fanout import (
    DEFAULT_REQUEST_TIMEOUT_S,
    HttpFanout,
)

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_REQUEST_TIMEOUT_S",
    "BackendChildDead",
    "ChildSpawnFailed",
    "Fanout",
    "FanoutError",
    "HttpFanout",
    "HttpUpstreamFailed",
    "IdentityConfig",
    "IdentityNotFound",
]
