"""Multi-tenant MCP multiplexers.

The package exposes three fanout implementations sharing one external
shape:

- :class:`Fanout` (stdio) — spawns N stdio child subprocesses, one per
  identity, each running as a distinct UID with a per-identity 0400
  token file. The historical (and original) backend; slated for
  deprecation once Technitium migrates to ``transport: container``.
- :class:`HttpFanout` (HTTP) — forwards JSON-RPC over HTTP to a
  federated upstream MCP that's already running (Outline, KitchenOwl,
  etc.), injecting per-identity auth headers via a pluggable
  :class:`mcp_hub.auth_strategies.AuthStrategy`.
- :class:`ContainerFanout` (container) — spawns wrapper containers
  on-demand per (mcp x identity) via the Docker remote API. Each
  container packages a stdio MCP behind an Authentik-fronted HTTPS
  shim; the hub federates with JwtPassthrough.

All three expose ``mcp_name``, ``identities``, ``start_eager_or_die``,
``call``, and ``close``. Server.py duck-types them via ``FanoutLike``.

Public API::

    from mcp_fanout import Fanout, HttpFanout, ContainerFanout, IdentityConfig
    from mcp_fanout.exceptions import (
        BackendChildDead,
        ChildSpawnFailed,
        HttpUpstreamFailed,
        IdentityNotFound,
    )
"""

from __future__ import annotations

from .container_fanout import (
    DEFAULT_AUDIENCE_TEMPLATE,
    DEFAULT_CONTAINER_HOST,
    DEFAULT_CONTAINER_PORT,
    DEFAULT_EVICTION_INTERVAL_S,
    DEFAULT_IDLE_TIMEOUT_S,
    DEFAULT_SPAWN_TIMEOUT_S,
    ContainerFanout,
    VolumeMountSpec,
)
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
    "DEFAULT_AUDIENCE_TEMPLATE",
    "DEFAULT_CONTAINER_HOST",
    "DEFAULT_CONTAINER_PORT",
    "DEFAULT_EVICTION_INTERVAL_S",
    "DEFAULT_IDLE_TIMEOUT_S",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_REQUEST_TIMEOUT_S",
    "DEFAULT_SPAWN_TIMEOUT_S",
    "BackendChildDead",
    "ChildSpawnFailed",
    "ContainerFanout",
    "Fanout",
    "FanoutError",
    "HttpFanout",
    "HttpUpstreamFailed",
    "IdentityConfig",
    "IdentityNotFound",
    "VolumeMountSpec",
]
