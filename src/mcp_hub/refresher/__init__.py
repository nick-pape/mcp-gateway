"""Token refresher subsystem.

Keeps short-lived auth tokens fresh on disk so consumers (the hub
itself, the bao login flow, future MCPs) read a non-expired credential
each time they open the file.

The architecture is plugin-first: ``TokenSource`` and ``TokenSink`` are
runtime-checkable Protocols; built-ins are registered via setuptools
entry points (groups ``mcp_hub.token_sources`` and
``mcp_hub.token_sinks``) so third-party plugins drop in without hub
changes. ``policy.yaml`` ``token_refresh:`` entries reference sources
and sinks by their entry-point name (e.g.
``authentik_client_credentials``); a dotted-path import string
(``my_pkg.MyAuthSource``) also works for quick local plugins that
aren't installed via entry points.

Why this lives in the hub today: the hub is the only consumer right
now (its ``fanout_jwt`` rotates against Authentik). The Protocol shape
is deliberately importable; if a second service ever needs the same
machinery the module extracts cleanly to a sidecar or its own package.
"""

from __future__ import annotations

from .manager import RefresherManager
from .orchestrator import TokenRefresher
from .protocols import (
    Token,
    TokenMintError,
    TokenSink,
    TokenSource,
    TokenWriteError,
)
from .registry import PluginNotFound, resolve_sink, resolve_source

__all__ = [
    "PluginNotFound",
    "RefresherManager",
    "Token",
    "TokenMintError",
    "TokenRefresher",
    "TokenSink",
    "TokenSource",
    "TokenWriteError",
    "resolve_sink",
    "resolve_source",
]
