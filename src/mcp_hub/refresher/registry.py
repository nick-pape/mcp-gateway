"""Plugin resolver for :class:`TokenSource` and :class:`TokenSink`.

Resolution order, in priority:

1. Setuptools entry points in groups ``mcp_hub.token_sources`` and
   ``mcp_hub.token_sinks``. Built-ins (Authentik client_credentials,
   file sink) are registered here in this package's ``pyproject.toml``;
   third-party plugins do the same in their own packages.

2. Dotted-path import (``my_package.MyAuthSource``) when the lookup key
   contains ``.``. Lets local/in-repo plugins skip the entry-point
   declaration step. Recommended for prototyping; entry points are
   recommended for anything that ships.

The resolved object MUST be a *class* (not an instance) implementing
the relevant Protocol. The factory (in ``policy.py`` / ``factory.py``)
constructs an instance from the policy's ``config`` block.

Why entry points instead of a global registry dict: package install =
plugin available, with no central import that has to know every plugin
in the universe. The hub never needs to ``import`` a third-party
plugin's module by name.
"""

from __future__ import annotations

import importlib
import importlib.metadata

from .protocols import TokenSink, TokenSource

SOURCE_ENTRY_POINT_GROUP = "mcp_hub.token_sources"
SINK_ENTRY_POINT_GROUP = "mcp_hub.token_sinks"


class PluginNotFound(Exception):
    """The requested plugin name resolves to nothing importable."""


def resolve_source(type_str: str) -> type[TokenSource]:
    """Look up a :class:`TokenSource` implementation by name."""
    cls = _resolve(type_str, SOURCE_ENTRY_POINT_GROUP)
    _validate_protocol(cls, type_str, kind="source")
    return cls


def resolve_sink(type_str: str) -> type[TokenSink]:
    """Look up a :class:`TokenSink` implementation by name."""
    cls = _resolve(type_str, SINK_ENTRY_POINT_GROUP)
    _validate_protocol(cls, type_str, kind="sink")
    return cls


def _resolve(type_str: str, group: str) -> type:
    """Entry-point lookup, then dotted-path fallback. Raises on miss."""
    if not type_str:
        raise PluginNotFound("plugin type string cannot be empty")

    # 1. Entry points. Bare names (no dot) MUST resolve here.
    eps = importlib.metadata.entry_points(group=group)
    for ep in eps:
        if ep.name == type_str:
            try:
                obj = ep.load()
            except Exception as exc:
                raise PluginNotFound(
                    f"entry point {type_str!r} in group {group!r} "
                    f"failed to load: {exc}"
                ) from exc
            if not isinstance(obj, type):
                raise PluginNotFound(
                    f"entry point {type_str!r} in {group!r} resolved to "
                    f"{obj!r} (a {type(obj).__name__}); expected a class"
                )
            return obj

    # 2. Dotted-path fallback. Only attempted when the lookup key looks
    #    like an import path; bare names that miss step 1 are clear errors.
    if "." in type_str:
        module_name, _, attr = type_str.rpartition(".")
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise PluginNotFound(
                f"dotted-path plugin {type_str!r}: cannot import module "
                f"{module_name!r}: {exc}"
            ) from exc
        try:
            obj = getattr(module, attr)
        except AttributeError as exc:
            raise PluginNotFound(
                f"dotted-path plugin {type_str!r}: module {module_name!r} "
                f"has no attribute {attr!r}"
            ) from exc
        if not isinstance(obj, type):
            raise PluginNotFound(
                f"dotted-path plugin {type_str!r} resolved to {obj!r} "
                f"(a {type(obj).__name__}); expected a class"
            )
        return obj

    # Bare name, not in entry points.
    available = sorted(ep.name for ep in eps)
    raise PluginNotFound(
        f"no plugin {type_str!r} registered in entry-point group "
        f"{group!r}; available: {available or '[]'}; "
        f"or use a dotted-path import like 'my_pkg.MyClass'"
    )


def _validate_protocol(cls: type, type_str: str, *, kind: str) -> None:
    """Cheap structural check before instantiation.

    Can't ``isinstance(cls, TokenSource)`` against a class (Protocol
    runtime check needs an instance), but we can at least confirm the
    methods exist. Catches the "user pointed at the wrong class" case
    early instead of erroring at first ``mint()`` / ``write()`` call.
    """
    required = {"source": ("mint", "close"), "sink": ("write", "close")}[kind]
    missing = [m for m in required if not callable(getattr(cls, m, None))]
    if missing:
        raise PluginNotFound(
            f"plugin {type_str!r} ({cls.__module__}.{cls.__qualname__}) "
            f"does not satisfy Token{kind.capitalize()} Protocol: "
            f"missing methods {missing}"
        )


__all__ = [
    "SINK_ENTRY_POINT_GROUP",
    "SOURCE_ENTRY_POINT_GROUP",
    "PluginNotFound",
    "resolve_sink",
    "resolve_source",
]
