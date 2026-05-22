"""Plugin resolver for :class:`~mcp_hub.interfaces.Approver`.

Mirrors :mod:`mcp_hub.secrets.registry` so the HITL provider isn't locked to
ntfy. Resolution order:

1. Setuptools entry points in group ``mcp_hub.approvers``. The built-ins
   (``auto``, ``reject``, ``ntfy``) are registered in this package's
   ``pyproject.toml``; a third-party approver (Slack, Telegram, webhook, ...)
   declares the same group in its own package and is picked up once installed.
2. Dotted-path import (``my_package.MyApprover``) for in-repo/prototype impls.

The resolved object MUST be a class implementing the ``Approver`` Protocol
(``request_approval`` + ``publish_outcome`` + ``close``). The factory
constructs an instance from the policy's ``approver.config`` block.
"""

from __future__ import annotations

import importlib
import importlib.metadata

from ..interfaces import Approver

APPROVER_ENTRY_POINT_GROUP = "mcp_hub.approvers"


class ApproverNotFound(Exception):
    """The requested ``approver.name`` resolves to nothing importable."""


def resolve_approver(type_str: str) -> type[Approver]:
    """Look up an ``Approver`` implementation class by name."""
    if not type_str:
        raise ApproverNotFound("approver.name cannot be empty")

    eps = importlib.metadata.entry_points(group=APPROVER_ENTRY_POINT_GROUP)
    for ep in eps:
        if ep.name == type_str:
            try:
                obj = ep.load()
            except Exception as exc:
                raise ApproverNotFound(
                    f"approver {type_str!r} failed to load: {exc}"
                ) from exc
            return _checked(obj, type_str)

    if "." in type_str:
        module_name, _, attr = type_str.rpartition(".")
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise ApproverNotFound(
                f"approver {type_str!r}: cannot import module {module_name!r}: {exc}"
            ) from exc
        try:
            obj = getattr(module, attr)
        except AttributeError as exc:
            raise ApproverNotFound(
                f"approver {type_str!r}: module {module_name!r} has no attribute "
                f"{attr!r}"
            ) from exc
        return _checked(obj, type_str)

    available = sorted(ep.name for ep in eps)
    raise ApproverNotFound(
        f"no approver {type_str!r} registered in entry-point group "
        f"{APPROVER_ENTRY_POINT_GROUP!r}; available: {available or '[]'}; "
        f"or use a dotted-path import like 'my_pkg.MyApprover'"
    )


def _checked(obj: object, type_str: str) -> type[Approver]:
    if not isinstance(obj, type):
        raise ApproverNotFound(
            f"approver {type_str!r} resolved to {obj!r} "
            f"(a {type(obj).__name__}); expected a class"
        )
    required = ("request_approval", "publish_outcome", "close")
    missing = [m for m in required if not callable(getattr(obj, m, None))]
    if missing:
        raise ApproverNotFound(
            f"approver {type_str!r} ({obj.__module__}.{obj.__qualname__}) does "
            f"not satisfy the Approver Protocol: missing {missing}"
        )
    return obj


__all__ = [
    "APPROVER_ENTRY_POINT_GROUP",
    "ApproverNotFound",
    "resolve_approver",
]
