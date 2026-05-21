"""Plugin resolver for :class:`~mcp_hub.interfaces.SecretBackend`.

Mirrors :mod:`mcp_hub.refresher.registry` for the secret-backend axis so
operators aren't locked to any one secrets provider. Resolution order:

1. Setuptools entry points in group ``mcp_hub.secret_backends``. The
   built-ins (``env``, ``file``, ``bao``) are registered in this package's
   ``pyproject.toml``; a third-party adapter declares the same group in its
   own package and is picked up once installed side-by-side — no change to
   the hub.
2. Dotted-path import (``my_package.MyBackend``) when the name contains a
   ``.`` — handy for in-repo/prototype adapters without an entry point.

The resolved object MUST be a *class* implementing the ``SecretBackend``
Protocol (``resolve`` + ``close``). The factory constructs an instance from
the policy's ``secret_backend.config`` block.
"""

from __future__ import annotations

import importlib
import importlib.metadata

from ..interfaces import SecretBackend

SECRET_BACKEND_ENTRY_POINT_GROUP = "mcp_hub.secret_backends"  # noqa: S105 (group name, not a secret)


class SecretBackendNotFound(Exception):
    """The requested ``secret_backend.name`` resolves to nothing importable."""


def resolve_secret_backend(type_str: str) -> type[SecretBackend]:
    """Look up a ``SecretBackend`` implementation class by name."""
    if not type_str:
        raise SecretBackendNotFound("secret_backend.name cannot be empty")

    # 1. Entry points. Bare names (no dot) MUST resolve here.
    eps = importlib.metadata.entry_points(group=SECRET_BACKEND_ENTRY_POINT_GROUP)
    for ep in eps:
        if ep.name == type_str:
            try:
                obj = ep.load()
            except Exception as exc:
                raise SecretBackendNotFound(
                    f"secret backend {type_str!r} failed to load: {exc}"
                ) from exc
            return _checked(obj, type_str)

    # 2. Dotted-path fallback for import-path-looking names.
    if "." in type_str:
        module_name, _, attr = type_str.rpartition(".")
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise SecretBackendNotFound(
                f"secret backend {type_str!r}: cannot import module "
                f"{module_name!r}: {exc}"
            ) from exc
        try:
            obj = getattr(module, attr)
        except AttributeError as exc:
            raise SecretBackendNotFound(
                f"secret backend {type_str!r}: module {module_name!r} has no "
                f"attribute {attr!r}"
            ) from exc
        return _checked(obj, type_str)

    available = sorted(ep.name for ep in eps)
    raise SecretBackendNotFound(
        f"no secret backend {type_str!r} registered in entry-point group "
        f"{SECRET_BACKEND_ENTRY_POINT_GROUP!r}; available: {available or '[]'}; "
        f"or use a dotted-path import like 'my_pkg.MyBackend'"
    )


def _checked(obj: object, type_str: str) -> type[SecretBackend]:
    """Confirm the resolved object is a class with the Protocol's methods."""
    if not isinstance(obj, type):
        raise SecretBackendNotFound(
            f"secret backend {type_str!r} resolved to {obj!r} "
            f"(a {type(obj).__name__}); expected a class"
        )
    missing = [m for m in ("resolve", "close") if not callable(getattr(obj, m, None))]
    if missing:
        raise SecretBackendNotFound(
            f"secret backend {type_str!r} ({obj.__module__}.{obj.__qualname__}) "
            f"does not satisfy the SecretBackend Protocol: missing {missing}"
        )
    return obj


__all__ = [
    "SECRET_BACKEND_ENTRY_POINT_GROUP",
    "SecretBackendNotFound",
    "resolve_secret_backend",
]
