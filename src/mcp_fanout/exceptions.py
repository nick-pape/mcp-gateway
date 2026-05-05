"""Exception types raised by the Fanout module."""

from __future__ import annotations


class FanoutError(Exception):
    """Base class for all Fanout-raised exceptions."""


class IdentityNotFound(FanoutError):
    """Raised when ``call(identity=...)`` references an unknown identity."""


class ChildSpawnFailed(FanoutError):
    """Raised when an stdio child fails to start.

    Eager-or-die: any spawn failure during ``start_eager_or_die`` aborts
    the whole stack — we don't try to limp along with a subset of
    identities up.
    """


class BackendChildDead(FanoutError):
    """Raised when the stdio child has exited or its response is unusable.

    Cases that surface this:

    - Child process has exited unexpectedly
    - Response line exceeds ``max_response_bytes`` (truncated, can't trust it)
    - Child wrote invalid JSON to stdout
    - Stream closed mid-read
    """
