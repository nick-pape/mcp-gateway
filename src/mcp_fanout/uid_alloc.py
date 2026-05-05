"""Per-identity UID allocation and gating.

The Fanout's security model requires each per-identity stdio child to
run as a **distinct unprivileged UID** so siblings cannot read each
other's ``/proc/<pid>/environ``. On Linux as root with ``gosu`` (or
``setpriv``) installed in the image, we can enforce this.

On non-Linux dev hosts (the user's Windows box) we cannot enforce UID
separation — Windows has no equivalent. In that case the Fanout still
works for protocol testing (single-UID, no isolation) but the security
property is documented as **not present**. Production deploys MUST run
on Linux as root with ``gosu`` available.

This module exposes two things:

- :func:`uid_separation_supported` — runtime predicate
- :func:`spawn_command` — prefixes ``gosu <uid>:<uid>`` if applicable
"""

from __future__ import annotations

import os
import platform
import shutil
from collections.abc import Sequence


def uid_separation_supported() -> bool:
    """True iff we can spawn children as distinct UIDs.

    Requires:
      - Linux platform (POSIX semantics around ``/proc/<pid>/environ``)
      - Running as UID 0 (root) so we can ``setuid`` away from it
      - ``gosu`` binary on PATH
    """
    if platform.system() != "Linux":
        return False
    # On Linux, ``os.geteuid`` is always available; on other platforms it
    # may not be. Guard with ``hasattr`` for type checkers.
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return False
    return shutil.which("gosu") is not None


def spawn_command(command: Sequence[str], uid: int) -> list[str]:
    """Wrap ``command`` with ``gosu <uid>:<uid>`` when supported.

    On unsupported platforms this is a no-op (returns ``command``
    unchanged). The Fanout logs a warning at boot if it spawns
    without UID separation.
    """
    if uid_separation_supported():
        return ["gosu", f"{uid}:{uid}", *command]
    return list(command)
