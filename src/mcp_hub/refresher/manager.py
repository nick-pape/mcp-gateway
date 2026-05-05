"""RefresherManager: lifecycle + ordering for N :class:`TokenRefresher`s.

Two-phase startup:

1. ``mint_initial()`` — runs every refresher's first mint synchronously
   (well, awaitably). Blocks until every refresher has a fresh token on
   disk OR raises if any fail. Hub startup MUST wait for this before
   calling ``Hub.start()``, since the bao login that ``Hub.start()``
   triggers reads ``role_jwt_path`` which is the refresher's output.

2. ``start_background()`` — spawns one asyncio Task per refresher
   running its ``run_forever()`` loop. Returns immediately.

This shape makes the dependency direction explicit: refresher writes,
THEN hub reads. There is no "self-healing on first failure" path —
fail at startup with a clear error, not later in a tools/call.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from contextlib import suppress

from .orchestrator import TokenRefresher

logger = logging.getLogger(__name__)


class RefresherManager:
    """Lifecycle owner for N :class:`TokenRefresher` instances."""

    def __init__(self, refreshers: Iterable[TokenRefresher]) -> None:
        self._refreshers: list[TokenRefresher] = list(refreshers)
        self._tasks: list[asyncio.Task[None]] = []
        # Distinct names — silent collisions would be confusing.
        names = [r.name for r in self._refreshers]
        if len(set(names)) != len(names):
            raise ValueError(
                f"RefresherManager: duplicate refresher names: {sorted(names)}"
            )

    @property
    def refreshers(self) -> list[TokenRefresher]:
        return list(self._refreshers)

    async def mint_initial(self) -> None:
        """Run every refresher's initial mint+write. Blocks until done.

        On failure of any single refresher, attempts to close all
        already-completed ones (release their HTTP clients), then
        re-raises. The hub cannot start without all initial mints
        succeeding.

        Refreshers are minted in parallel — they're independent and
        an N=2-or-more startup deserves to be fast.
        """
        if not self._refreshers:
            logger.info("RefresherManager: no refreshers configured")
            return

        logger.info(
            "RefresherManager: minting initial tokens for %d refresher(s): %s",
            len(self._refreshers),
            [r.name for r in self._refreshers],
        )

        results = await asyncio.gather(
            *(r.mint_initial() for r in self._refreshers),
            return_exceptions=True,
        )
        failures = [
            (r.name, exc)
            for r, exc in zip(self._refreshers, results, strict=True)
            if isinstance(exc, BaseException)
        ]
        if failures:
            # Best-effort cleanup of refreshers (theirs may hold HTTP
            # clients we'd otherwise leak), then re-raise the FIRST
            # failure with context about the rest.
            await self.close()
            names = ", ".join(name for name, _ in failures)
            first_name, first_exc = failures[0]
            raise RuntimeError(
                f"RefresherManager: initial mint failed for {len(failures)}"
                f"/{len(self._refreshers)} refresher(s) [{names}]; "
                f"first failure ({first_name!r}): {first_exc}"
            ) from first_exc

        logger.info("RefresherManager: all %d initial mints OK", len(self._refreshers))

    def start_background(self) -> None:
        """Spawn one ``run_forever()`` task per refresher.

        Must be called AFTER ``mint_initial()`` succeeds. Idempotent:
        re-calling is a no-op (the existing tasks are kept).
        """
        if self._tasks:
            logger.warning("RefresherManager.start_background called twice; ignoring")
            return
        for refresher in self._refreshers:
            task = asyncio.create_task(
                refresher.run_forever(),
                name=f"refresher-{refresher.name}",
            )
            self._tasks.append(task)
        logger.info(
            "RefresherManager: started %d background rotation task(s)",
            len(self._tasks),
        )

    async def close(self) -> None:
        """Cancel all rotation tasks and release refresher resources.

        Idempotent. Errors during close are logged but do not raise.
        """
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        for refresher in self._refreshers:
            await refresher.close()


__all__ = ["RefresherManager"]
