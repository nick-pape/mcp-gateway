"""TokenRefresher: one rotation loop per (source, sink) pair.

Mints a fresh token, atomically writes it to the sink, sleeps until
the next rotation, repeats. Failure handling is "hold last known +
keep retrying" — never crash the hub on a transient outage; let the
downstream consumer fail loudly when the held token actually expires
and gets rejected.

Rotation cadence:

- ``rotate_every`` is the *maximum* sleep between mints. The orchestrator
  ALSO wakes early if the just-minted token's expiry is closer than
  ``rotate_every`` (minus a safety buffer). This handles cases where the
  source returns shorter-than-expected lifetimes (e.g. provider config
  changes during runtime).

Backoff policy on transient failures:

- Exponential, doubling each attempt, capped at ``max_backoff``.
- Reset to ``initial_backoff`` after any successful rotation.
- Non-transient failures (``TokenMintError(transient=False)`` etc.)
  log a louder warning but otherwise behave the same — we don't have
  a better option than retrying. The point of the refresher is to
  keep trying.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from .protocols import Token, TokenMintError, TokenSink, TokenSource, TokenWriteError

logger = logging.getLogger(__name__)


# Don't sleep less than this between rotation attempts even if the
# token's TTL would suggest sooner. Prevents tight loops if a source
# is misbehaving and returning near-expired tokens.
MIN_SLEEP = timedelta(seconds=10)


class TokenRefresher:
    """One rotation loop. Manager owns N of these and runs each as a task."""

    def __init__(
        self,
        *,
        name: str,
        source: TokenSource,
        sink: TokenSink,
        rotate_every: timedelta,
        safety_buffer: timedelta = timedelta(seconds=30),
        initial_backoff: timedelta = timedelta(seconds=5),
        max_backoff: timedelta = timedelta(minutes=2),
    ) -> None:
        self._name = name
        self._source = source
        self._sink = sink
        self._rotate_every = rotate_every
        self._safety_buffer = safety_buffer
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._last_token: Token | None = None
        self._consecutive_failures = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def last_token(self) -> Token | None:
        """The most recently minted token, or ``None`` if never succeeded.

        Exposed for tests and for the manager's startup ordering — after
        ``mint_initial()`` returns, this MUST be set."""
        return self._last_token

    async def mint_initial(self) -> Token:
        """Synchronous-style first mint+write. Used at startup.

        Raises the underlying :class:`TokenMintError` /
        :class:`TokenWriteError` to the caller. The caller (typically
        :class:`RefresherManager`) decides whether the hub can boot
        without this token (today: it cannot, since the bao login at
        Hub.start() needs it).
        """
        token = await self._rotate_once()
        return token

    async def run_forever(self) -> None:
        """Long-running rotation loop. Call from an asyncio Task.

        Returns only on cancellation. Internal failures are logged and
        swallowed; the loop continues.
        """
        backoff = self._initial_backoff
        while True:
            try:
                token = await self._rotate_once()
                backoff = self._initial_backoff  # reset
                sleep_for = self._compute_sleep(token)
                logger.debug(
                    "refresher %s: next rotation in %.0fs",
                    self._name,
                    sleep_for.total_seconds(),
                )
                await asyncio.sleep(sleep_for.total_seconds())
            except asyncio.CancelledError:
                raise
            except (TokenMintError, TokenWriteError) as exc:
                self._consecutive_failures += 1
                level = (
                    logging.ERROR
                    if not getattr(exc, "transient", True)
                    else logging.WARNING
                )
                logger.log(
                    level,
                    "refresher %s: rotation failed (attempt #%d, %s, "
                    "backoff %.0fs): %s",
                    self._name,
                    self._consecutive_failures,
                    "non-transient" if not getattr(exc, "transient", True) else "transient",
                    backoff.total_seconds(),
                    exc,
                )
                await asyncio.sleep(backoff.total_seconds())
                backoff = min(backoff * 2, self._max_backoff)
            except Exception:
                # Any other exception is a programming error in source/sink.
                # Log + continue so the loop survives.
                self._consecutive_failures += 1
                logger.exception(
                    "refresher %s: unexpected error (attempt #%d); continuing",
                    self._name,
                    self._consecutive_failures,
                )
                await asyncio.sleep(backoff.total_seconds())
                backoff = min(backoff * 2, self._max_backoff)

    async def _rotate_once(self) -> Token:
        """Mint then write. Raises on either failure."""
        token = await self._source.mint()
        await self._sink.write(token)
        self._last_token = token
        self._consecutive_failures = 0
        return token

    def _compute_sleep(self, token: Token) -> timedelta:
        """How long to sleep before the next rotation attempt.

        ``min(rotate_every, ttl - safety_buffer)`` clamped to ``MIN_SLEEP``.
        """
        ttl_based = token.time_to_expiry() - self._safety_buffer
        candidate = min(self._rotate_every, ttl_based)
        return max(candidate, MIN_SLEEP)

    async def close(self) -> None:
        """Release source + sink resources. Idempotent."""
        try:
            await self._source.close()
        except Exception:
            logger.exception("refresher %s: source.close() failed", self._name)
        try:
            await self._sink.close()
        except Exception:
            logger.exception("refresher %s: sink.close() failed", self._name)


__all__ = ["MIN_SLEEP", "TokenRefresher"]
