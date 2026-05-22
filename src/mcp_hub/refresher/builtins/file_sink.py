"""File-on-disk :class:`TokenSink`.

Writes a token to a path on the local filesystem with restrictive
permissions, atomically. Consumers (the hub's bao-login flow, today;
any other tool tomorrow) read the path each time they need a token —
the atomic rename guarantees they see either the previous full token
or the newly-rotated one, never an empty or half-written file.

Important constraint: the destination path's PARENT DIRECTORY must be
writable by the hub process. If the destination is inside a Docker
bind-mounted single-file mount (e.g.
``-v /host/file:/container/file``), the rename will fail because the
file's inode is bound to the host's. Bind-mount the *directory*
instead. The compose file does this for the config dir.

Registered as the entry point ``file`` in group ``mcp_hub.token_sinks``
(see ``pyproject.toml``).
"""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from ..protocols import Token, TokenWriteError

logger = logging.getLogger(__name__)


class FileSink:
    """Atomically write tokens to a file path."""

    name = "file"

    def __init__(
        self,
        *,
        path: Path | str,
        mode: int | str = 0o400,
        owner_uid: int | None = None,
        owner_gid: int | None = None,
    ) -> None:
        self._path = Path(path)
        # YAML 1.1 doesn't parse `0o400` as octal — users get a string.
        # Accept `0o`/`0x`/`0b` prefixes + decimal via int(s, 0), plus the
        # classic leading-zero octal form (`0400`, `0600`) that policy.yaml
        # writers expect. int(s, 0) rejects leading-zero literals, so treat a
        # leading `0` (without an 0o/0x/0b prefix) as octal explicitly.
        if isinstance(mode, str):
            s = mode.strip()
            try:
                if len(s) > 1 and s[0] == "0" and s[1] not in "oObBxX":
                    mode = int(s, 8)
                else:
                    mode = int(s, 0)
            except ValueError as exc:
                raise ValueError(
                    f"FileSink mode must be int or numeric string "
                    f"(e.g. '0o400', '0400'); got {mode!r}"
                ) from exc
        self._mode = mode
        self._owner_uid = owner_uid
        self._owner_gid = owner_gid
        if owner_gid is not None and owner_uid is None:
            raise ValueError("owner_gid set without owner_uid; specify both or neither")

    async def write(self, token: Token) -> None:
        # Same-directory tmp file so os.replace is a same-fs rename
        # (POSIX rename(2) atomicity guarantee). Suffix carries pid +
        # nonce to avoid collisions if two refreshers ever share a
        # path (which would itself be a config bug, but defensive).
        nonce = secrets.token_hex(4)
        tmp_path = self._path.with_name(
            f"{self._path.name}.tmp.{os.getpid()}.{nonce}"
        )

        # Ensure parent dir exists. Doesn't try to set its perms — that's
        # an external concern (the bind-mount or the LXC bootstrap sets
        # the dir's mode). Just don't crash if the path is fresh.
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TokenWriteError(
                f"FileSink: parent dir {self._path.parent} not creatable: {exc}",
                transient=False,
            ) from exc

        # O_EXCL on the temp file — if a stale tmp exists from a crashed
        # writer, fail loudly rather than silently overwriting another
        # process's in-flight write.
        try:
            fd = os.open(
                str(tmp_path),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                self._mode,
            )
        except FileExistsError as exc:
            raise TokenWriteError(
                f"FileSink: tmp file {tmp_path} already exists; "
                f"another writer crashed mid-rotation? Remove the stale "
                f"tmp file manually."
            ) from exc
        except OSError as exc:
            raise TokenWriteError(
                f"FileSink: failed to open tmp file {tmp_path}: {exc}"
            ) from exc

        try:
            try:
                os.write(fd, token.value.encode("utf-8"))
                # fsync so the bytes hit disk before the rename. Without
                # this, a crash between rename and the kernel flush
                # could leave a zero-byte file at the destination.
                os.fsync(fd)
            finally:
                os.close(fd)

            # Apply ownership AFTER write but BEFORE replace. The file
            # at the temp path is the only thing visible to other
            # processes (and only via directory listing); the
            # destination remains the previous valid token until rename.
            if self._owner_uid is not None:
                if not hasattr(os, "chown"):
                    # Windows dev host. Mode + ownership semantics are
                    # POSIX-only; warn and continue. The deploy target
                    # is Linux, so this branch is dev-host noise.
                    logger.warning(
                        "FileSink: os.chown not available (non-POSIX host); "
                        "skipping owner_uid=%s",
                        self._owner_uid,
                    )
                else:
                    gid = self._owner_gid if self._owner_gid is not None else self._owner_uid
                    try:
                        os.chown(str(tmp_path), self._owner_uid, gid)
                    except OSError as exc:
                        # CAP_CHOWN missing in container, etc. Fatal —
                        # the consumer might be running as a different
                        # UID and need this perm to read.
                        raise TokenWriteError(
                            f"FileSink: chown {self._owner_uid}:{gid} on "
                            f"{tmp_path} failed: {exc}; check CAP_CHOWN"
                        ) from exc

            try:
                os.replace(str(tmp_path), str(self._path))
            except OSError as exc:
                raise TokenWriteError(
                    f"FileSink: rename {tmp_path} -> {self._path} failed: {exc}"
                ) from exc
        except BaseException:
            # Anything went wrong after open() — clean up the tmp file.
            # Use try/except to avoid masking the original exception.
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception("FileSink: failed to clean up tmp file %s", tmp_path)
            raise

        logger.info(
            "FileSink: wrote %s (mode=0o%o, owner=%s, %d bytes, exp=%s)",
            self._path,
            self._mode,
            f"{self._owner_uid}:{self._owner_gid or self._owner_uid}"
            if self._owner_uid is not None
            else "(unchanged)",
            len(token.value),
            token.expires_at.isoformat(),
        )

    async def close(self) -> None:
        # Stateless — nothing to release.
        return None


__all__ = ["FileSink"]
