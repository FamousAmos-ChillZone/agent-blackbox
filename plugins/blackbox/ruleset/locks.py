"""Cross-process refresh locking (fcntl on POSIX, msvcrt on Windows).

``_ruleset_refresh_lock`` guarantees one refresh at a time across every agent
process sharing a ``$BLACKBOX_HOME``; ``_refresh_lock`` is the in-process half.
"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import os
import threading
import time
from typing import Any, Callable
from ..kernel import constants
from . import disk_cache

_refresh_lock = threading.Lock()
_WINDOWS_FILE_LOCK_TIMEOUT_S = 30.0
_WINDOWS_FILE_LOCK_POLL_S = 0.05


def _is_windows_platform() -> bool:
    return os.name == "nt"


@contextmanager
def _ruleset_refresh_lock(*, blocking: bool):
    """Serialize expensive VM reads across threads and Blackbox processes."""
    thread_acquired = _refresh_lock.acquire(blocking=blocking)
    if not thread_acquired:
        yield False
        return

    lock_fh = None
    file_acquired = False
    try:
        try:
            home = constants.blackbox_home()
            home.mkdir(parents=True, exist_ok=True)
            lock_fh = open(disk_cache._lock_path(), "a+b")  # windows-footgun: ok - binary byte lock
            if _is_windows_platform():  # pragma: no cover - exercised via helper
                if disk_cache._lock_path().stat().st_size == 0:
                    lock_fh.write(b"0")
                    lock_fh.flush()
                lock_fh.seek(0)
                if not _acquire_windows_file_lock(lock_fh, blocking=blocking):
                    lock_fh.close()
                    lock_fh = None
                    yield False
                    return
            else:
                import fcntl

                operation = fcntl.LOCK_EX
                if not blocking:
                    operation |= fcntl.LOCK_NB
                fcntl.flock(lock_fh.fileno(), operation)
            file_acquired = True
        except BlockingIOError:
            if lock_fh is not None:
                lock_fh.close()
                lock_fh = None
            yield False
            return
        except OSError:
            if _is_windows_platform():
                if lock_fh is not None:
                    lock_fh.close()
                    lock_fh = None
                yield False
                return
            if lock_fh is not None:
                lock_fh.close()
                lock_fh = None
        except Exception:
            if lock_fh is not None:
                lock_fh.close()
                lock_fh = None
            if _is_windows_platform():
                yield False
                return
            # Retain the in-process guard on platforms without a usable file
            # lock. Ruleset refreshes are fail-open by design.

        yield True
    finally:
        if lock_fh is not None:
            try:
                if file_acquired:
                    if _is_windows_platform():  # pragma: no cover - exercised on Windows
                        import msvcrt

                        lock_fh.seek(0)
                        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            finally:
                lock_fh.close()
        _refresh_lock.release()


def _acquire_windows_file_lock(
    lock_fh: Any,
    *,
    blocking: bool,
    msvcrt_module: Any = None,
    timeout_s: float = _WINDOWS_FILE_LOCK_TIMEOUT_S,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Acquire one Windows byte lock within a bounded contention window."""
    if msvcrt_module is None:  # pragma: no cover - imported only on Windows
        import msvcrt as msvcrt_module

    deadline = monotonic() + max(0.0, timeout_s)
    while True:
        lock_fh.seek(0)
        try:
            msvcrt_module.locking(
                lock_fh.fileno(),
                msvcrt_module.LK_NBLCK,
                1,
            )
            return True
        except OSError as exc:
            if not blocking:
                return False
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                return False
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False
            sleep(min(_WINDOWS_FILE_LOCK_POLL_S, remaining))
