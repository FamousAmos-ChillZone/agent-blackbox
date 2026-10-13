"""Watching one running sandbox process against its deadline and the host egress caps.

Shared by every sandbox kind (gVisor container, Firecracker microVM): each one
starts its process, then hands it here. :func:`watch` reads the process's
stdout in short slices; between slices it asks the :class:`EgressGuard`
whether the sandbox's address went over a cap. The answer has three outcomes
(LES-011) and only a definite yes kills.

The sandbox's address may not be known when the process starts (a container
gets one from Docker a moment later), so it is asked for through *address*
until it answers; the first answer is cleared in the guard — whatever a
previous sandbox at that address left is not this one's — and recorded in
*watched* so the caller can clear it again once the sandbox is gone.

Usage::

    watched = []
    try:
        report = watch(process, timeout, egress, lambda: "172.30.4.10", watched)
    except subprocess.TimeoutExpired: ...   # kill: deadline
    except CaughtScanning: ...              # kill: scanning
    finally:
        for address in watched: egress.forget(address)
"""

from __future__ import annotations

import subprocess
import time
from typing import Callable, List, Optional

from .egress import EgressGuard

#: How often a networked sandbox's address is checked against the egress caps.
WATCH_INTERVAL_SECONDS = 0.2


class CaughtScanning(Exception):
    """The egress guard listed the sandbox's address as over a cap."""


def watch(process: subprocess.Popen[bytes], timeout_seconds: float, egress: EgressGuard,
          address: Callable[[], Optional[str]], watched: list[str]) -> bytes:
    """The process's stdout once it exits. Retrying ``communicate`` after its
    timeout loses no output. Raises ``subprocess.TimeoutExpired`` at the
    deadline and :class:`CaughtScanning` on a definite yes from the guard
    (None — could not tell — never kills)."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(str(process.args), timeout_seconds)
        try:
            report, _ = process.communicate(timeout=min(WATCH_INTERVAL_SECONDS, remaining))
            return report
        except subprocess.TimeoutExpired:
            pass
        if not watched:
            seen = address()
            if seen is None:
                continue
            egress.forget(seen)
            watched.append(seen)
        if egress.offended(watched[0]) is True:
            raise CaughtScanning()
