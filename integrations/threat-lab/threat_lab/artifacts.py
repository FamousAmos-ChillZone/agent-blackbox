"""Raw artifacts (downloaded archives, probe reports) kept by sha256 for 90 days,
then deleted (proposal §03.5 ground rules, F-015).

Raw artifacts never leave the lab: curators read the job's output only (hosts,
sha256 digests, note codes). A file's
age is its modification time, set when it is stored; storing the same bytes again
restarts its 90 days (it was seen again). :meth:`ArtifactStore.sweep` deletes
everything older — the runner calls it at start-up and daily, and
``threat-lab sweep`` runs it by hand.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from pathlib import Path
from typing import Callable, List

from .config import RETENTION_DAYS

_DAY_SECONDS = 86_400
_SHA256_NAME = re.compile(r"^[0-9a-f]{64}$")


class ArtifactStore:
    """``<root>/<sha256>`` files, one per distinct artifact."""

    def __init__(self, root: Path, clock: Callable[[], float] = time.time,
                 retention_days: int = RETENTION_DAYS) -> None:
        self._root = root
        self._clock = clock
        self._retention_seconds = retention_days * _DAY_SECONDS

    def put(self, data: bytes) -> str:
        """Store *data*; returns its sha256. Safe from several jobs at once: each
        writer fills its own temporary file, and the final rename is atomic."""
        digest = hashlib.sha256(data).hexdigest()
        self._root.mkdir(parents=True, exist_ok=True)
        path = self._root / digest
        if not path.exists():
            # One temporary file PER WRITER: two jobs storing the same bytes at once
            # (the same guest report, the same download) must not share it, or the
            # second's rename finds it already moved and the job fails (FIX-0094).
            partial = self._root / f".{digest}.{uuid.uuid4().hex}.partial"
            partial.write_bytes(data)
            os.replace(partial, path)
        now = self._clock()
        os.utime(path, (now, now))
        return digest

    def path(self, digest: str) -> Path:
        if not _SHA256_NAME.match(digest):
            raise ValueError("an artifact is named by its sha256")
        return self._root / digest

    def sweep(self) -> List[str]:
        """Delete artifacts older than the retention window; returns their names."""
        if not self._root.is_dir():
            return []
        cutoff = self._clock() - self._retention_seconds
        deleted = []
        for path in self._root.iterdir():
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                deleted.append(path.name)
        return sorted(deleted)
