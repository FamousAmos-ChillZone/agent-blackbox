"""Local overrides — `blackbox rules unblock` (Refine R7b, plan §06 ASYMMETRIC SAFETY).

Every operator keeps a release valve: a verified rule that blocks here can be
demoted to FLAG on this machine only. The override is LOCAL (never shared,
never a statement on any graph), AUDITED (the store itself is the record:
who, when, why; every hook decision it changes says "local override"), and
it only ever REDUCES enforcement — there is no `rules block` because raising
enforcement needs the curators' 2-of-3, never one operator.

One class, one lock, atomic file: ``$BLACKBOX_HOME/overrides.json``.

Usage::

    store = OverrideStore()
    store.unblock("dep:npm:evil@1.0.0", reason="false positive in our CI")
    store.is_unblocked("dep:npm:evil@1.0.0")      # True
    blocking, demoted = demote_blocking(findings, store.unblocked())
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

from ..kernel import constants

logger = logging.getLogger(__name__)
_STORE_FILE = "overrides.json"
_MAX_REASON = 200


@dataclass(frozen=True)
class LocalOverride:
    """``identifier`` demoted BLOCK → FLAG on this machine; ``reason`` (the
    operator's words, clamped); ``day`` (UTC day it was set)."""

    identifier: str
    reason: str
    day: str

    def as_json(self) -> Dict[str, str]:
        return {"identifier": self.identifier, "reason": self.reason, "day": self.day}


class OverrideStore:
    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (constants.blackbox_home() / _STORE_FILE)
        self._lock = threading.Lock()

    def current(self) -> Dict[str, LocalOverride]:
        with self._lock:
            return self._load()

    def unblocked(self) -> FrozenSet[str]:
        return frozenset(self.current())

    def is_unblocked(self, identifier: str) -> bool:
        return identifier in self.current()

    def unblock(self, identifier: str, reason: str) -> LocalOverride:
        """Demote *identifier* to FLAG here (idempotent; the newest reason wins)."""
        override = LocalOverride(identifier=identifier.strip(), reason=str(reason or "")[:_MAX_REASON],
                                 day=datetime.now(timezone.utc).date().isoformat())
        with self._lock:
            current = self._load()
            current[override.identifier] = override
            self._save(current)
        logger.warning("blackbox: LOCAL OVERRIDE — %s blocks no more on this machine (flag only): %s",
                       override.identifier, override.reason or "no reason given")
        return override

    def reblock(self, identifier: str) -> bool:
        """Remove the override (the verified rule blocks again). True when one was removed."""
        with self._lock:
            current = self._load()
            if identifier not in current:
                return False
            del current[identifier]
            self._save(current)
        logger.warning("blackbox: local override removed — %s blocks again", identifier)
        return True

    def _load(self) -> Dict[str, LocalOverride]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {str(item["identifier"]): LocalOverride(str(item["identifier"]), str(item.get("reason", "")),
                                                           str(item.get("day", "")))
                    for item in data.get("overrides", []) if isinstance(item, dict) and item.get("identifier")}
        except (OSError, ValueError, TypeError, KeyError):
            return {}

    def _save(self, current: Dict[str, LocalOverride]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(f"{self._path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
            tmp.write_text(json.dumps({"overrides": [o.as_json() for o in current.values()]}), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            logger.warning("blackbox: could not save local overrides (%s)", exc)


def demote_blocking(findings: Iterable[Any], unblocked: FrozenSet[str]) -> Tuple[List[Any], List[Any]]:
    """Split would-block *findings* into (still blocking, demoted by a local override)."""
    blocking, demoted = [], []
    for finding in findings:
        (demoted if getattr(finding, "identifier", "") in unblocked else blocking).append(finding)
    return blocking, demoted
