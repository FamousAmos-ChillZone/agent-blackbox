"""Intake — the curator node watches the community tier and notifies (Refine R6).

Plan §09 INTAKE: ``blackbox curate watch`` polls the delta view and tells the
curator about NEW threats through ONE webhook — the direction the shipped
graph never proved (a report on bench B reaching the curator's queue).

Pattern: Observer — :class:`IntakeWatcher` remembers what it already announced
(``$BLACKBOX_HOME/curate/intake_seen.json``) and notifies a sink;
:class:`WebhookSink` POSTs JSON to the operator's URL (3 s timeout, never
raises); any object with ``notify(event)`` is a sink (tests use a list).

Usage::

    watcher = IntakeWatcher()
    announced = watcher.poll(delta_view, WebhookSink(url))
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional, Protocol, Set

from . import keys
from .queue import DeltaView, QueueItem

logger = logging.getLogger(__name__)

_SEEN_FILE = "intake_seen.json"
_WEBHOOK_TIMEOUT = 3.0
#: Most identifiers remembered (the oldest announced are forgotten first).
_MAX_SEEN = 50_000


@dataclass(frozen=True)
class IntakeEvent:
    """What the webhook receives for one new threat: the item's facts only."""

    identifier: str
    stage: str
    enforcement: str
    reporters: int
    lane: int


class IntakeSink(Protocol):
    """Where announcements go. Each method returns False when the notification
    was NOT delivered (the watcher then tries again next round); True or None
    counts as delivered."""

    def notify(self, event: IntakeEvent) -> Optional[bool]: ...

    def notify_alarm(self, item: Any) -> Optional[bool]: ...


class WebhookSink:
    """POSTs each event as JSON to *url*. Fail-open: a failed delivery is logged, never raised."""

    def __init__(self, url: str) -> None:
        self._url = url

    def notify(self, event: IntakeEvent) -> bool:
        return self._post(asdict(event), event.identifier)

    def notify_alarm(self, item: Any) -> bool:
        """R10b: a curator-audience alarm ({audience, class, message, what_to_do})."""
        return self._post({"kind": "alarm", **item.as_dict()}, item.message)

    def _post(self, body: dict, what: str) -> bool:
        """True when the webhook accepted the POST (a failed delivery is logged and retried next round)."""
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self._url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=_WEBHOOK_TIMEOUT):
                return True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("blackbox curate: webhook failed for %s: %s", what, exc)
            return False


class AlarmWatcher:
    """R10b: delivers each curator alarm ONCE per message to the sink (same shape as the intake watcher)."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / "alarms_seen.json")
        self._lock = threading.Lock()

    def poll(self, items: Iterable[Any], sink: "IntakeSink") -> List[str]:
        """Notify *sink* of every alarm message not delivered before; returns them."""
        with self._lock:
            seen = _load_seen(self._path)
            fresh = [item for item in items if item.message not in seen]
            delivered = [item for item in fresh if sink.notify_alarm(item) is not False]
            seen.update(item.message for item in delivered)   # an undelivered alarm is tried again next round
            _save_seen(self._path, seen)
        return [item.message for item in delivered]


def _load_seen(path: Path) -> Set[str]:
    try:
        return set(str(x) for x in json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return set()


def _save_seen(path: Path, seen: Set[str]) -> None:
    kept = sorted(seen)[-_MAX_SEEN:]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
    tmp.write_text(json.dumps(kept), encoding="utf-8")
    os.replace(tmp, path)


class IntakeWatcher:
    """Announces each NEW queue item once. One lock; atomic, bounded memory."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _SEEN_FILE)
        self._lock = threading.Lock()

    def poll(self, view: DeltaView, sink: IntakeSink) -> List[str]:
        """Notify *sink* of every item not announced before; returns their identifiers."""
        with self._lock:
            seen = self._load()
            fresh = [item for item in view.new if item.identifier not in seen]
            delivered = [item for item in fresh if sink.notify(_event(item)) is not False]
            seen.update(item.identifier for item in delivered)   # KI-261: announced means DELIVERED
            self._save(seen)
        return [item.identifier for item in delivered]

    def _load(self) -> Set[str]:
        try:
            return set(str(x) for x in json.loads(self._path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            return set()

    def _save(self, seen: Set[str]) -> None:
        kept = sorted(seen)[-_MAX_SEEN:]
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(f"{self._path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
        tmp.write_text(json.dumps(kept), encoding="utf-8")
        os.replace(tmp, self._path)


def _event(item: QueueItem) -> IntakeEvent:
    return IntakeEvent(identifier=item.identifier, stage=item.stage, enforcement=item.enforcement,
                       reporters=item.reporters, lane=item.lane.value)
