"""The reader's own copy of the trust statements it verified (Community Curation C3).

Shared memory forgets after about 30 days, a busy node answers "nothing", and
anyone can publish junk beside a curator's statement. So what the network
shows at any one moment is not the state of record for trust — this file is:
``$BLACKBOX_HOME/community_trust.json`` holds, per community graph, the key
manifests and the CURRENT curator statements this node has verified, as the
signed rows themselves.

Two properties make that safe:

* nothing in the file is trusted for being there — every row is verified
  again, against the pinned roots and the effective manifest, each time it is
  loaded into a view. Editing the file can only remove trust, never add it;
* trust only moves forward — a listing ends on its signed expiry day or by a
  signed delisting, a verdict by a newer signed verdict. A statement that is
  merely ABSENT from one read stays. Because the highest sequence number per
  statement is kept, an old statement replayed later cannot undo a newer one.

The file also remembers which enforcement-raising statements this node has
ADMITTED and on which of its own days, which the daily cap on raising
statements uses (:mod:`.raising_budget`): the first read of a node is a
baseline, exempt.

It holds only statements that are public in the community graph (curator keys,
reporter keys and addresses, threat identifiers) — nothing about this
operator. It is rebuilt from the network if deleted.

Pattern: Repository — one class, one lock, atomic write; pure pruning function.

Usage::

    store = TrustStore()
    stored = store.load(graph)                         # StoredTrust (empty when unknown)
    ...verify stored.manifests + stored.statements + fresh rows...
    store.remember(graph, verified_manifest_rows, verified_statement_rows, admitted=admission.admitted)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from ...kernel import constants, signing, threat_ids, yaml_files
from ...kernel.signing.statement_order import CuratorStatement

logger = logging.getLogger(__name__)

_STORE_FILE = "community_trust.json"
#: A statement signed longer ago than this is dropped (the longest community
#: lifetime is 460 days, the longest listing 366).
MAX_STATEMENT_AGE_DAYS = 500
#: Bounds: statements and manifests kept per graph, and how many pauses (the
#: "same two keys cannot chain pauses" rule needs the previous ones).
MAX_STORED_STATEMENTS = 20_000
MAX_STORED_MANIFESTS = 8
PAUSES_KEPT = 4
#: Statement kinds where each curator KEY has its own current statement.
_PER_KEY_KINDS = frozenset({CuratorStatement.HEARTBEAT.value, CuratorStatement.AWAY.value})

Row = Dict[str, str]


@dataclass(frozen=True)
class StoredTrust:
    """One graph's stored trust: ``manifests`` and ``statements`` (plain rows,
    unverified until the caller checks them), ``admitted`` — the raising
    statements this node acts on and the reader-day each was admitted (by
    :func:`statement_key`; ``""`` = part of the baseline), and
    ``baseline_until`` — the time of the first read (None before any)."""

    manifests: Tuple[Row, ...] = ()
    statements: Tuple[Row, ...] = ()
    admitted: Mapping[str, str] = field(default_factory=dict)
    baseline_until: Optional[float] = None

    @property
    def identifiers(self) -> List[str]:
        """The identifiers the stored statements are about (worth asking for again)."""
        return list(dict.fromkeys(row.get("identifier", "") for row in self.statements if row.get("identifier")))


def statement_key(row: Mapping[str, str]) -> str:
    """A short stable key for one signed statement: what was SIGNED, not how
    the row is written (KI-266). One statement can be published as many
    different texts that all verify, by anyone, with no key; they all have
    this one key, so they take one place in the store and in the daily cap.
    A row that is not a statement at all is keyed by its subject and text."""
    text = str(row.get("signedStatement", ""))
    envelope = signing.from_text(text)
    return threat_ids.stable_hash(signing.content_id(envelope) if envelope is not None else f"{row.get('r', '')}\n{text}", 20)


def _age_days(day: str, today: str) -> int:
    try:
        return (date.fromisoformat(today) - date.fromisoformat(day)).days
    except ValueError:
        return 0   # an unreadable day is kept (pruning must never remove a reduction by accident)


def current_statements(rows: Iterable[Mapping[str, str]], today: str) -> List[Row]:
    """The rows worth keeping: per (kind, identifier) — per curator key for
    heartbeats and away notices — only the highest sequence number (every row
    at that number, so ties stay decidable); the newest ``PAUSES_KEPT`` pauses;
    nothing signed more than ``MAX_STATEMENT_AGE_DAYS`` ago. Newest first,
    capped at ``MAX_STORED_STATEMENTS``. Rows must already be verified."""
    groups: Dict[Tuple[str, str, str], List[Tuple[int, str, Row]]] = {}
    for row in rows:
        envelope = signing.from_text(row.get("signedStatement", ""))
        if envelope is None:
            continue
        day = str(envelope.payload.get("day", ""))
        if _age_days(day, today) > MAX_STATEMENT_AGE_DAYS:
            continue
        kind = envelope.statement_type
        key_field = str(envelope.payload.get("key", "")) if kind in _PER_KEY_KINDS else ""
        plain = {"r": str(row.get("r", "")), "identifier": str(row.get("identifier", "")),
                 "signedStatement": str(row.get("signedStatement", ""))}
        groups.setdefault((kind, str(envelope.payload.get("identifier", "")), key_field), []).append(
            (envelope.sequence, day, plain))
    kept: List[Tuple[str, Row]] = []
    for (kind, _identifier, _key), entries in groups.items():
        if kind == CuratorStatement.PAUSE.value:
            numbers = sorted({sequence for sequence, _, _ in entries}, reverse=True)[:PAUSES_KEPT]
        else:
            numbers = [max(sequence for sequence, _, _ in entries)]
        kept.extend((day, row) for sequence, day, row in entries if sequence in numbers)
    kept.sort(key=lambda item: item[0], reverse=True)
    return [row for _, row in kept[:MAX_STORED_STATEMENTS]]


class TrustStore:
    """``$BLACKBOX_HOME/community_trust.json`` — see the module docstring.
    Instances are cheap and share ONE lock, so every read-modify-write of the
    file in this process is serialised whichever instance does it."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (constants.blackbox_home() / _STORE_FILE)
        self._clock = clock

    def load(self, graph: str) -> StoredTrust:
        """What this node has stored for *graph* (empty when nothing, or the file is unreadable)."""
        with self._lock:
            return self._entry(self._read(), graph)

    def remember(self, graph: str, manifests: Iterable[Mapping[str, str]],
                 statements: Iterable[Mapping[str, str]], *, admitted: Optional[Mapping[str, str]] = None) -> StoredTrust:
        """Replace *graph*'s stored trust with these VERIFIED rows, pruned to
        the current ones, and with *admitted* (the raising statements acted on
        — kept only for rows that are kept). Writes only when something
        changed. Fail-open: an unwritable home only costs the memory, never
        the read."""
        with self._lock:
            data = self._read()
            before = self._entry(data, graph)
            now = self._clock()
            today = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
            kept = current_statements(statements, today)
            keys = {statement_key(row) for row in kept}
            source = before.admitted if admitted is None else admitted
            manifest_rows = _newest_manifests(manifests)
            after = StoredTrust(manifests=tuple(manifest_rows), statements=tuple(kept),
                                admitted={key: day for key, day in source.items() if key in keys},
                                baseline_until=before.baseline_until if before.baseline_until is not None else now)
            if after != before:
                data.setdefault("graphs", {})[graph] = {
                    "manifests": list(after.manifests), "statements": list(after.statements),
                    "admitted": dict(after.admitted), "baseline_until": after.baseline_until}
                self._write(data)
            return after

    def forget(self, graph: Optional[str] = None) -> None:
        """Drop one graph's stored trust, or all of it (tests, and a graph the operator left)."""
        with self._lock:
            data = self._read()
            if graph is None:
                data = {}
            else:
                data.get("graphs", {}).pop(graph, None)
            self._write(data)

    # -- file -------------------------------------------------------------

    @staticmethod
    def _entry(data: Mapping[str, object], graph: str) -> StoredTrust:
        try:
            entry = dict(dict(data.get("graphs") or {}).get(graph) or {})
            baseline = entry.get("baseline_until")
            return StoredTrust(
                manifests=tuple(_plain_rows(entry.get("manifests"))),
                statements=tuple(_plain_rows(entry.get("statements"))),
                admitted={str(k): str(v) for k, v in dict(entry.get("admitted") or {}).items()},
                baseline_until=float(baseline) if baseline is not None else None)
        except (TypeError, ValueError):
            return StoredTrust()

    def _read(self) -> Dict[str, object]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}   # missing or unreadable: rebuilt from the network

    def _write(self, data: Mapping[str, object]) -> None:
        try:
            yaml_files.atomic_write(self._path, json.dumps({"version": 1, **dict(data)}))
        except OSError as exc:
            logger.warning("blackbox: could not save the community trust store (%s)", exc)


def _plain_rows(value: object) -> List[Row]:
    rows: List[Row] = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, dict):
            rows.append({"r": str(item.get("r", "")), "identifier": str(item.get("identifier", "")),
                         "signedStatement": str(item.get("signedStatement", ""))})
    return rows


def _newest_manifests(rows: Iterable[Mapping[str, str]]) -> List[Row]:
    """The newest ``MAX_STORED_MANIFESTS`` manifest rows by (root epoch, version)."""
    ordered: List[Tuple[Tuple[int, int], Row]] = []
    for row in rows:
        envelope = signing.from_text(row.get("signedStatement", ""))
        if envelope is not None:
            ordered.append(((envelope.root_epoch, envelope.sequence),
                            {"r": str(row.get("r", "")), "identifier": "",
                             "signedStatement": str(row.get("signedStatement", ""))}))
    ordered.sort(key=lambda item: item[0], reverse=True)
    return [row for _, row in ordered[:MAX_STORED_MANIFESTS]]


def held_manifest_texts(graph: str) -> Tuple[str, ...]:
    """The signed key manifests this node holds for *graph*, as texts (each was
    verified against the pinned root when it was stored) — the chain an export
    bundle carries so a receiver can check everything from the root down."""
    return tuple(sorted(row["signedStatement"] for row in TrustStore().load(graph).manifests if row.get("signedStatement")))


def manifest_orders(rows: Iterable[Mapping[str, str]]) -> List[Tuple[int, int]]:
    """The (root epoch, version) of each stored manifest row — what the next lookup probes beyond."""
    orders = []
    for row in rows:
        envelope = signing.from_text(row.get("signedStatement", ""))
        if envelope is not None:
            orders.append((envelope.root_epoch, envelope.sequence))
    return orders
