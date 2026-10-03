"""What the curator has said, as this node can verify it (Refine R2).

Builds ONE :class:`CuratorView` from root-signed key manifests and curator
statements read from both graphs:

* TRUST — a key manifest counts only when signed by a ROOT this network
  trusts (``kernel.signing.trust_anchors``); which manifest a reader acts on
  is ``community.trust.manifests``. No root = no manifest = no curator
  statement counts.
* PLACEMENT — enforcement-affecting statements (promotion, revocation, pause,
  the counted-author list) count only from the VERIFIED graph;
  advisory ones only from the COMMUNITY graph (plan §06). A statement signed
  for the wrong graph does not count.
* LATEST — per threat, the current verdict is the highest sequence, a
  terminal statement (revocation, rejection) winning ties and beating
  replays (:mod:`...kernel.signing.statement_order`).

Pattern: Value Object (:class:`CuratorView`) built by a pure function from
rows the reader fetched.

Usage (from the reader)::

    view = curator_view.build_view(manifest, verified_rows, community_rows,   # manifest: community.trust.manifests
                                   verified_graph=vm_graph, community_graph=community_graph)
    view.is_counted(author_key), view.rejected(identifier), view.revoked
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, AbstractSet, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from ...kernel.signing import key_manifest, statement_order
from ...kernel.signing.statement_order import CuratorStatement
from . import curator_statements
from .curator_statements import CuratorRecord

logger = logging.getLogger(__name__)
from .disputes import VerifiedDispute


#: Statement types that count only from the verified graph (plan §06).
VERIFIED_GRAPH_KINDS = frozenset({CuratorStatement.PROMOTION, CuratorStatement.REVOCATION,
                                  CuratorStatement.PAUSE, CuratorStatement.COUNTED_AUTHORS})
#: Statement types that decide a threat's verdict.
_VERDICT_KINDS = frozenset({CuratorStatement.CONFIRMATION, CuratorStatement.REJECTION, CuratorStatement.REVOCATION,
                            CuratorStatement.IN_REVIEW, CuratorStatement.DEFERRAL, CuratorStatement.DEFERRAL_LAPSED})


@dataclass(frozen=True)
class CountedAuthor:
    """One currently counted author: ``key`` (the reporter key — the
    identity), ``address`` (display), ``author_class`` (partner|established),
    ``org`` (partners: one cluster per organisation), ``expires`` (UTC day)."""

    key: str
    address: str
    author_class: str
    org: str
    expires: str


@dataclass(frozen=True)
class CuratorView:
    """Everything the curator has said that this node verified.

    ``manifest`` — the trusted key manifest (None: no curator statement
    counts). ``verdicts`` — the current verdict record per threat.
    ``counted`` — the counted authors, by reporter key (listed, unexpired).
    ``backlog`` / ``away`` — the latest backlog notice and the away notices.
    ``attestations`` — the current (highest-sequence) stage attestation per
    threat (R3-attest); readers prefer it over their local stage unless a
    terminal verdict dominates.
    """

    manifest: Optional[key_manifest.KeyManifest] = None
    verdicts: Mapping[str, CuratorRecord] = field(default_factory=dict)
    counted: Mapping[str, CountedAuthor] = field(default_factory=dict)
    backlog: Optional[CuratorRecord] = None
    away: Tuple[CuratorRecord, ...] = ()
    attestations: Mapping[str, CuratorRecord] = field(default_factory=dict)
    #: R10b: newest heartbeat day per curator key; the newest day any curator statement carries;
    #: True when two trusted manifests share an order with different content (SECURITY).
    heartbeats: Mapping[str, str] = field(default_factory=dict)
    last_statement_day: str = ""
    manifest_conflict: bool = False
    #: R7b: "" | "pending" | "stale" with the day it takes effect / expired; while STALE,
    #: enforcement-RAISING statements dated after the expiry are frozen out — reductions
    #: and already-verified rules keep working.
    manifest_state: str = ""
    manifest_state_day: str = ""
    #: R7b: the day the trusted manifest expires ("" when undated) — the 30-day-ahead alarm.
    manifest_expires_day: str = ""
    #: The newest signed PAUSE's `until` day ("" = none) — enforced by the community tier.
    pause_until: str = ""
    #: KI-228: True when a page of manifests or curator statements FAILED (not when it was
    #: legitimately empty). Readers must then keep their last good stages — an empty view
    #: here would silently de-list every counted author and drop every threat to MONITOR.
    unavailable: bool = False

    def is_counted(self, author_key: str) -> bool:
        return author_key in self.counted

    def verdict(self, identifier: str) -> Optional[CuratorStatement]:
        record = self.verdicts.get(identifier)
        return record.kind if record else None

    def pause_active(self, today: str) -> bool:
        """A 2-of-3 signed pause (≤ 7 d) is in force today."""
        return bool(self.pause_until) and today <= self.pause_until

    def attestation(self, identifier: str) -> Optional[CuratorRecord]:
        """The curator's current stage attestation for *identifier*, if any."""
        return self.attestations.get(identifier)

    def rejected(self, identifier: str) -> bool:
        return self.verdict(identifier) is CuratorStatement.REJECTION

    @property
    def revoked(self) -> FrozenSet[str]:
        """Threats whose current verdict is a revocation."""
        return frozenset(i for i, r in self.verdicts.items() if r.kind is CuratorStatement.REVOCATION)


def _records(rows: Iterable[Mapping[str, Any]], manifest: key_manifest.KeyManifest, graph: str,
             verified_graph: bool, *, root_keys: AbstractSet[str] = frozenset(),
             curators_silent: bool = False) -> List[CuratorRecord]:
    """Verified records from one graph, keeping only types that may live there."""
    records = []
    root_alone = 0
    for row in rows:
        record = curator_statements.parse_statement(row, manifest, graph=graph, root_keys=root_keys,
                                                    curators_silent=curators_silent)
        if record is None or (record.kind in VERIFIED_GRAPH_KINDS) != verified_graph:
            continue
        if len(record.signers) < (manifest.threshold if record.kind.needs_quorum else 1):   # accepted root-alone
            root_alone += 1
            if root_alone > ROOT_ALONE_PER_READ:
                continue
        records.append(record)
    return records


#: R7b: the offline root alone may sign reductions after this many days without any curator heartbeat.
CURATOR_SILENCE_FOR_ROOT_DAYS = 7


#: Root-alone reductions one read may honour (review round 4: never "disable all" through the root).
ROOT_ALONE_PER_READ = 20


def _curators_silent(records: Iterable[CuratorRecord], today: str, community_readable: bool) -> bool:
    """True only when the community graph was READ, at least one heartbeat has ever
    been seen, and the newest is older than the silence window. An unreadable or
    unconfigured community graph is not silence (review round 4: a compromised root
    plus an eclipsed node must not revoke the whole corpus)."""
    if not community_readable:
        return False
    newest = max((r.day for r in records if r.kind is CuratorStatement.HEARTBEAT), default="")
    if not newest:
        return False
    try:
        return (date.fromisoformat(today) - date.fromisoformat(newest)).days > CURATOR_SILENCE_FOR_ROOT_DAYS
    except ValueError:
        return False


def _frozen_out(records: Iterable[CuratorRecord], state: str, since: str) -> List[CuratorRecord]:
    """While the manifest is STALE, enforcement-raising statements dated after its
    expiry are frozen out; reductions always apply (LES-016)."""
    if state != "stale":
        return list(records)
    return [r for r in records if not (r.kind.raises_enforcement and r.day > since)]


def build_view(manifest: Optional[key_manifest.KeyManifest], verified_rows: Iterable[Mapping[str, Any]],
               community_rows: Iterable[Mapping[str, Any]], *, verified_graph: str, community_graph: str,
               today: Optional[str] = None, manifest_conflict: bool = False,
               root_keys: AbstractSet[str] = frozenset(), community_readable: bool = False) -> CuratorView:
    """The view from a trusted *manifest* and both graphs' statement rows."""
    if manifest is None:
        return CuratorView(manifest_conflict=manifest_conflict)
    day = today or _today()
    state, state_day = key_manifest.manifest_clock(manifest, day)
    first_pass = _records(community_rows, manifest, community_graph, False)
    silent = _curators_silent(first_pass, day, community_readable)
    records = _frozen_out(_records(verified_rows, manifest, verified_graph, True, root_keys=root_keys, curators_silent=silent)
                          + _records(community_rows, manifest, community_graph, False, root_keys=root_keys,
                                     curators_silent=silent), state, state_day)
    return CuratorView(manifest=manifest, verdicts=_current_verdicts(records),
                       counted=_counted_authors(records, today or _today()),
                       backlog=_latest(r for r in records if r.kind is CuratorStatement.BACKLOG),
                       away=tuple(r for r in records if r.kind is CuratorStatement.AWAY),
                       attestations=_current_attestations(records),
                       heartbeats=_heartbeats(records), last_statement_day=max((r.day for r in records), default=""),
                       pause_until=_active_pause_until(records),
                       manifest_conflict=manifest_conflict, manifest_state=state, manifest_state_day=state_day,
                       manifest_expires_day=(state_day if state != "pending" else key_manifest.manifest_clock(manifest, state_day)[1]))


def _heartbeats(records: Iterable[CuratorRecord]) -> Dict[str, str]:
    """Newest heartbeat day per curator key (only a key beating for ITSELF counts)."""
    newest: Dict[str, str] = {}
    for record in records:
        if record.kind is CuratorStatement.HEARTBEAT and record.field("key") in record.signers:
            newest[record.field("key")] = max(newest.get(record.field("key"), ""), record.day)
    return newest


def _current_verdicts(records: Iterable[CuratorRecord]) -> Dict[str, CuratorRecord]:
    by_order: Dict[statement_order.OrderedStatement, CuratorRecord] = {}
    for record in records:
        if record.kind in _VERDICT_KINDS:
            by_order[statement_order.OrderedStatement(record.identifier, record.kind, record.sequence)] = record
    current = statement_order.current_by_threat(by_order)
    return {threat: by_order[ordered] for threat, ordered in current.items()}


def _current_attestations(records: Iterable[CuratorRecord]) -> Dict[str, CuratorRecord]:
    """The highest-sequence attestation per threat: a replayed older one loses."""
    current: Dict[str, CuratorRecord] = {}
    for record in records:
        if record.kind is CuratorStatement.ATTESTATION:
            held = current.get(record.identifier)
            if held is None or record.sequence > held.sequence:
                current[record.identifier] = record
    return current


def _counted_authors(records: Iterable[CuratorRecord], today: str) -> Dict[str, CountedAuthor]:
    """The latest entry per author key (by sequence); listed and unexpired only."""
    latest: Dict[str, CuratorRecord] = {}
    for record in records:
        if record.kind is CuratorStatement.COUNTED_AUTHORS:
            held = latest.get(record.identifier)
            if held is None or record.sequence > held.sequence:
                latest[record.identifier] = record
    counted = {}
    for identifier, record in latest.items():
        if record.field("listed") == "yes" and record.field("expires") >= today:
            key = identifier[len("author:"):]
            counted[key] = CountedAuthor(key=key, address=record.field("address"),
                                         author_class=record.field("class"), org=record.field("org"),
                                         expires=record.field("expires"))
    return counted


def _active_pause_until(records: Iterable[CuratorRecord]) -> str:
    """The `until` day of the pause in force, honouring §09 "not renewable back-to-back by
    the same pair" (KI-229): walking pauses in sequence order, a pause signed by the SAME
    signers as the pause it would extend, dated on or before that pause's `until`, is a
    renewal and is ignored — two keys cannot chain 7-day pauses indefinitely. A pause by
    a different signer set, or one that starts after the previous pause ended, counts."""
    active: Optional[CuratorRecord] = None
    for record in sorted((r for r in records if r.kind is CuratorStatement.PAUSE), key=lambda r: r.sequence):
        if active is not None and record.signers == active.signers and record.day <= active.field("until"):
            logger.info("blackbox: ignoring a back-to-back pause renewal by the same signers (statement #%d)", record.sequence)
            continue
        active = record
    return active.field("until") if active is not None else ""


def _latest(records: Iterable[CuratorRecord]) -> Optional[CuratorRecord]:
    return max(records, key=lambda r: r.sequence, default=None)


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def today_utc() -> str:
    """The reader's UTC day (the clock every curator-statement span uses)."""
    return _today()


def counted_dispute_weight(disputes: Iterable[VerifiedDispute], view: CuratorView) -> Dict[str, int]:
    """Per threat, how many COUNTED authors dispute it. An unlisted author's
    dispute weighs 0 (plan §04): it is shown, never counted toward decay."""
    disputers: Dict[str, set] = {}
    for dispute in disputes:
        if view.is_counted(dispute.author):
            disputers.setdefault(dispute.identifier, set()).add(dispute.author)
    return {identifier: len(authors) for identifier, authors in disputers.items()}
