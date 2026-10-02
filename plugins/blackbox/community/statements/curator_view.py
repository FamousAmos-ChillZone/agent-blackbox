"""What the curator has said, as this node can verify it (Refine R2).

Builds ONE :class:`CuratorView` from root-signed key manifests and curator
statements read from both graphs:

* TRUST — a key manifest counts only when signed by a ROOT this network
  trusts (:func:`trusted_roots`). Roots are pinned per network in
  ``constants.CURATOR_ROOT_KEYS``. Only a network with no pinned root (a
  sandbox) may take roots from the ``BLACKBOX_CURATOR_ROOT_KEYS`` environment
  variable. The root is deliberately NOT a config-file setting, so a config
  edit can never move trust. No root = no manifest = no curator statement
  counts.
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

    roots = curator_view.trusted_roots(environment)
    manifest = curator_view.newest_trusted_manifest(manifest_rows, environment, vm_graph, roots)
    view = curator_view.build_view(manifest, verified_rows, community_rows,
                                   verified_graph=vm_graph, community_graph=community_graph)
    view.is_counted(author_key), view.rejected(identifier), view.revoked
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AbstractSet, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from ...kernel import constants, signing, sparql_text
from ...kernel.dkg_client import extract_binding
from ...kernel.signing import key_manifest, statement_order
from ...kernel.signing.statement_order import CuratorStatement
from . import curator_statements
from .curator_statements import CuratorRecord
from .disputes import VerifiedDispute

_ROOT_ENV = "BLACKBOX_CURATOR_ROOT_KEYS"
_KEY_HEX = re.compile(r"[0-9a-f]{64}")

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

    def is_counted(self, author_key: str) -> bool:
        return author_key in self.counted

    def verdict(self, identifier: str) -> Optional[CuratorStatement]:
        record = self.verdicts.get(identifier)
        return record.kind if record else None

    def attestation(self, identifier: str) -> Optional[CuratorRecord]:
        """The curator's current stage attestation for *identifier*, if any."""
        return self.attestations.get(identifier)

    def rejected(self, identifier: str) -> bool:
        return self.verdict(identifier) is CuratorStatement.REJECTION

    @property
    def revoked(self) -> FrozenSet[str]:
        """Threats whose current verdict is a revocation."""
        return frozenset(i for i, r in self.verdicts.items() if r.kind is CuratorStatement.REVOCATION)


def trusted_roots(environment: str, env: Mapping[str, str] = os.environ) -> FrozenSet[str]:
    """The curator root keys *environment* (a DKG network id) trusts: the
    pinned ones, else (sandbox networks only) those in the environment
    variable. Malformed keys are ignored."""
    pinned = constants.CURATOR_ROOT_KEYS.get(environment)
    if pinned:
        return frozenset(k.lower() for k in pinned if _KEY_HEX.fullmatch(k.lower()))
    raw = env.get(_ROOT_ENV, "")
    return frozenset(k.strip().lower() for k in raw.split(",") if _KEY_HEX.fullmatch(k.strip().lower()))


def key_manifests_sparql(after: str) -> str:
    """One page of key-manifest rows after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?signedStatement WHERE {{
  ?r a g:KeyManifest ;
     g:signedStatement ?signedStatement .
  {cursor}
}} ORDER BY STR(?r) LIMIT 500
"""


def newest_trusted_manifest(rows: Iterable[Mapping[str, Any]], environment: str, graph: str,
                            roots: AbstractSet[str]) -> Optional[key_manifest.KeyManifest]:
    """The newest manifest (by root epoch, version) signed by one of *roots*."""
    if not roots:
        return None
    return key_manifest.newest(trusted_manifests(rows, environment, graph, roots))


def trusted_manifests(rows: Iterable[Mapping[str, Any]], environment: str, graph: str,
                      roots: AbstractSet[str]) -> List[key_manifest.KeyManifest]:
    """Every root-signed manifest in *rows* for this environment and graph."""
    manifests = []
    for row in rows:
        envelope = signing.from_text(extract_binding(row.get(curator_statements.SIGNED_STATEMENT_VAR)))
        manifest = key_manifest.verify_manifest(envelope, environment=environment, graph=graph, root_keys=roots)
        if manifest is not None:
            manifests.append(manifest)
    return manifests


def manifests_conflict(manifests: Iterable[key_manifest.KeyManifest]) -> bool:
    """R10b SECURITY: two trusted manifests with the same (root epoch, version)
    but different content — someone published a second truth."""
    seen: Dict[Tuple[int, int], str] = {}
    for manifest in manifests:
        digest = manifest.content_hash()
        if seen.setdefault(manifest.order, digest) != digest:
            return True
    return False


def _records(rows: Iterable[Mapping[str, Any]], manifest: key_manifest.KeyManifest, graph: str,
             verified_graph: bool) -> List[CuratorRecord]:
    """Verified records from one graph, keeping only types that may live there."""
    records = []
    for row in rows:
        record = curator_statements.parse_statement(row, manifest, graph=graph)
        if record is not None and (record.kind in VERIFIED_GRAPH_KINDS) == verified_graph:
            records.append(record)
    return records


def build_view(manifest: Optional[key_manifest.KeyManifest], verified_rows: Iterable[Mapping[str, Any]],
               community_rows: Iterable[Mapping[str, Any]], *, verified_graph: str, community_graph: str,
               today: Optional[str] = None, manifest_conflict: bool = False) -> CuratorView:
    """The view from a trusted *manifest* and both graphs' statement rows."""
    if manifest is None:
        return CuratorView(manifest_conflict=manifest_conflict)
    records = (_records(verified_rows, manifest, verified_graph, True)
               + _records(community_rows, manifest, community_graph, False))
    return CuratorView(manifest=manifest, verdicts=_current_verdicts(records),
                       counted=_counted_authors(records, today or _today()),
                       backlog=_latest(r for r in records if r.kind is CuratorStatement.BACKLOG),
                       away=tuple(r for r in records if r.kind is CuratorStatement.AWAY),
                       attestations=_current_attestations(records),
                       heartbeats=_heartbeats(records), last_statement_day=max((r.day for r in records), default=""),
                       manifest_conflict=manifest_conflict)


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


def _latest(records: Iterable[CuratorRecord]) -> Optional[CuratorRecord]:
    return max(records, key=lambda r: r.sequence, default=None)


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def counted_dispute_weight(disputes: Iterable[VerifiedDispute], view: CuratorView) -> Dict[str, int]:
    """Per threat, how many COUNTED authors dispute it. An unlisted author's
    dispute weighs 0 (plan §04): it is shown, never counted toward decay."""
    disputers: Dict[str, set] = {}
    for dispute in disputes:
        if view.is_counted(dispute.author):
            disputers.setdefault(dispute.identifier, set()).add(dispute.author)
    return {identifier: len(authors) for identifier, authors in disputers.items()}
