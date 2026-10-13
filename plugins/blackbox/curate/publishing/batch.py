"""The batch publisher — beat step 8 on the wallet node (trust-and-threat-lab §03.4, D27).

Quorum-signed promotions wait as APPROVED proposals; :class:`BatchPublisher`
turns them into ONE verified-graph knowledge asset per batch (≤ 50 entries,
one subject per threat at ``threat_uri(identifier)``, each row carrying its own
2-of-N envelope) and walks that batch through the :class:`PublishLedger`.
Pattern: Builder — the batch asset is assembled entry by entry from the
per-category row builders, then written in the ledger's steps.

When a batch goes (D15, F-017), whichever comes first:

* :data:`BATCH_ENTRIES` entries are waiting;
* the oldest waiting entry has waited :data:`BATCH_SECONDS` (6 h);
* a block-tier entry (package ``dep:``; skill ``skill:``, which also holds the
  artifact fingerprint ``skill:artifact:…``) with ≥ :data:`FAST_LANE_REPORTERS`
  reporters has waited :data:`FAST_LANE_HOLD_SECONDS` — held half an hour so
  others can join it, which leaves the beat interval and the publish inside
  the hour the proposal promises.

Revocations and corrections are never batched: only ``blackbox.promotion``
proposals are collected; every other kind goes at once through
:func:`.publish.publish` (asymmetric safety, F-032).

Fail-closed rules (F-035, LES-011):

* Before a new batch, every earlier unsettled batch is settled first. A SEALED
  batch (a definite refusal) is re-submitted — the same batch, never a new one.
  A SUBMITTED batch found after a crash moves on only from what the node says
  (its UAL). A MINTED batch (HTTP 207: paid, not readable) is NEVER submitted
  again: it is reconciled by reading it back, or written off by the operator.
  While any batch is unsettled no new batch is queued.
* The pre-check (:func:`.precheck.precheck`) runs immediately before the paid
  publish with :func:`strict_verified_subset`, which RAISES when the store
  cannot tell — ``Ruleset.verified_subset`` would answer "none listed".

Usage (the beat wiring is SVC4)::

    publisher = BatchPublisher()          # ProposalStore() + PublishLedger() in the curate home
    report = publisher.run(ctx)           # one step; report.action says what happened
    publisher.metrics(ctx)                # the F-035 record for the console and Slack
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from ...kernel import signing, threat_ids
from .. import promotion
from ..context import CurateContext
from ..proposal import Proposal, ProposalError, ProposalState, ProposalStore
from .ledger import BatchEntry, BatchRecord, PublishLedger, PublishState
from .precheck import VerifiedSubset, precheck
from .publish import NodeBatchWriter, SubmitReply, definite_refusal, has_quorum
from .row_builders import PROMOTION_STATEMENT, ROW_BUILDERS, ConfirmedEntry

logger = logging.getLogger(__name__)

BATCH_ENTRIES = 50
BATCH_SECONDS = 6 * 3600
FAST_LANE_REPORTERS = 3
FAST_LANE_HOLD_SECONDS = 30 * 60
#: Block-tier categories (package, skill; the fingerprint is a ``skill:artifact:`` identifier).
BLOCK_TIER_CATEGORIES = frozenset({"dep", "skill"})
#: A proposal waiting for its co-sign longer than this many beats is reported (F-035).
COSIGN_STALL_BEATS = 3
#: ``blackbox curate run``'s default beat interval (curate/parser.py).
DEFAULT_BEAT_SECONDS = 300.0
FAST_LANE = "fast"
BATCH_LANE = "batched"
_UNSETTLED = frozenset({PublishState.QUEUED, PublishState.SEALED, PublishState.SUBMITTED, PublishState.MINTED})


class PrecheckUnavailable(RuntimeError):
    """The verified store could not tell whether an entry is listed: nothing is published."""


@dataclass(frozen=True)
class Candidate:
    """One APPROVED promotion ready for a batch: its proposal, the entry its signed
    payload names, the envelope, the rows already built, when it was approved and
    how many reporters its provenance credits."""

    proposal_id: str
    entry: ConfirmedEntry
    envelope: signing.SignedEnvelope
    quads: Tuple[Dict[str, str], ...]
    approved_at: float
    reporters: int

    @property
    def fast(self) -> bool:
        return self.entry.category in BLOCK_TIER_CATEGORIES and self.reporters >= FAST_LANE_REPORTERS


@dataclass(frozen=True)
class BatchRunReport:
    """What one :meth:`BatchPublisher.run` did. ``action``: ``waiting`` (no trigger
    yet), ``published`` (a batch was bound and read back), ``minted`` (paid, not yet
    readable), ``held`` (an earlier batch is unsettled), ``failed`` (definite
    refusal; the batch stays SEALED and is retried), ``could-not-tell`` (nothing
    decided)."""

    action: str
    batch_id: Optional[str] = None
    entries: int = 0
    dropped: int = 0
    note: str = ""


@dataclass(frozen=True)
class BatchMetrics:
    """The publisher's F-035 record (console + Slack monitor). Optional fields are
    None when unknown — never a guessed 0."""

    waiting_per_lane: Mapping[str, int]
    oldest_waiting_seconds: Optional[float]
    proposals_awaiting_cosign: int          # PROPOSED for more than COSIGN_STALL_BEATS beats
    unsettled_batches: int
    held_back: int                          # APPROVED promotions no row builder can write
    failures: int
    minted_207s: int
    seconds_since_last_batch: Optional[float]
    wallet_trac: Optional[Decimal]
    wallet_floor_trac: Optional[Decimal]    # two batches at the dearest recorded cost
    below_wallet_floor: Optional[bool]


def strict_verified_subset(compiled: Any) -> VerifiedSubset:
    """``Ruleset.verified_subset`` that RAISES :class:`PrecheckUnavailable` instead of
    reading a store that could not tell as "none listed" (precheck's contract)."""

    def lookup(identifiers: Iterable[str]) -> Set[str]:
        wanted = {str(identifier) for identifier in identifiers}
        if compiled is None:
            raise PrecheckUnavailable("no compiled ruleset to check against")
        found = {str(rule.get("identifier") or "") for _category, rule in compiled.iter_rules()
                 if rule.get("source") == "public" and rule.get("identifier") in wanted}
        dependencies = [parsed for ident in wanted if (parsed := threat_ids.parse_dependency_identifier(ident))]
        iocs = [ident for ident in wanted if ident.startswith("ioc:")]
        if not dependencies and not iocs:
            return found
        live = compiled.live_lookup() if callable(getattr(compiled, "live_lookup", None)) else None
        if live is None:
            raise PrecheckUnavailable("the live verified lookup is not ready")
        for answer in ([live.dependencies(dependencies)] if dependencies else []) + ([live.iocs(iocs)] if iocs else []):
            if not answer.known:
                raise PrecheckUnavailable(f"the verified store could not tell ({answer.reason or 'no reason'})")
            found |= {rule["identifier"] for rule in answer.rules.values() if rule.get("identifier") in wanted}
        return found

    return lookup


class BatchPublisher:
    """Owns beat step 8. ``store`` / ``ledger`` default to the curate home's;
    ``writer`` — the node side (default :class:`.publish.NodeBatchWriter` on the
    context's client); ``verified_subset`` — the pre-check lookup (default
    :func:`strict_verified_subset` over ``ctx.compiled``); ``wallet_balance`` — the
    wallet's TRAC, None when unknown; ``beat_seconds`` — the beat interval."""

    def __init__(self, store: Optional[ProposalStore] = None, ledger: Optional[PublishLedger] = None, *,
                 writer: Optional[NodeBatchWriter] = None, verified_subset: Optional[VerifiedSubset] = None,
                 wallet_balance: Callable[[], Optional[Decimal]] = lambda: None,
                 beat_seconds: float = DEFAULT_BEAT_SECONDS, clock: Callable[[], float] = time.time) -> None:
        self._store = store or ProposalStore()
        self._ledger = ledger or PublishLedger(clock=clock)
        self._writer = writer
        self._verified_subset = verified_subset
        self._wallet_balance = wallet_balance
        self._beat_seconds = beat_seconds
        self._clock = clock

    # ------------------------------------------------------------ the step

    def run(self, ctx: CurateContext) -> BatchRunReport:
        """Settle earlier batches, then publish at most ONE new batch when a trigger fired."""
        writer = self._writer or NodeBatchWriter(ctx.client, ctx.verified_graph)
        candidates, _ = self._candidates(ctx)
        settled: Optional[BatchRunReport] = None
        for record in [record for record in self._ledger.batches() if record.state in _UNSETTLED]:
            settled = self._settle(record, candidates, writer)
            if settled.action != "published":
                return settled
        for record in self._ledger.batches():
            if record.state in (PublishState.BOUND, PublishState.SEEN):
                self._mark_published(record, candidates)
        waiting = self._waiting(candidates)
        if not self._due(waiting):
            return settled or BatchRunReport("waiting", entries=len(waiting))
        chosen = sorted(waiting, key=lambda c: (not c.fast, c.approved_at))[:BATCH_ENTRIES]
        try:
            checked = precheck([c.entry for c in chosen], self._verified_subset or strict_verified_subset(ctx.compiled))
        except Exception as exc:   # LES-011: no answer, no paid publish
            logger.warning("blackbox: batch pre-check could not tell (%s); nothing published", exc)
            return BatchRunReport("could-not-tell", entries=len(chosen), note=str(exc))
        self._close_dropped(checked.dropped, candidates)
        kept = [candidates[entry.identifier] for entry in checked.kept]
        if not kept:
            return BatchRunReport("waiting", dropped=len(checked.dropped), note="every chosen entry is already listed")
        batch_id = f"b-{int(self._clock())}-{secrets.token_hex(4)}"
        record = self._ledger.queue(batch_id, [BatchEntry(c.entry.identifier, c.entry.category) for c in kept])
        report = self._settle(record, candidates, writer)
        return BatchRunReport(report.action, batch_id, len(kept), len(checked.dropped), report.note)

    # ------------------------------------------------------------ collecting

    def _candidates(self, ctx: CurateContext) -> Tuple[Dict[str, Candidate], int]:
        """APPROVED, quorum-signed promotions for the verified graph, by identifier;
        plus how many of them no row builder can write (held back, logged)."""
        out: Dict[str, Candidate] = {}
        held_back = 0
        for proposal in self._store.all():
            if (proposal.state is not ProposalState.APPROVED or proposal.kind != PROMOTION_STATEMENT
                    or proposal.graph != ctx.verified_graph):
                continue
            envelope = proposal.parsed()
            if envelope is None or not has_quorum(ctx, proposal, envelope):
                continue
            try:
                candidate = _candidate(proposal, envelope)
            except ValueError as exc:   # RowBuildError, PromotionError, the store's literal cap
                held_back += 1
                logger.warning("blackbox: promotion %s cannot be batched: %s", proposal.id, exc)
                continue
            out.setdefault(candidate.entry.identifier, candidate)
        return out, held_back

    def _waiting(self, candidates: Mapping[str, Candidate]) -> List[Candidate]:
        """Candidates in no batch yet (a written-off batch's entries wait again)."""
        taken = {entry.identifier for record in self._ledger.batches()
                 if record.state is not PublishState.WRITTEN_OFF for entry in record.entries}
        return [candidate for identifier, candidate in candidates.items() if identifier not in taken]

    def _due(self, waiting: Sequence[Candidate]) -> bool:
        now = self._clock()
        return (len(waiting) >= BATCH_ENTRIES
                or any(now - c.approved_at >= BATCH_SECONDS for c in waiting)
                or any(c.fast and now - c.approved_at >= FAST_LANE_HOLD_SECONDS for c in waiting))

    def _close_dropped(self, dropped: Iterable[Any], candidates: Mapping[str, Candidate]) -> None:
        """A promotion the verified graph already covers is closed, so it is not re-checked every beat."""
        for drop in dropped:
            self._transition(candidates[drop.entry.identifier].proposal_id, ProposalState.REJECTED,
                             f"not published: {drop.reason} ({drop.covered_by})")

    # ------------------------------------------------------------ the ledger steps

    def _settle(self, record: BatchRecord, candidates: Mapping[str, Candidate],
                writer: NodeBatchWriter) -> BatchRunReport:
        """Move *record* as far as the node's answers allow (see the module doc)."""
        rows = [candidates.get(entry.identifier) for entry in record.entries]
        if any(row is None for row in rows):   # a promotion left APPROVED: the asset cannot be rebuilt
            return BatchRunReport("held", record.batch_id, note="a batch entry is no longer an approved promotion")
        batch = [row for row in rows if row is not None]
        name = asset_name(record.batch_id)
        if record.state is PublishState.QUEUED:
            try:
                writer.seal(name, [quad for c in batch for quad in c.quads])
            except Exception as exc:   # nothing was spent; the next run seals the same batch again
                return BatchRunReport("failed", record.batch_id, note=f"working-memory write failed: {exc}")
            record = self._ledger.advance(record.batch_id, PublishState.SEALED)
        if record.state is PublishState.SEALED:
            return self._submit(record, batch, name, writer)
        if record.state is PublishState.SUBMITTED:
            ual = writer.asset_ual(name)
            if ual is None:
                return BatchRunReport("held", record.batch_id, note="submitted; the node has not named a UAL yet")
            return self._minted(record, batch, SubmitReply(ual), writer, "found after a restart")
        return self._reconcile(record, batch, writer)

    def _submit(self, record: BatchRecord, batch: Sequence[Candidate], name: str,
                writer: NodeBatchWriter) -> BatchRunReport:
        # SUBMITTED is written BEFORE the call: a crash mid-call must read as "could not tell".
        self._ledger.advance(record.batch_id, PublishState.SUBMITTED)
        try:
            reply = writer.submit(name)
        except Exception as exc:
            if definite_refusal(exc):
                self._ledger.advance(record.batch_id, PublishState.SEALED, note=f"refused: {exc}"[:400])
                return BatchRunReport("failed", record.batch_id, note=str(exc))
            return BatchRunReport("could-not-tell", record.batch_id, note=str(exc))
        if reply.ual is None:
            return BatchRunReport("could-not-tell", record.batch_id, note="the node named no UAL")
        return self._minted(record, batch, reply, writer, f"tx {reply.tx_hash or 'not reported'}")

    def _minted(self, record: BatchRecord, batch: Sequence[Candidate], reply: SubmitReply,
                writer: NodeBatchWriter, how: str) -> BatchRunReport:
        """SUBMITTED → BOUND when the rows read back, else MINTED (a 207). The node's
        reply carries no TRAC figure, so the bytes are logged and the TRAC is 0 with
        the transaction named — the wallet watch compares it with the chain."""
        readable = writer.readable(_signed_rows(batch))
        state = PublishState.BOUND if readable else PublishState.MINTED
        record = self._ledger.advance(record.batch_id, state, ual=reply.ual, cost_trac="0",
                                      cost_bytes=_byte_size(batch), note=f"TRAC not in the reply; {how}")
        if state is PublishState.MINTED:
            logger.warning("blackbox: batch %s minted as %s but not readable (207); reconciled next beat",
                           record.batch_id, reply.ual)
            return BatchRunReport("minted", record.batch_id, len(batch))
        self._mark_published(record, {c.entry.identifier: c for c in batch})
        return BatchRunReport("published", record.batch_id, len(batch))

    def _reconcile(self, record: BatchRecord, batch: Sequence[Candidate], writer: NodeBatchWriter) -> BatchRunReport:
        """A MINTED batch is read back, never re-minted; written off only by the operator."""
        if writer.readable(_signed_rows(batch)) is not True:
            return BatchRunReport("held", record.batch_id, note="minted (207), not readable yet; not re-submitted")
        record = self._ledger.reconcile_minted(record.batch_id, readable_ual=record.ual, note="read back after a 207")
        self._mark_published(record, {c.entry.identifier: c for c in batch})
        return BatchRunReport("published", record.batch_id, len(batch))

    def _mark_published(self, record: BatchRecord, candidates: Mapping[str, Candidate]) -> None:
        for entry in record.entries:
            if entry.identifier in candidates:
                self._transition(candidates[entry.identifier].proposal_id, ProposalState.PUBLISHED,
                                 f"published in batch {record.batch_id} as {record.ual}")

    def _transition(self, proposal_id: str, state: ProposalState, note: str) -> None:
        proposal = self._store.get(proposal_id)
        if proposal is None or proposal.state is not ProposalState.APPROVED:
            return
        try:
            self._store.save(proposal.transition(state, now=self._clock(), note=note))
        except ProposalError as exc:   # pragma: no cover - APPROVED allows both moves
            logger.warning("blackbox: could not close proposal %s: %s", proposal_id, exc)

    # ------------------------------------------------------------ F-035

    def metrics(self, ctx: CurateContext) -> BatchMetrics:
        now = self._clock()
        candidates, held_back = self._candidates(ctx)
        waiting = self._waiting(candidates)
        lanes = {FAST_LANE: sum(c.fast for c in waiting), BATCH_LANE: sum(not c.fast for c in waiting)}
        stalled = sum(1 for p in self._store.all() if p.state is ProposalState.PROPOSED
                      and now - p.created > COSIGN_STALL_BEATS * self._beat_seconds)
        batches = self._ledger.batches()
        ledger = self._ledger.metrics(now)
        costs = [record.cost_trac for record in batches if record.cost_trac]
        floor = 2 * max(costs) if costs else None
        balance = self._wallet_balance()
        return BatchMetrics(
            waiting_per_lane=MappingProxyType(lanes),
            oldest_waiting_seconds=max((now - c.approved_at for c in waiting), default=None),
            proposals_awaiting_cosign=stalled,
            unsettled_batches=sum(record.state in _UNSETTLED for record in batches),
            held_back=held_back,
            failures=ledger.failures,
            minted_207s=ledger.minted_207s,
            seconds_since_last_batch=ledger.seconds_since_last_success,
            wallet_trac=balance,
            wallet_floor_trac=floor,
            below_wallet_floor=None if balance is None or floor is None else balance < floor,
        )


def asset_name(batch_id: str) -> str:
    """The knowledge-asset name of a batch (deterministic, so a retry writes the same asset)."""
    return f"verified-batch-{batch_id}"


def _candidate(proposal: Proposal, envelope: signing.SignedEnvelope) -> Candidate:
    """The entry the SIGNED payload names, built into its rows now so a
    promotion no builder can write never reaches a batch."""
    payload = envelope.payload
    provenance = tuple(ident for ident in str(payload.get("provenance", "")).split(",") if ident)
    entry = ConfirmedEntry(
        identifier=str(payload.get("identifier", "")), severity=str(payload.get("severity", "")),
        kind=str(payload.get("kind", "")), provenance=provenance,
        evidence="; ".join(proposal.checks[key] for key in sorted(proposal.checks)),
        name=str(payload.get("name", "")), advisory_id=str(payload.get("advisoryId", "")),
    )
    if entry.category == "dep":
        promotion.validate_payload(payload)   # the dependency rule the second signer checked (KI-195)
    quads = tuple(ROW_BUILDERS[entry.category].quads(entry, envelope))
    return Candidate(proposal.id, entry, envelope, quads, proposal.updated, len(provenance))


def _signed_rows(batch: Sequence[Candidate]) -> Dict[str, str]:
    return {threat_ids.threat_uri(c.entry.identifier): c.envelope.to_text() for c in batch}


def _byte_size(batch: Sequence[Candidate]) -> int:
    """The batch's quads as the node receives them (JSON), in bytes."""
    return len(json.dumps([quad for c in batch for quad in c.quads]).encode("utf-8"))
