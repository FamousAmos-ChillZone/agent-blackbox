"""Publishing an APPROVED curator proposal: quorum check, consent, the write, the read-back.

A proposal is written to the graph it was SIGNED for (``proposal.graph``): the
verified graph is published to verifiable memory, the community graph is
shared into shared memory. Which graph a statement belongs in was decided when
it was proposed, from the acting authority (``kernel.signing.authority``).

"Published" means the statement can be READ BACK from that graph (KI-246): a
node reply that only says "accepted", "already there" or "partly failed" is
not proof. A write that cannot be read back leaves the proposal APPROVED, is
reported as not published, and gives the consent back so the operator can run
`publish` again (KI-249).

Every outward write sits behind content-bound consent and is ledgered.

A revocation or a correction (P5) is published at once, never batched, and
once it reads back the verified authority also posts its ADVISORY TWIN in the
community graph (:func:`advisory_twin`, D26) so readers' 20 s pulse withdraws
the rule instead of waiting for a full refresh. A correction publishes only
under an EFFECTIVE manifest (:func:`require_effective_manifest`).

Usage::

    proposal, outcome = publish(ctx, store, proposal_id, typed_code=code, yes=False)
    outcome.startswith("published")      # True only after the read-back

The batch publisher (``batch.py``) writes promotions in batches through the
same node, split into its ledger's steps: :class:`NodeBatchWriter` seals a
batch asset in working memory, submits it to ``/vm/publish``, asks the node
for an asset's UAL and reads every signed row back; :func:`has_quorum` is the
quorum check both paths share.
"""

from __future__ import annotations

import logging
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Tuple
from urllib.parse import quote, urlencode

from ... import audit, community, killlist
from ...kernel import constants, node_routes, rdf_terms, signing, sparql_text, threat_ids
from ...kernel.dkg_client import DkgClient, DkgError
from ...kernel.signing import key_manifest
from ...kernel.signing.statement_order import CuratorStatement
from .. import consent, promotion
from ..ladder import outcomes
from ..upkeep import published
from ..context import CORRECTION_STATEMENT, CurateContext
from ..proposal import Proposal, ProposalState, ProposalStore
from . import row_builders
from .errors import VerbError

logger = logging.getLogger(__name__)

MANIFEST_KIND = key_manifest.KEY_MANIFEST_STATEMENT


class PublishOutcome(Enum):
    """What a write achieved, observed by reading it back."""

    PUBLISHED = "published"          # written now, and readable
    ALREADY_THERE = "already-there"  # the node already held it, and it is readable
    UNCONFIRMED = "unconfirmed"      # the node accepted the write but it cannot be read back


def publish(ctx: CurateContext, store: ProposalStore, proposal_id: str, *, typed_code: Optional[str], yes: bool,
            standing: str = "") -> Tuple[Proposal, str]:
    """Write an APPROVED proposal to its graph, behind content-bound consent.
    Returns (proposal, what happened); the text starts with "published" only
    when the statement was read back from the graph. *standing* — set ONLY by
    the curator service, after its policy allowed this statement and the
    operator's standing consent was checked (``curate.service``): the policy's
    reason, recorded in the consent ledger in place of a typed code."""
    proposal = store.get(proposal_id)
    if proposal is None or proposal.state is not ProposalState.APPROVED:
        raise VerbError("no APPROVED proposal with that id")
    envelope = proposal.parsed()
    if proposal.kind == CORRECTION_STATEMENT:
        require_effective_manifest(ctx)
    if envelope is None or not has_quorum(ctx, proposal, envelope):
        raise VerbError("the proposal does not carry enough curator signatures to publish")
    ledger = consent.ConsentLedger()
    code = ledger.show(proposal.envelope, summary(proposal))
    ok, why = (ledger.standing(proposal.envelope, standing) if standing
               else ledger.consent(proposal.envelope, typed=typed_code, sandbox=ctx.sandbox, yes=yes))
    if not ok:
        return proposal, f"not published — {why}. Confirmation code: {code}"
    try:
        name, graph, outcome = _write(ctx, proposal, envelope)
    except VerbError:
        ledger.release(proposal.envelope, "the write was refused")
        raise
    except Exception as exc:   # the node refused or failed: nothing was published, the operator may retry
        ledger.release(proposal.envelope, str(exc))
        raise VerbError(f"the write failed, nothing was published: {exc}") from exc
    if outcome is PublishOutcome.UNCONFIRMED:
        ledger.release(proposal.envelope, "written but not readable")
        return proposal, (f"not published — written to {graph} as {name}, but it cannot be read back yet. "
                          f"Run `blackbox curate publish {proposal.id}` again to re-check.")
    audit.record_share_outcome(identifier=proposal.identifier, category=f"curator:{proposal.kind.split('.', 1)[-1]}",
                               severity="info", subject=proposal.id, asset_name=name, ok=True, outcome="accepted")
    store.save(proposal.transition(ProposalState.PUBLISHED, note=f"published to {graph} as {name}"))
    if graph == ctx.community_graph:   # shared memory forgets: this node keeps its statement alive
        published.remember(ctx.cfg, graph=graph, name=name, quads=_asset(proposal, envelope)[1])
    _credit_reporters(ctx, proposal)
    already = " (the node already held it)" if outcome is PublishOutcome.ALREADY_THERE else ""
    twin = f" · {post_advisory_twin(ctx, envelope)}" if proposal.kind in TWINNED_STATEMENTS else ""
    return proposal, f"published to {graph} as {name}{already}{twin}"


def require_effective_manifest(ctx: CurateContext) -> None:
    """Refuse unless the acting authority's trusted manifest is in force: a
    correction signed under none, or under one still inside its
    time-lock, is envelope-less to every reader and ignored."""
    if ctx.manifest is None:
        raise VerbError("no trusted key manifest is in force yet; a correction would be ignored by every reader")
    if ctx.view.manifest_state == "pending":
        raise VerbError(f"the trusted key manifest takes effect on {ctx.view.manifest_state_day}; "
                        "a correction signed before then would be ignored by every reader")


# ---------------------------------------------------------------- the advisory twin (D26)

#: The statements whose advisory twin the verified authority posts in the community graph.
TWINNED_STATEMENTS = frozenset({CuratorStatement.REVOCATION.value, CORRECTION_STATEMENT})


def advisory_twin(envelope: signing.SignedEnvelope) -> Tuple[str, List[Dict[str, str]]]:
    """``(asset name, quads)`` of a revocation's or correction's advisory twin:
    the same signed text under a ``g:CuratorStatement`` subject, which changes
    the community graph's pulse fingerprint (``community.pulse``), so the pulse
    re-applies the curator tier within ~20 s (R4).

    It says nothing by itself: the envelope is bound to the verified graph and
    the subject carries no ``g:identifier``, so every community statement read
    skips it — and, unlike a new verdict, it can never outrank the revocation."""
    if envelope.statement_type not in TWINNED_STATEMENTS:
        raise VerbError(f"only {sorted(TWINNED_STATEMENTS)} have an advisory twin")
    kind, digest = envelope.statement_type.split(".", 1)[1], threat_ids.stable_hash(envelope.to_text(), 24)
    subject = f"urn:guardian:curator:twin:{kind}:{digest}"
    return f"curator-twin-{kind}-{digest[:16]}", [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.CURATOR_STATEMENT_TYPE_IRI)),
        rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(envelope.to_text())),
    ]


def post_advisory_twin(ctx: CurateContext, envelope: signing.SignedEnvelope) -> str:
    """Share *envelope*'s advisory twin into the community graph, AFTER the
    verified-graph asset reads back (the pulse reads the verified graph: a twin
    that synced first would find nothing). Best effort — readers still withdraw
    the rule on their next full refresh — so it reports, never raises."""
    graph = ctx.community_graph
    if not graph or graph == ctx.verified_graph:
        return "no community graph: no advisory twin (readers act on their next full refresh)"
    name, quads = advisory_twin(envelope)
    try:
        _share(ctx, graph, name, quads)
    except Exception as exc:
        logger.warning("blackbox: advisory twin %s not posted (%s); readers act on their next full refresh", name, exc)
        return f"advisory twin NOT posted ({exc}); readers act on their next full refresh"
    return f"advisory twin posted to {graph} as {name}"


#: Statements whose publication changes what reporters are credited with, or their band.
_LADDER_KINDS = frozenset({CuratorStatement.CONFIRMATION.value, CuratorStatement.REJECTION.value,
                           CuratorStatement.COUNTED_AUTHORS.value})


def _credit_reporters(ctx: CurateContext, proposal: Proposal) -> None:
    """A published verdict credits the threat's reporters, and a published
    listing moves its reporter's band, in this node's private ledger — at
    once, without anyone typing it (KI-252). Best effort: the ledger can
    always be rebuilt from the public record, so a failure here never undoes
    a publish."""
    if proposal.kind not in _LADDER_KINDS:
        return
    try:
        outcomes.credit_verdicts(ctx, also=[proposal.identifier])
    except Exception as exc:
        logger.warning("blackbox: could not credit reporters after publishing (%s); `curate graduate` re-syncs", exc)


def has_quorum(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> bool:
    """True when *envelope* carries the signatures its kind needs under ``ctx.manifest``."""
    if proposal.kind == MANIFEST_KIND:
        return True   # root-signed; verified by readers against the pinned roots
    if ctx.manifest is None:
        return False
    if proposal.kind == killlist.KILL_LIST_STATEMENT:
        return ctx.manifest.has_quorum(envelope, statement_type=killlist.KILL_LIST_STATEMENT, graph=proposal.graph)
    if proposal.kind in (CuratorStatement.PROMOTION.value, CORRECTION_STATEMENT):   # one key per operator, like every reader
        return ctx.manifest.has_quorum(envelope, statement_type=proposal.kind, graph=proposal.graph)
    kind = CuratorStatement(proposal.kind)
    needed = ctx.manifest.threshold if kind.needs_quorum else 1
    return len(ctx.manifest.curator_signers(envelope, statement_type=kind.value, graph=proposal.graph)) >= needed


def _write(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> Tuple[str, str, PublishOutcome]:
    """Build the quads, write them to the graph the proposal was signed for and
    read them back; (asset name, graph, outcome)."""
    name, quads = _asset(proposal, envelope)
    graph = proposal.graph
    if graph == ctx.verified_graph:
        node_routes.publish_to_verified_memory(ctx.client, graph, name, quads)
        already, view = False, constants.VIEW_VERIFIABLE_MEMORY
    elif graph and graph == ctx.community_graph:
        already, view = _share(ctx, graph, name, quads), constants.VIEW_SHARED_WORKING_MEMORY
    else:
        raise VerbError(f"the proposal was signed for {graph or 'no graph'}, which is neither of this node's graphs")
    if not _readable(ctx, graph, view, quads):
        return name, graph, PublishOutcome.UNCONFIRMED
    return name, graph, PublishOutcome.ALREADY_THERE if already else PublishOutcome.PUBLISHED


def _asset(proposal: Proposal, envelope: signing.SignedEnvelope) -> Tuple[str, List[Dict[str, str]]]:
    """(asset name, quads) for a proposal, by its kind."""
    if proposal.kind == CuratorStatement.PROMOTION.value:
        _validated_promotion(envelope)
        return promotion.asset_name(proposal.identifier), row_builders.verified_rule_quads(dict(envelope.payload), envelope)
    if proposal.kind == killlist.KILL_LIST_STATEMENT:
        return f"kill-list-{envelope.sequence}", killlist.kill_list_quads(envelope)
    if proposal.kind == CORRECTION_STATEMENT:
        try:
            quads = row_builders.correction_quads(envelope)
        except row_builders.RowBuildError as exc:
            raise VerbError(f"the correction is not acceptable: {exc}") from exc
        return f"correction-{threat_ids.stable_hash(proposal.identifier, 12)}-{envelope.sequence}", quads
    if proposal.kind == MANIFEST_KIND:
        return f"key-manifest-{envelope.root_epoch}-{envelope.sequence}", community.key_manifest_quads(envelope)
    kind = CuratorStatement(proposal.kind)
    name = f"curator-{kind.value.split('.', 1)[1]}-{threat_ids.stable_hash(proposal.identifier, 12)}-{envelope.sequence}"
    return name, community.curator_statement_quads(envelope)


def _share(ctx: CurateContext, graph: str, name: str, quads: List[Dict[str, str]]) -> bool:
    """Share into the community graph; True when the node already held this
    asset (an earlier attempt got it there). Any other failure is raised."""
    try:
        result = ctx.client.share_knowledge_asset(graph, name, quads)
    except Exception as exc:
        if community.ALREADY_SEALED_REPLY in str(exc).lower():
            return True
        raise
    return bool(isinstance(result, dict) and result.get("idempotent"))


def _readable(ctx: CurateContext, graph: str, view: str, quads: List[Dict[str, str]]) -> bool:
    """True when the signed statement just written can be read from *graph*:
    an exact lookup of its subject AND its signed text (so another node's
    statement under the same subject does not count). Quads that carry no
    signed statement have nothing to read back and count as readable."""
    signed = next((q for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED), None)
    if signed is None:
        return True
    sparql = (f"SELECT ?r WHERE {{ VALUES ?r {{ <{signed['subject']}> }} "
              f"?r <{constants.SIGNED_STATEMENT_PRED}> {signed['object']} }} LIMIT 1")
    return bool(sparql_text.query_rows(ctx.client, sparql, graph, view))


def _validated_promotion(envelope: signing.SignedEnvelope) -> None:
    try:
        promotion.validate_payload(envelope.payload)
    except promotion.PromotionError as exc:
        raise VerbError(f"the promotion payload is not acceptable: {exc}") from exc


def summary(proposal: Proposal) -> str:
    """What the operator is asked to consent to (graph, kind, subject, signers);
    a whole-package promotion says so in words, so the second signer cannot
    miss the scope."""
    envelope = proposal.parsed()
    signers = ", ".join(s[:12] + "…" for s in envelope.signers) if envelope else "?"
    scope = " · WHOLE PACKAGE (every version)" if envelope and promotion.whole_package(envelope.payload) else ""
    if envelope and proposal.kind == CORRECTION_STATEMENT:
        scope = f" · SUPPRESSES {len(str(envelope.payload.get('targetSubjects', '')).split())} subject(s)"
    return f"{proposal.kind} · {proposal.identifier}{scope} · graph {proposal.graph} · seq {envelope.sequence if envelope else '?'} · keys {signers}"


# ---------------------------------------------------------------- the batch path (BatchPublisher's node side)


@dataclass(frozen=True)
class SubmitReply:
    """What ``/vm/publish`` answered: ``ual`` — set when the asset was minted on
    chain (the node names it whether or not the graph binding then succeeded:
    a 207 carries it too); ``tx_hash`` — the publish transaction, kept on the
    ledger so the spend can be looked up on chain."""

    ual: Optional[str]
    tx_hash: str = ""


def definite_refusal(exc: BaseException) -> bool:
    """True only when the node DEFINITELY refused (a 4xx): nothing was minted
    and a retry is safe. A 5xx, a timeout or a dropped connection is "could
    not tell" (LES-011) — the asset may be on chain already."""
    status = getattr(exc, "status_code", None)
    return isinstance(exc, DkgError) and isinstance(status, int) and 400 <= status < 500


class NodeBatchWriter:
    """The node side of a batch, one call per publish-ledger step (pattern:
    Adapter over the DKG routes ``node_routes.publish_to_verified_memory``
    uses). The write and the publish are separate calls here, unlike the
    one-shot path: a failed working-memory write spent nothing and is retried
    as such, while a failed publish may have been paid for.

    Usage::

        writer = NodeBatchWriter(ctx.client, ctx.verified_graph)
        writer.seal(name, quads)                   # QUEUED → SEALED
        reply = writer.submit(name)                # SUBMITTED → MINTED / BOUND
        writer.readable({subject: envelope_text})  # True / False / None (could not tell)
    """

    def __init__(self, client: DkgClient, graph: str) -> None:
        self._client = client
        self._graph = graph

    def seal(self, name: str, quads: List[Dict[str, str]]) -> None:
        """Write and seal the batch, then share it in full to shared memory — the
        node publishes only a complete share (KI-351). Both are free, so a
        failure here is a safe retry: nothing has been paid yet."""
        try:
            self._client.write_private_knowledge_asset(self._graph, name, quads)
        except DkgError as exc:
            # The node finished an earlier seal whose reply was lost (timeout, crash before the
            # ledger moved): the name is this batch's own, so the sealed asset IS this batch.
            # Without this the batch fails every beat and holds every later batch (P4 review).
            if not _already_sealed(exc):
                raise
        self._client.share_finalized_knowledge_asset(self._graph, name)

    def submit(self, name: str) -> SubmitReply:
        reply = self._client.request("POST", f"/api/knowledge-assets/{quote(name, safe='')}/vm/publish",
                                     {"contextGraphId": self._graph})
        return SubmitReply(ual=_text(reply, "ual") or None, tx_hash=_text(reply, "txHash"))

    def asset_ual(self, name: str) -> Optional[str]:
        """The UAL the node's lifecycle descriptor names for *name*; None when it
        names none or cannot be asked (could not tell — never "not minted")."""
        path = f"/api/knowledge-assets/{quote(name, safe='')}?{urlencode({'contextGraphId': self._graph})}"
        try:
            return _text(self._client.request("GET", path), "ual") or None
        except DkgError:
            return None

    def readable(self, signed: Mapping[str, str]) -> Optional[bool]:
        """True when every subject in *signed* (subject → envelope text) reads back
        from verifiable memory carrying exactly that envelope; None when the read
        cannot be believed."""
        if not signed:
            return True
        values = " ".join(f"<{subject}>" for subject in sorted(signed))
        sparql = (f"SELECT ?r ?o WHERE {{ VALUES ?r {{ {values} }} ?r <{constants.SIGNED_STATEMENT_PRED}> ?o }} "
                  f"LIMIT {len(signed) * 4}")
        rows = sparql_text.query_rows(self._client, sparql, self._graph, constants.VIEW_VERIFIABLE_MEMORY)
        if rows is None:
            return None
        seen = set()
        for row in rows:
            envelope = signing.from_text(sparql_text.extract_binding(row.get("o")))
            if envelope is not None:
                seen.add((sparql_text.extract_binding(row.get("r")), envelope.to_text()))
        return all((subject, text) in seen for subject, text in signed.items())


def _already_sealed(exc: DkgError) -> bool:
    """The node's answer to a create for a name it already sealed: DKG 10.0.20+
    (``community.ALREADY_SEALED_REPLY``) and the older "already finalized" text."""
    message = str(exc).lower()
    return community.ALREADY_SEALED_REPLY in message or "already finalized" in message


def _text(reply: object, key: str) -> str:
    value = reply.get(key) if isinstance(reply, dict) else None
    return value.strip() if isinstance(value, str) else ""
