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

Usage::

    proposal, outcome = publish(ctx, store, proposal_id, typed_code=code, yes=False)
    outcome.startswith("published")      # True only after the read-back
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Dict, List, Optional, Tuple

from ... import audit, community, killlist
from ...kernel import constants, node_routes, signing, sparql_text, threat_ids
from ...kernel.signing import key_manifest
from ...kernel.signing.statement_order import CuratorStatement
from .. import consent, promotion
from ..context import CurateContext
from ..proposal import Proposal, ProposalState, ProposalStore
from .errors import VerbError

logger = logging.getLogger(__name__)

MANIFEST_KIND = key_manifest.KEY_MANIFEST_STATEMENT


class PublishOutcome(Enum):
    """What a write achieved, observed by reading it back."""

    PUBLISHED = "published"          # written now, and readable
    ALREADY_THERE = "already-there"  # the node already held it, and it is readable
    UNCONFIRMED = "unconfirmed"      # the node accepted the write but it cannot be read back


def publish(ctx: CurateContext, store: ProposalStore, proposal_id: str, *, typed_code: Optional[str], yes: bool) -> Tuple[Proposal, str]:
    """Write an APPROVED proposal to its graph, behind content-bound consent.
    Returns (proposal, what happened); the text starts with "published" only
    when the statement was read back from the graph."""
    proposal = store.get(proposal_id)
    if proposal is None or proposal.state is not ProposalState.APPROVED:
        raise VerbError("no APPROVED proposal with that id")
    envelope = proposal.parsed()
    if envelope is None or not _has_quorum(ctx, proposal, envelope):
        raise VerbError("the proposal does not carry enough curator signatures to publish")
    ledger = consent.ConsentLedger()
    code = ledger.show(proposal.envelope, summary(proposal))
    ok, why = ledger.consent(proposal.envelope, typed=typed_code, sandbox=ctx.sandbox, yes=yes)
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
    already = " (the node already held it)" if outcome is PublishOutcome.ALREADY_THERE else ""
    return proposal, f"published to {graph} as {name}{already}"


def _has_quorum(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> bool:
    if proposal.kind == MANIFEST_KIND:
        return True   # root-signed; verified by readers against the pinned roots
    if ctx.manifest is None:
        return False
    if proposal.kind == killlist.KILL_LIST_STATEMENT:
        return ctx.manifest.has_quorum(envelope, statement_type=killlist.KILL_LIST_STATEMENT, graph=proposal.graph)
    if proposal.kind == CuratorStatement.PROMOTION.value:
        signers = signing.verified_signers(envelope, statement_type=envelope.statement_type,
                                           environment=ctx.manifest.environment, graph=proposal.graph,
                                           chain=ctx.manifest.chain, root_epoch=ctx.manifest.root_epoch)
        return len(signers & frozenset(ctx.manifest.curator_keys)) >= ctx.manifest.threshold
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
        return promotion.asset_name(proposal.identifier), promotion.verified_rule_quads(dict(envelope.payload), envelope)
    if proposal.kind == killlist.KILL_LIST_STATEMENT:
        return f"kill-list-{envelope.sequence}", killlist.kill_list_quads(envelope)
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
    return f"{proposal.kind} · {proposal.identifier}{scope} · graph {proposal.graph} · seq {envelope.sequence if envelope else '?'} · keys {signers}"
