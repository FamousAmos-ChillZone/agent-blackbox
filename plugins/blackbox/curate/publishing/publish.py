"""Publishing an APPROVED curator proposal: quorum check, consent, the write.

Where a statement goes: promotions, revocations, pauses, the counted-author
list and key manifests -> the VERIFIED graph (publish to verifiable memory);
confirmations, rejections, deferrals and notices -> the COMMUNITY graph.
Every outward write sits behind content-bound consent and is ledgered.

Usage::

    proposal, outcome = publish(ctx, store, proposal_id, typed_code=code, yes=False)
"""

from __future__ import annotations

from typing import Optional, Tuple

from ... import audit, community, killlist
from ...kernel import node_routes, signing, threat_ids
from ...kernel.signing import key_manifest
from ...kernel.signing.statement_order import CuratorStatement
from .. import consent, promotion
from ..context import CurateContext
from ..proposal import Proposal, ProposalState, ProposalStore
from .errors import VerbError

MANIFEST_KIND = key_manifest.KEY_MANIFEST_STATEMENT


def publish(ctx: CurateContext, store: ProposalStore, proposal_id: str, *, typed_code: Optional[str], yes: bool) -> Tuple[Proposal, str]:
    """Write an APPROVED proposal to its graph, behind content-bound consent."""
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
    name, graph = _write(ctx, proposal, envelope)
    audit.record_share_outcome(identifier=proposal.identifier, category=f"curator:{proposal.kind.split('.', 1)[-1]}",
                               severity="info", subject=proposal.id, asset_name=name, ok=True, outcome="accepted")
    store.save(proposal.transition(ProposalState.PUBLISHED, note=f"published to {graph} as {name}"))
    return proposal, f"published to {graph} as {name}"


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


def _write(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> Tuple[str, str]:
    """Build the quads and write them where the statement lives; (asset name, graph)."""
    if proposal.kind == CuratorStatement.PROMOTION.value:
        _validated_promotion(envelope)
        quads = promotion.verified_rule_quads(dict(envelope.payload), envelope)
        name = promotion.asset_name(proposal.identifier)
        node_routes.publish_to_verified_memory(ctx.client, ctx.verified_graph, name, quads)
        return name, ctx.verified_graph
    if proposal.kind == killlist.KILL_LIST_STATEMENT:
        name = f"kill-list-{envelope.sequence}"
        node_routes.publish_to_verified_memory(ctx.client, ctx.verified_graph, name, killlist.kill_list_quads(envelope))
        return name, ctx.verified_graph
    if proposal.kind == MANIFEST_KIND:
        quads = community.key_manifest_quads(envelope)
        name = f"key-manifest-{envelope.root_epoch}-{envelope.sequence}"
        node_routes.publish_to_verified_memory(ctx.client, ctx.verified_graph, name, quads)
        return name, ctx.verified_graph
    kind = CuratorStatement(proposal.kind)
    quads = community.curator_statement_quads(envelope)
    name = f"curator-{kind.value.split('.', 1)[1]}-{threat_ids.stable_hash(proposal.identifier, 12)}-{envelope.sequence}"
    if kind in community.VERIFIED_GRAPH_KINDS:
        node_routes.publish_to_verified_memory(ctx.client, ctx.verified_graph, name, quads)
        return name, ctx.verified_graph
    ctx.client.share_knowledge_asset(ctx.community_graph, name, quads)
    return name, ctx.community_graph


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
