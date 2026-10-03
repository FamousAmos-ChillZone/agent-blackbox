"""The curator's write verbs: propose, approve, publish, nominate, manifest (Refine R6).

Each verb is one Command over a :class:`.context.CurateContext`. The two-key
flow (plan §09 TRANSPORT): machine A ``propose`` — the checklist must pass,
the first curator key signs, the proposal is stored and sent by private
message; machine B ``inbox`` then ``approve`` — the envelope's first signer
must be one of the manifest's curator keys and not B's own, B records its own
item-1 check, co-signs, gives consent bound to the content, and PUBLISHES
("whoever signs second publishes"). Nothing reaches a shared graph before
approval. Every outward write is ledgered.

Where a statement goes: promotions, revocations, pauses, the counted-author
list and key manifests -> the VERIFIED graph (publish to verifiable memory);
confirmations, rejections, deferrals and notices -> the COMMUNITY graph.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import audit, community, killlist
from ..kernel import health, node_routes, signing, threat_ids
from ..kernel.signing import key_manifest
from ..kernel.signing.statement_order import CuratorStatement
from . import consent, dossier, keys, promotion, transport
from .context import CurateContext
from .proposal import Proposal, ProposalState, ProposalStore
from ..community import reputation

logger = logging.getLogger(__name__)

MANIFEST_KIND = key_manifest.KEY_MANIFEST_STATEMENT


class VerbError(ValueError):
    """A verb refused; the message says why (printed, never a traceback)."""


# -- sequence numbers -----------------------------------------------------------


def next_sequence(ctx: CurateContext, store: ProposalStore, identifier: str) -> int:
    """One past the highest per-identifier sequence this node knows (verified
    statements, counted-author entries, its own proposals)."""
    seen = [0]
    record = ctx.view.verdicts.get(identifier)
    if record is not None:
        seen.append(record.sequence)
    for proposal in store.for_identifier(identifier):
        envelope = proposal.parsed()
        if envelope is not None:
            seen.append(envelope.sequence)
    return max(seen) + 1


# -- propose -----------------------------------------------------------------


def propose_promotion(ctx: CurateContext, store: ProposalStore, *, identifier: str, severity: str, evidence: str,
                      reason: str, report_subjects: Iterable[str], name: str = "") -> Proposal:
    """A promotion proposal (dependency, kind=malware): checklist, first signature, stored."""
    _require_manifest(ctx)
    items = dossier.checklist(identifier, kind="malware", evidence=evidence, reason=reason)
    if not dossier.passes(items):
        raise VerbError("checklist failed: " + "; ".join(f"{i.item}. {i.note}" for i in items if not i.ok))
    advisory = evidence[len("advisory:"):] if evidence.startswith("advisory:") else ""
    payload = promotion.payload_for(identifier, severity=severity, advisory=advisory, report_subjects=report_subjects,
                                    provenance=promotion.ProvenanceMap(), name=name)
    key = keys.curator_key_store().load_or_create()
    envelope = promotion.sign(payload, key, ctx.manifest, sequence=next_sequence(ctx, store, identifier))
    return _stored(store, CuratorStatement.PROMOTION.value, identifier, envelope, ctx.verified_graph,
                   {signing.public_key_hex(key): evidence})


def propose_statement(ctx: CurateContext, store: ProposalStore, *, kind: CuratorStatement, identifier: str,
                      fields: Mapping[str, str], evidence: str = "") -> Proposal:
    """A verdict / notice / counted-author / pause proposal, first signature on it."""
    _require_manifest(ctx)
    graph = ctx.verified_graph if kind in community.VERIFIED_GRAPH_KINDS else ctx.community_graph
    key = keys.curator_key_store().load_or_create()
    try:
        envelope = community.sign_curator_statement(kind, identifier, sequence=next_sequence(ctx, store, identifier),
                                                     fields=fields, key=key, manifest=ctx.manifest, graph=graph)
    except ValueError as exc:
        raise VerbError(str(exc)) from exc
    return _stored(store, kind.value, identifier, envelope, graph, {signing.public_key_hex(key): evidence or "n/a"})


def record_outcome(key: str, *, confirmed: bool, day: str, novel: bool = False, strike: bool = False,
                   first_seen_day: str = "", ledger: Optional[reputation.ReputationLedger] = None) -> reputation.ReporterStanding:
    """R4: one curator decision about one of *key*'s reports goes into the
    curator-PRIVATE ledger (never published). A strike is confirmed bad faith;
    novelty is judged by :func:`community.reputation.novelty_credit` first."""
    if len(key) != 64:
        raise VerbError("a reporter KEY (64 hex) is the identity, never an address")
    return (ledger or reputation.ReputationLedger()).record(key.lower(), reputation.Outcome(day, confirmed), novel=novel,
                                                              strike=strike, first_seen_day=first_seen_day)


def graduation_candidates(today: str, ledger: Optional[reputation.ReputationLedger] = None
                          ) -> List[Tuple[reputation.ReporterStanding, float, str]]:
    """R4: every ledgered reporter with its reputation and what today calls for:
    'graduate', 'demote', or '' (nothing). Read-only."""
    book = ledger or reputation.ReputationLedger()
    rows = []
    for key in book.keys():
        standing, score = book.standing(key), book.reputation(key, today)
        action = ("graduate" if reputation.graduates(standing, today)
                  else "demote" if reputation.demotion(standing, score, today) is not None else "")
        rows.append((standing, score, action))
    return rows


def propose_graduation(ctx: CurateContext, store: ProposalStore, *, key: str, address: str, today: str,
                       cluster: str = "", ledger: Optional[reputation.ReputationLedger] = None) -> Proposal:
    """R4: turn a standing into the counted-author proposal it calls for
    (graduation lists, demotion delists, a collapse shares an org) — the same
    2-of-3 flow as every nomination; readers never see the ledger."""
    book = ledger or reputation.ReputationLedger()
    standing = book.standing(key.lower())
    fields = reputation.nomination_fields(standing, address=address, today=today,
                                          reputation=book.reputation(key.lower(), today), cluster=cluster)
    if fields is None:
        raise VerbError(f"nothing to propose for this reporter today (band {standing.band.value}, "
                        f"{standing.novel_credits} novel credit(s), {standing.strikes} strike(s))")
    proposal = propose_statement(ctx, store, kind=CuratorStatement.COUNTED_AUTHORS, identifier=f"author:{key.lower()}",
                                 fields=fields, evidence=f"reputation ledger {today}")
    if fields["listed"] == "yes" and standing.band is reputation.ReputationBand.PROBATION:
        book.set_standing(replace(standing, band=reputation.ReputationBand.ESTABLISHED, org=cluster))
    elif fields["listed"] == "no":
        demoted = reputation.demotion(standing, book.reputation(key.lower(), today), today)
        if demoted is not None:
            book.set_standing(demoted)
    return proposal


def curator_alarms(ctx: CurateContext, compiled: Optional[Any], *, today: str, now: float,
                   ledger: Optional[reputation.ReputationLedger] = None) -> List[health.HealthItem]:
    """R10b: the curator-audience alarms from this node's own facts — the queue
    (depth and lane ages against the SLA), the private ledger (drift), the
    reader's first-seen trail (report velocity), the share retries and the
    counted list's expiries. Never shown to operators."""
    from . import queue as queue_mod
    from .context import verified_identifiers
    lane_depth: Dict[int, int] = {}
    lane_over: Dict[int, int] = {}
    if compiled is not None:
        view = queue_mod.delta_view(compiled.community, verified_identifiers(compiled))
        for item in view.new:
            lane_depth[item.lane.value] = lane_depth.get(item.lane.value, 0) + 1
            first_seen = float((compiled.community.get(item.identifier) or {}).get("firstSeen") or now)
            if now - first_seen > health.LANE_SLA_DAYS.get(item.lane.value, 14) * 86_400:
                lane_over[item.lane.value] = lane_over.get(item.lane.value, 0) + 1
    book = ledger or reputation.ReputationLedger()
    established = [k for k in book.keys() if book.standing(k).band is reputation.ReputationBand.ESTABLISHED]
    below = sum(1 for k in established if book.reputation(k, today) < reputation.REPUTATION_FLOOR)
    today_count, mean, sigma = _report_velocity(now)
    expiring = sum(1 for entry in ctx.view.counted.values()
                   if 0 <= _days_until(entry.expires, today) <= 30)
    inputs = health.CuratorInputs(lane_depth=lane_depth, lane_over_sla=lane_over, established_below_floor=below,
                                  established_total=len(established), reports_today=today_count, velocity_mean=mean,
                                  velocity_sigma=sigma, shares_given_up=community.share_retry_stats().given_up,
                                  expiring_keys=expiring)
    return health.curator_health(inputs)


def _days_until(day: str, today: str) -> int:
    try:
        return (date.fromisoformat(day) - date.fromisoformat(today)).days
    except ValueError:
        return 10**6


def _report_velocity(now: float, days: int = 14) -> Tuple[int, float, float]:
    """(statements first seen today, mean per day, σ) over the last *days* days,
    from the reader's first-seen trail (``community_first_seen.json``)."""
    first_seen, _ = community.first_seen_trail()
    buckets = [0] * days
    for seen_at in first_seen.values():
        age = int((now - float(seen_at)) // 86_400)
        if 0 <= age < days:
            buckets[age] += 1
    history = buckets[1:]
    mean = sum(history) / len(history) if history else 0.0
    sigma = (sum((x - mean) ** 2 for x in history) / len(history)) ** 0.5 if history else 0.0
    return buckets[0], mean, sigma


def _stored(store: ProposalStore, kind: str, identifier: str, envelope: signing.SignedEnvelope, graph: str,
            checks: Mapping[str, str]) -> Proposal:
    proposal = Proposal.new(kind, identifier, envelope, graph, checks=checks).transition(ProposalState.PROPOSED)
    store.save(proposal)
    return proposal


def send(ctx: CurateContext, proposal: Proposal, peer: str) -> Dict[str, object]:
    return transport.send_proposal(ctx.client, peer, proposal)


# -- approve (second key) ----------------------------------------------------------


def propose_kill_list(ctx: CurateContext, store: ProposalStore, *, entries: List[Dict[str, str]]) -> Proposal:
    """R14: first signature on a kill list (the next version); wide or popular
    kills still need the root to co-sign at approval (`approve --root`)."""
    _require_manifest(ctx)
    parsed = [killlist.KillEntry.from_json(item) for item in entries]
    if not parsed or any(e is None for e in parsed):
        raise VerbError("every kill-list entry needs registry (skill|mcp), identifier, action (disable|warn) and a closed reason")
    version = next_sequence(ctx, store, "kill-list")
    kill_list = killlist.KillList(version=version, day=datetime.now(timezone.utc).date().isoformat(),
                                  entries=tuple(e for e in parsed if e is not None))
    key = keys.curator_key_store().load_or_create()
    try:
        envelope = killlist.sign_kill_list(kill_list, key, ctx.manifest, ctx.verified_graph)
    except ValueError as exc:
        raise VerbError(str(exc)) from exc
    return _stored(store, killlist.KILL_LIST_STATEMENT, "kill-list", envelope, ctx.verified_graph,
                   {signing.public_key_hex(key): f"{len(kill_list.entries)} entries, {len(kill_list.disables)} disables"})


def approve(ctx: CurateContext, store: ProposalStore, proposal_id: str, *, evidence: str,
            typed_code: Optional[str], yes: bool, root: bool = False) -> Tuple[Proposal, str]:
    """Second signature + consent + publish. Returns (proposal, what happened).
    *root* (SANDBOX, kill lists): also add the root key's signature — the third
    signature a wide or popular kill needs (R14)."""
    _require_manifest(ctx)
    proposal = store.get(proposal_id)
    if proposal is None or proposal.state is not ProposalState.PROPOSED:
        raise VerbError("no PROPOSED proposal with that id")
    envelope = proposal.parsed()
    if envelope is None:
        raise VerbError("the proposal's envelope is malformed")
    my_key = keys.curator_key_store().load_or_create()
    _check_first_signer(ctx, envelope, proposal, signing.public_key_hex(my_key))
    if proposal.kind == CuratorStatement.PROMOTION.value:
        if not evidence:
            raise VerbError("a promotion needs your own item-1 evidence (--evidence advisory:<id> …); each key checks the truth itself")
        _validated_promotion(envelope)   # KI-195: never cosign a payload you did not check yourself
    try:
        cosigned = signing.cosign(envelope, my_key)
        if root and proposal.kind == killlist.KILL_LIST_STATEMENT:
            cosigned = signing.cosign(cosigned, keys.root_key_store().load_or_create())
    except ValueError as exc:   # round 4: a third signature can outgrow the 4 KB envelope
        raise VerbError(f"cannot add this signature: {exc} — split the list into smaller versions") from exc
    proposal = proposal.with_envelope(cosigned, {signing.public_key_hex(my_key): evidence or "n/a"})
    proposal = proposal.transition(ProposalState.APPROVED)
    store.save(proposal)
    return publish(ctx, store, proposal.id, typed_code=typed_code, yes=yes)


def _check_first_signer(ctx: CurateContext, envelope: signing.SignedEnvelope, proposal: Proposal, my_key: str) -> None:
    signers = ctx.manifest.curator_signers(envelope, statement_type=envelope.statement_type, graph=proposal.graph) \
        if proposal.kind != CuratorStatement.PROMOTION.value else \
        signing.verified_signers(envelope, statement_type=envelope.statement_type, environment=ctx.manifest.environment,
                                 graph=proposal.graph, chain=ctx.manifest.chain, root_epoch=ctx.manifest.root_epoch) \
        & frozenset(ctx.manifest.curator_keys)
    if not signers:
        raise VerbError("the proposal is not signed by a curator key in the trusted manifest")
    if my_key in signers:
        raise VerbError("you already signed this proposal; the SECOND signature must come from another curator")


# -- publish -----------------------------------------------------------------


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


# -- manifest (sandbox) --------------------------------------------------------


def manifest_proposal(ctx: CurateContext, store: ProposalStore, *, curator_keys: List[str], threshold: int,
                      promotion_author: str, root_epoch: int, version: int, legacy_uals: Iterable[str]) -> Proposal:
    """SANDBOX: a root-signed key manifest, stored APPROVED (one root signature
    is the whole quorum) for `curate publish`. On a real network the root is
    offline; its manifest arrives as a file, not from this verb (R7b)."""
    manifest = key_manifest.KeyManifest(environment=ctx.environment, graph=ctx.verified_graph, chain="",
                                        root_epoch=root_epoch, version=version, curator_keys=tuple(sorted(curator_keys)),
                                        threshold=threshold, promotion_author=promotion_author,
                                        legacy_assets_hash=key_manifest.legacy_assets_hash(legacy_uals))
    root: Ed25519PrivateKey = keys.root_key_store().load_or_create()
    envelope = key_manifest.sign_manifest(manifest, root)
    proposal = Proposal.new(MANIFEST_KIND, "curator", envelope, ctx.verified_graph,
                            checks={signing.public_key_hex(root): "root"})
    proposal = proposal.transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED)
    store.save(proposal)
    return proposal


def _require_manifest(ctx: CurateContext) -> None:
    if ctx.manifest is None:
        raise VerbError("no trusted key manifest on this network — publish one first (sandbox: `curate manifest`), "
                        "and make sure BLACKBOX_CURATOR_ROOT_KEYS names its root")
