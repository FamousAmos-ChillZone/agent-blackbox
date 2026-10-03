"""Which proposals the service takes in, and which of its own are finished (Community Curation C9).

Two questions the beat asks about a proposal, both answered from signatures
and the graph, never from what a message claims:

* :func:`from_a_curator` — anyone can message a curator node. A received
  proposal is kept only when its envelope is what the proposal says it is and
  a curator key of the trusted manifest signed it.
* :func:`published_elsewhere` — "whoever signs second publishes", so the node
  that signed FIRST never sees its own proposal change state. It is finished
  when the graph holds that same signed statement with enough signatures.
"""

from __future__ import annotations

from typing import Optional

from ... import community
from ...kernel import signing, threat_ids
from ...kernel.signing.key_manifest import KeyManifest
from ...kernel.signing.statement_order import CuratorStatement
from ..context import CurateContext
from ..proposal import Proposal


def from_a_curator(manifest: Optional[KeyManifest], proposal: Proposal) -> bool:
    """True when *proposal* is consistent with its own envelope (id, kind,
    graph) and a curator key of *manifest* signed that envelope."""
    envelope = proposal.parsed()
    if envelope is None or manifest is None:
        return False
    if (proposal.id, proposal.kind, proposal.graph) != (threat_ids.stable_hash(proposal.envelope, 16),
                                                        envelope.statement_type, envelope.graph):
        return False
    signers = signing.verified_signers(envelope, statement_type=envelope.statement_type, environment=manifest.environment,
                                       graph=envelope.graph, chain=manifest.chain, root_epoch=manifest.root_epoch)
    return bool(signers & frozenset(manifest.curator_keys))


def published_elsewhere(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> bool:
    """True when the community graph holds the statement *proposal* proposes —
    the same signed content — carrying the signatures its kind needs (another
    curator co-signed and published it)."""
    manifest = ctx.manifest
    if manifest is None or proposal.graph != ctx.community_graph:
        return False
    try:
        kind = CuratorStatement(proposal.kind)
    except ValueError:
        return False
    wanted = signing.content_id(envelope)
    needed = manifest.threshold if kind.needs_quorum else 1
    for _graph, row in community.known_curator_statements(ctx.client, ctx.cfg, [proposal.identifier]):
        held = signing.from_text(row.get("signedStatement", ""))
        if held is not None and signing.content_id(held) == wanted and len(
                manifest.curator_signers(held, statement_type=kind.value, graph=proposal.graph)) >= needed:
            return True
    return False
