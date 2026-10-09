"""Sequence numbers for curator statements — which number the next one takes.

Each authority numbers its statements per identifier; readers act on the
highest number and resolve a tie toward the reduction. A curator machine must
therefore continue where the others left off, whichever kind the last
statement was — a listing, an attestation, a pause — and whichever machine
published it (KI-245: a machine that restarts at 1 collides with an existing
statement and may be silently ignored).

Usage::

    sequence = next_sequence(ctx, store, "author:<reporter key>")
"""

from __future__ import annotations

import logging
from typing import List

from ... import community
from ...kernel import signing
from ...kernel.signing.authority import Authority
from ..context import CurateContext
from ..proposal import ProposalStore

logger = logging.getLogger(__name__)


def next_sequence(ctx: CurateContext, store: ProposalStore, identifier: str) -> int:
    """One past the highest sequence this node knows for *identifier* under the
    acting authority: published statements of EVERY kind (looked up in the
    graphs and in this node's trust store) and this machine's own proposals."""
    seen = [0]
    seen.extend(_published_sequences(ctx, identifier))
    for proposal in store.for_identifier(identifier):
        envelope = proposal.parsed()
        if envelope is not None:
            seen.append(envelope.sequence)
    return max(seen) + 1


def _published_sequences(ctx: CurateContext, identifier: str) -> List[int]:
    """Sequence numbers of published statements about *identifier* that a
    curator key of the acting authority's manifest signed. Best effort: an
    unreadable graph contributes nothing (the proposal store still counts)."""
    manifest = ctx.manifest
    if manifest is None:
        return []
    try:
        candidates = community.known_curator_statements(ctx.client, ctx.cfg, [identifier],
                                                        verified_graph=ctx.authority is Authority.VERIFIED)
    except Exception as exc:   # the node is the curator's own; a failed read must not block proposing
        logger.debug("blackbox: sequence lookup failed (%s)", exc)
        return []
    numbers = []
    for graph, row in candidates:
        envelope = signing.from_text(row.get("signedStatement", ""))
        if envelope is not None and manifest.curator_signers(envelope, statement_type=envelope.statement_type, graph=graph):
            numbers.append(envelope.sequence)
    return numbers
