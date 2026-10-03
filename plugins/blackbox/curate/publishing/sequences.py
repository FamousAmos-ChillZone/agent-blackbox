"""Sequence numbers for curator statements — which number the next one takes."""

from __future__ import annotations

from ..context import CurateContext
from ..proposal import ProposalStore


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
