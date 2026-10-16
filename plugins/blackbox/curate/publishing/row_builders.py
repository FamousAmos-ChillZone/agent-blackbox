"""Row builders — the signed correction rows a correction is written as (trust-and-threat-lab P5, §03.4).

A correction is not a threat category: :func:`correction_payload` is what the
curators sign to suppress the subjects the verified graph holds for one
address, and :func:`correction_quads` writes one ``CorrectionSignal`` row per
signed target, each carrying the envelope (its community-graph twin:
``publish.advisory_twin``).

Promotions no longer write rows: a promoted report is published as itself,
with the curators' statement beside it (``kernel.signing.promotion_statement``). The
verified rows earlier promotions wrote stay as they are, read by the verified
reader's envelope tier (``ruleset/live/envelope_tier.py``).

Usage::

    payload = row_builders.correction_payload("ioc:ip:8.8.8.8", subjects, reason=..., source=...)
    envelope = ctx.cosign(ctx.sign(CorrectionDraft(payload, sequence=n), key_a), key_b)
    quads = row_builders.correction_quads(envelope)
"""

from __future__ import annotations

from typing import Sequence

from ...kernel import constants, rdf_terms, signing, threat_ids
from ..context import CORRECTION_STATEMENT

_DEFENDER_PREDICATE = "urn:defender:p:"


class RowBuildError(ValueError):
    """A correction that must not be written: the message says why."""


# ---------------------------------------------------------------- corrections and the advisory twin (P5)

#: How many subjects one correction may name, and its reason/source length (the envelope stays under 4 KB).
MAX_CORRECTION_TARGETS, _CORRECTION_TEXT_MAX = 20, 200
_IRI_UNSAFE = frozenset('<>"{}|^`\\ \r\n\t')


def correction_payload(identifier: str, subjects: Sequence[str], *, reason: str, source: str) -> dict[str, str]:
    """The flat payload the curators sign to suppress *subjects* — the subjects
    the verified graph holds for *identifier*, read first (F-031: a legacy row
    does not live at ``threat_uri(identifier)``). The reader honours only the
    targets inside this payload (``ruleset/live/corrections.py``)."""
    targets = sorted(set(subjects))
    if not 0 < len(targets) <= MAX_CORRECTION_TARGETS:
        raise RowBuildError(f"a correction names 1 to {MAX_CORRECTION_TARGETS} subjects, not {len(targets)}")
    if any(not target or len(target) > 512 or _IRI_UNSAFE & set(target) for target in targets):
        raise RowBuildError("a correction target must be a plain subject IRI")
    for label, text in (("reason", reason), ("source", source)):
        if not text.strip() or len(text) > _CORRECTION_TEXT_MAX or not text.isprintable():
            raise RowBuildError(f"a correction needs a one-line {label} of at most {_CORRECTION_TEXT_MAX} characters")
    return {"action": constants.DEFENDER_CORRECTION_SUPPRESS, "targetSubjects": " ".join(targets),
            "identifier": identifier, "reason": reason.strip(), "source": source.strip()}


def correction_quads(envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
    """One ``CorrectionSignal`` suppress row per signed target, each carrying the
    envelope — the shape the R3 reader honours. No ``g:identifier`` on purpose:
    the legacy identifier lane would compile such a row into a rule."""
    if envelope.statement_type != CORRECTION_STATEMENT or not envelope.signatures:
        raise RowBuildError(f"a correction row needs a signed {CORRECTION_STATEMENT} envelope")
    payload = envelope.payload
    if payload.get("action") != constants.DEFENDER_CORRECTION_SUPPRESS:
        raise RowBuildError("only a suppress correction is written")
    signed = rdf_terms.literal(envelope.to_text())
    prefix = f"urn:blackbox:correction:{threat_ids.stable_hash(payload.get('identifier', ''), 16)}:{envelope.sequence}"
    quads = []
    for target in str(payload.get("targetSubjects", "")).split():
        subject = f"{prefix}:{threat_ids.stable_hash(target, 12)}"
        quads += [
            rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.DEFENDER_CORRECTION_TYPE_IRI)),
            rdf_terms.make_quad(subject, constants.DEFENDER_CORRECTION_TARGET_PRED, rdf_terms.iri(target)),
            rdf_terms.make_quad(subject, constants.DEFENDER_CORRECTION_ACTION_PRED,
                                rdf_terms.literal(constants.DEFENDER_CORRECTION_SUPPRESS)),
            rdf_terms.make_quad(subject, f"{_DEFENDER_PREDICATE}reason", rdf_terms.literal(payload.get("reason", ""))),
            rdf_terms.make_quad(subject, f"{_DEFENDER_PREDICATE}source", rdf_terms.literal(payload.get("source", ""))),
            rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, signed),
        ]
    if not quads:
        raise RowBuildError("the signed correction names no target subject")
    rdf_terms.assert_quads_literal_size(quads, label="correction row")
    return quads

