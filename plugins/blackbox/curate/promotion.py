"""Promotion — a community report enters the verified tier AS ITSELF (Refine R6, the one-graph flow).

Edge nodes share signed reports into the verified graph's shared memory,
sub-graph ``reports``. The curators review one report and promote it: two
curator keys sign a promotion statement that POINTS at it
(``kernel.signing.promotion_statement``: identifier, report subject, the report's
digest, severity, day), and the publish step publishes the reporter's own
report from shared memory to Verified Memory with the statement beside it
(:mod:`.publishing`). Nothing is copied and nothing stays curator-private:
the report is the provenance. Once promoted it is permanent in Verified
Memory and names its reporter (agent address and reporter key) — the
project's accepted trade-off.

* :func:`choose_report` — which of an identifier's reports a promotion points at;
* :func:`payload_for` — the payload the first curator signs for that report;
* :func:`checked_report` — what every signer and the publisher run before
  acting on a promotion (KI-195): the report re-read on THIS node, its digest
  and its scope checked;
* :func:`report_copies` — where this node holds a report (asset, layer), read
  from the node's own store;
* :func:`asset_name` — the statement asset's name (one per promotion).

Scope: dependency (kind ``malware`` only — R6: a vulnerability never
blocks), IOC, skill and file-access reports, exactly as reported — a
whole-package report (``@*``, a typosquat or mirror collision) promotes every
version, and the checklist asks for its reason. An injection report carries
the hash of its pattern, never the pattern, so it cannot be promoted.

Usage::

    report = promotion.choose_report(read.reports, "dep:npm:x@1.0.0")
    payload = promotion.payload_for(report, severity="critical")
    envelope = ctx.sign(PromotionDraft(payload, sequence=n), key)   # first key (curate.context); ctx.cosign adds the second
    report = promotion.checked_report(ctx, envelope)                  # every later key and the publisher, before acting
"""

from __future__ import annotations

from datetime import date, datetime, UTC
from typing import Iterable, Optional

from .. import community
from ..kernel import constants, signing, threat_ids
from ..kernel.dkg_client import DkgClient, DkgError
from ..kernel.signing import promotion_statement as statement
from ..kernel.store import StoreClient, loopback_store_url
from .context import CurateContext

#: Copies of one report a lookup reads at most (keep-alive copies, a shared and a verified one).
_COPIES_PER_REPORT = 32


class PromotionError(ValueError):
    """A promotion outside the promotable scope, or one this node cannot check."""


def choose_report(reports: Iterable[community.VerifiedReport], identifier: str,
                  subject: str = "") -> community.VerifiedReport:
    """The report a promotion of *identifier* points at: the one with
    *subject* when given, else the EARLIEST report (its signed day, then its
    subject) — the first reporter is the one the verified rule names. Raises
    :class:`PromotionError` when there is none."""
    candidates = [report for report in reports if report.identifier == identifier and (not subject or report.subject == subject)]
    if not candidates:
        where = f" with subject {subject}" if subject else ""
        raise PromotionError(f"no verified community report of {identifier}{where}: a promotion points at a report")
    return min(candidates, key=lambda report: (report.day or "9999-12-31", report.subject))


def payload_for(report: community.VerifiedReport, *, severity: str, today: Optional[date] = None) -> dict[str, str]:
    """The flat payload the curators sign to promote *report*. Raises
    :class:`PromotionError` for a report outside the promotable scope."""
    check_scope(report)
    envelope = signing.from_text(report.signed)
    if envelope is None:
        raise PromotionError("the report carries no signed statement")
    try:
        return statement.promotion_payload(report.identifier, report=report.subject,
                                           report_digest=signing.content_id(envelope), reporter_key=report.author,
                                           severity=severity.strip().lower(),
                                           day=(today or datetime.now(UTC).date()).isoformat())
    except ValueError as exc:
        raise PromotionError(str(exc)) from exc


def check_scope(report: community.VerifiedReport) -> None:
    """Refuse a report no promotion may point at (see the module doc)."""
    if not report.identifier.startswith(statement.PROMOTABLE_PREFIXES):
        raise PromotionError(f"a report is promoted as {statement.PROMOTABLE_PREFIXES} only: {report.identifier} "
                             "is not (an injection report carries no pattern)")
    if report.identifier.startswith("dep:") and dict(report.fields).get("kind") != constants.KIND_MALWARE:
        raise PromotionError("R6 promotes malware dependencies only: this report's signed kind is not malware")


def checked_report(ctx: CurateContext, envelope: Optional[signing.SignedEnvelope]) -> community.VerifiedReport:
    """The report a promotion *envelope* points at, re-read and checked on
    THIS node — what every curator key and the publisher run before acting on
    it (KI-195: the first signer's client may have been modified, and a person
    approving sees only the summary). The report must be held here, in
    shared or Verified Memory, with exactly the signed digest, signed by the
    named reporter key for this network, and the identifier the promotion
    names. Raises :class:`PromotionError`."""
    promotion = statement.parse(envelope)
    if promotion is None:
        raise PromotionError("the payload is not a well-formed promotion of a report")
    copies = report_copies(ctx.client, ctx.verified_graph, [promotion.report])
    if copies is None:
        raise PromotionError("this node's store could not be read: the report cannot be checked (try again)")
    report = verified_copy(ctx, promotion, copies)
    if report is None:
        raise PromotionError(f"this node does not hold the report {promotion.report} with the signed digest "
                             "and reporter key: nothing is signed or published until it does")
    check_scope(report)
    return report


def verified_copy(ctx: CurateContext, promotion: statement.Promotion,
                  copies: Iterable[statement.ReportCopy]) -> Optional[community.VerifiedReport]:
    """The report among *copies* that IS the one *promotion* names — its
    digest, signed by its reporter key (:func:`statement.is_the_report`) for
    this network and the one graph — reporting the promoted identifier; None
    when no copy is."""
    for copy in copies:
        envelope = signing.from_text(copy.text)
        if envelope is None or envelope.graph != ctx.verified_graph or not statement.is_the_report(promotion, copy.text):
            continue
        report = community.ReportVerifier(ctx.environment, ctx.verified_graph).verify_signed(copy.text)
        if report is not None and (report.subject, report.identifier) == (promotion.report, promotion.identifier):
            return report
    return None


def report_copies(client: DkgClient, graph: str, subjects: Iterable[str]) -> Optional[list[statement.ReportCopy]]:
    """Every copy of the reports *subjects* this node holds in *graph* — shared
    or verified, each in an asset its own reporter authored — read from the
    node's own store; None when the store could not be asked or could not tell."""
    wanted = sorted(set(subjects))
    sparql = statement.report_copies_sparql(graph, wanted, _COPIES_PER_REPORT * max(1, len(wanted)))
    if not sparql:
        return []
    try:
        url = loopback_store_url(client.status(timeout=5.0))
    except DkgError:
        return None
    answer = StoreClient(url).select(sparql) if url else None
    if answer is None or not answer.known:
        return None
    return [copy for row in answer.rows or [] if (copy := statement.report_copy(graph, row)) is not None]


def asset_name(identifier: str, sequence: int) -> str:
    """The knowledge-asset name of one promotion statement (a new asset per statement)."""
    return f"promotion-{threat_ids.stable_hash(identifier, 16)}-{sequence}"
