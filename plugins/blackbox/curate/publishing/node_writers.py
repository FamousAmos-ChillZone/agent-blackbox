"""The node side of the paid publishes — one call per publish-ledger step (pattern: Adapter over the DKG routes).

A paid publish to Verified Memory is split into the steps the publish ledger
(:mod:`.ledger`) walks, so a failure is retried as what it was: a free write
that failed is retried as such, while a publish that may have been paid for
is never sent again on a guess (LES-011).

* :class:`NodeBatchWriter` — a verified batch asset: seal it in working
  memory and share it in full (KI-351), submit it to ``/vm/publish``, ask the
  node for its UAL, read every signed row back.
* :class:`SubmitReply` — what ``/vm/publish`` answered; :func:`definite_refusal`
  — whether a failed call definitely spent nothing.

Usage::

    writer = NodeBatchWriter(ctx.client, ctx.verified_graph)
    writer.seal(name, quads)                   # QUEUED → SEALED
    reply = writer.submit(name)                # SUBMITTED → MINTED / BOUND
    writer.readable({subject: envelope_text})  # True / False / None (could not tell)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import quote, urlencode

from ... import community
from ...kernel import constants, signing, sparql_text
from ...kernel.dkg_client import DkgClient, DkgError


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

    def seal(self, name: str, quads: list[dict[str, str]]) -> None:
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
