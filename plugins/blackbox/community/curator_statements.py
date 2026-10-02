"""Curator statements on the wire — build, sign, and parse (Refine R2).

The curator's verdicts and notices — confirmation, rejection, revocation,
in-review, deferral-lapsed, backlog, away, and the Phase 1 counted-author
list — travel as ONE kind of graph asset: a ``g:CuratorStatement`` subject
carrying the threat identifier and a signed envelope (:mod:`..kernel.signing`).
Everything a reader acts on is inside the SIGNED payload; the one shown field
(the identifier) must agree with it.

Each statement type has a CLOSED payload schema (exact key set, closed
values). The reduction-only ones — revocation and rejection — use
:data:`REDUCTION_SCHEMA`, frozen forever, so every reader version accepts them
(asymmetric safety, LES-016). A statement counts only when the trusted key
manifest's curator keys signed it: the full threshold for statements that
raise enforcement (2-of-3, KI-134), one curator key for the others.

Every statement is a NEW asset: its subject includes the per-identifier
sequence number, so nothing is ever re-shared at the same version (KI-103);
"latest" is decided by sequence (:mod:`..kernel.signing.statement_order`).

Pattern: Value Object (:class:`CuratorRecord`) with paired build / parse
functions, and a Strategy table of per-type payload validators.

Usage (curator side, R6)::

    envelope = curator_statements.sign_statement(CuratorStatement.REVOCATION, "dep:npm:x@1",
        sequence=4, fields={"reason": "false-positive"}, key=key_a, manifest=manifest, graph=vm_graph)
    envelope = signing.cosign(envelope, key_b)
    quads = curator_statements.statement_quads(envelope)

Usage (reader side)::

    record = curator_statements.parse_statement(row, manifest, graph=vm_graph)   # None = ignore
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..kernel import constants, rdf_terms, signing, sparql_text, threat_ids
from ..kernel.dkg_client import extract_binding
from ..kernel.signing.key_manifest import KeyManifest
from ..kernel.signing.statement_order import CuratorStatement
from . import report_schema

#: The frozen payload schema of reduction-only statements (revocation,
#: rejection): every reader version must accept it, forever. Never edit.
REDUCTION_SCHEMA = frozenset({"identifier", "reason", "day"})

_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_ADDRESS = re.compile(r"0x[0-9a-f]{40}")
_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_LANES = frozenset({"1", "2", "3", "4", "5"})

#: The reader variable carrying the envelope.
SIGNED_STATEMENT_VAR = "signedStatement"


@dataclass(frozen=True)
class CuratorRecord:
    """One VERIFIED curator statement.

    ``kind`` — its :class:`CuratorStatement`; ``identifier`` — the threat
    (or ``author:0x…`` for a counted-author entry, ``curator`` for backlog /
    away); ``sequence`` — the signed per-identifier sequence; ``day`` — the
    signed UTC day; ``fields`` — the validated payload extras, sorted;
    ``signers`` — the manifest curator keys that signed it.
    """

    kind: CuratorStatement
    identifier: str
    sequence: int
    day: str
    fields: Tuple[Tuple[str, str], ...]
    signers: FrozenSet[str]

    def field(self, name: str) -> str:
        return dict(self.fields).get(name, "")


# -- per-type payload validators (Strategy table): extras in -> extras out, or None


def _reason_from(allowed: Tuple[str, ...]) -> Callable[[Mapping[str, str]], Optional[Dict[str, str]]]:
    def check(extras: Mapping[str, str]) -> Optional[Dict[str, str]]:
        reason = extras.get("reason", "")
        return {"reason": reason} if set(extras) == {"reason"} and reason in allowed else None
    return check


def _no_extras(extras: Mapping[str, str]) -> Optional[Dict[str, str]]:
    return {} if not extras else None


def _days(*names: str) -> Callable[[Mapping[str, str]], Optional[Dict[str, str]]]:
    def check(extras: Mapping[str, str]) -> Optional[Dict[str, str]]:
        ok = set(extras) == set(names) and all(_DAY.fullmatch(extras[n]) for n in names)
        return dict(extras) if ok else None
    return check


def _backlog(extras: Mapping[str, str]) -> Optional[Dict[str, str]]:
    lanes = extras.get("lanes", "").split(",")
    ok = set(extras) == {"lanes", "until"} and bool(lanes) and set(lanes) <= _LANES and _DAY.fullmatch(extras["until"])
    return dict(extras) if ok else None


def _away(extras: Mapping[str, str]) -> Optional[Dict[str, str]]:
    ok = (set(extras) == {"key", "from", "until"} and _KEY_HEX.fullmatch(extras["key"])
          and _DAY.fullmatch(extras["from"]) and _DAY.fullmatch(extras["until"]))
    return dict(extras) if ok else None


def _counted_author(extras: Mapping[str, str]) -> Optional[Dict[str, str]]:
    """One counted-author entry: listed yes/no, class, org (partners), expiry."""
    keys = {"listed", "class", "org", "expires"}
    if set(extras) != keys or extras["listed"] not in ("yes", "no") or not _DAY.fullmatch(extras["expires"]):
        return None
    if extras["class"] not in constants.COUNTED_AUTHOR_CLASSES:
        return None
    if extras["class"] == "partner" and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", extras["org"]):
        return None   # all of an organisation's keys share one cluster, so a partner names its org
    return dict(extras)


_VALIDATORS: Dict[CuratorStatement, Callable[[Mapping[str, str]], Optional[Dict[str, str]]]] = {
    CuratorStatement.REVOCATION: _reason_from(constants.REVOCATION_REASONS),
    CuratorStatement.REJECTION: _reason_from(constants.REJECTION_REASONS),
    CuratorStatement.CONFIRMATION: _no_extras,
    CuratorStatement.IN_REVIEW: _no_extras,
    CuratorStatement.DEFERRAL_LAPSED: _no_extras,
    CuratorStatement.PAUSE: _days("until"),
    CuratorStatement.BACKLOG: _backlog,
    CuratorStatement.AWAY: _away,
    CuratorStatement.COUNTED_AUTHORS: _counted_author,
}


def _identifier_ok(kind: CuratorStatement, identifier: str) -> bool:
    if kind is CuratorStatement.COUNTED_AUTHORS:
        return identifier.startswith("author:") and bool(_ADDRESS.fullmatch(identifier[len("author:"):]))
    if kind in (CuratorStatement.BACKLOG, CuratorStatement.AWAY, CuratorStatement.PAUSE):
        return identifier == "curator"
    try:
        return report_schema.validate_statement_identifier(identifier) == identifier
    except report_schema.ReportValidationError:
        return False


def _validated_payload(kind: CuratorStatement, payload: Mapping[str, str]) -> Optional[Tuple[str, str, Dict[str, str]]]:
    """(identifier, day, extras) when *payload* meets its type's closed schema."""
    if kind is CuratorStatement.PROMOTION:
        return None   # promotions are written in the verified-rule vocabulary (R6), not here
    identifier, day = payload.get("identifier", ""), payload.get("day", "")
    if not _identifier_ok(kind, identifier) or not _DAY.fullmatch(day):
        return None
    extras = _VALIDATORS[kind]({k: v for k, v in payload.items() if k not in ("identifier", "day")})
    return None if extras is None else (identifier, day, extras)


# -- build (curator side) ----------------------------------------------------


def sign_statement(kind: CuratorStatement, identifier: str, *, sequence: int, fields: Mapping[str, str],
                   key: Ed25519PrivateKey, manifest: KeyManifest, graph: str,
                   day: Optional[date] = None) -> signing.SignedEnvelope:
    """The first signature on a curator statement (co-sign with
    :func:`..kernel.signing.cosign`). Raises ``ValueError`` for a payload that
    does not meet the type's closed schema."""
    when = (day or datetime.now(timezone.utc).date()).isoformat()
    payload = {"identifier": identifier, "day": when, **dict(fields)}
    if _validated_payload(kind, payload) is None:
        raise ValueError(f"not a valid {kind.value} statement")
    return signing.sign(key, statement_type=kind.value, environment=manifest.environment, graph=graph,
                        payload=payload, chain=manifest.chain, root_epoch=manifest.root_epoch, sequence=sequence)


def statement_subject(kind: CuratorStatement, identifier: str, sequence: int) -> str:
    """``urn:guardian:curator:<type>:<identifier hash>:<sequence>`` — a new
    asset per statement (never a same-version re-share)."""
    return f"urn:guardian:curator:{kind.value.split('.', 1)[1]}:{threat_ids.stable_hash(identifier, 24)}:{sequence}"


def statement_quads(envelope: signing.SignedEnvelope) -> List[rdf_terms.Quad]:
    """The graph quads for a signed curator statement."""
    kind = CuratorStatement(envelope.statement_type)
    identifier = envelope.payload["identifier"]
    subject = statement_subject(kind, identifier, envelope.sequence)
    return [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.CURATOR_STATEMENT_TYPE_IRI)),
        rdf_terms.make_quad(subject, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(envelope.to_text())),
    ]


# -- parse (reader side) -----------------------------------------------------


def parse_statement(row: Mapping[str, Any], manifest: Optional[KeyManifest], *, graph: str) -> Optional[CuratorRecord]:
    """The verified curator statement in *row*, or None to ignore it.

    None without a trusted *manifest*, for an unknown type, a payload outside
    its closed schema, a shown identifier that disagrees with the signed one,
    a subject that is not the statement's own, or too few curator signatures
    (the full threshold for statements that raise enforcement). Never raises.
    """
    if manifest is None:
        return None
    envelope = signing.from_text(extract_binding(row.get(SIGNED_STATEMENT_VAR)))
    if envelope is None:
        return None
    try:
        kind = CuratorStatement(envelope.statement_type)
    except ValueError:
        return None
    validated = _validated_payload(kind, envelope.payload)
    if validated is None:
        return None
    identifier, day, extras = validated
    shown = (extract_binding(row.get("r")), extract_binding(row.get("identifier")).strip())
    if shown != (statement_subject(kind, identifier, envelope.sequence), identifier):
        return None
    signers = manifest.curator_signers(envelope, statement_type=kind.value, graph=graph)
    needed = manifest.threshold if kind.raises_enforcement else 1
    if len(signers) < needed:
        return None
    return CuratorRecord(kind=kind, identifier=identifier, sequence=envelope.sequence, day=day,
                         fields=tuple(sorted(extras.items())), signers=signers)


def curator_statements_sparql(after: str) -> str:
    """One page of curator statements after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?identifier ?signedStatement WHERE {{
  ?r a g:CuratorStatement ;
     g:identifier ?identifier ;
     g:signedStatement ?signedStatement .
  {cursor}
}} ORDER BY STR(?r) LIMIT 5000
"""

