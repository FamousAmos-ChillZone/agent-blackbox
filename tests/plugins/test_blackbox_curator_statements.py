"""Refine R2 — curator statements on the wire: build, sign, parse.

A curator statement counts only when the trusted key manifest's curator keys
signed it (the full threshold for statements that raise enforcement, one key
otherwise), its payload meets its type's closed schema, and its shown
identifier and subject agree with what was signed. Reductions use a frozen
schema every reader accepts.
"""

from __future__ import annotations

import json
from datetime import date

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

NETWORK = "562ea760dbe27fb4233d58dfc958bbddf844b82596ec3d51dff98718e6bf61ca"
VM_GRAPH = "0x37b1Fdfd/agent-blackbox-vm"
COMMUNITY = "0x51E5dE758A45/agent-blackbox-community-dev"
THREAT = "dep:npm:evil@1.0.0"
DAY = date(2026, 10, 2)


@pytest.fixture(scope="module")
def keys():
    return [Ed25519PrivateKey.generate() for _ in range(4)]   # three curators + one outsider


@pytest.fixture(scope="module")
def manifest(keys):
    return km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1,
                          curator_keys=tuple(sorted(signing.public_key_hex(k) for k in keys[:3])), threshold=2,
                          promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))


def _row(envelope):
    row = {}
    for quad in cs.statement_quads(envelope):
        row["r"] = quad["subject"]
        if quad["predicate"].endswith("/identifier"):
            row["identifier"] = json.loads(quad["object"])
        if quad["predicate"].endswith("/signedStatement"):
            row["signedStatement"] = json.loads(quad["object"])
    return row


def _statement(kind, identifier, fields, signers, manifest, *, graph=VM_GRAPH, sequence=1):
    envelope = cs.sign_statement(kind, identifier, sequence=sequence, fields=fields, key=signers[0],
                                 manifest=manifest, graph=graph, day=DAY)
    for key in signers[1:]:
        envelope = signing.cosign(envelope, key)
    return envelope


# ------------------------------------------------------------------ round trip


def test_a_two_key_revocation_round_trips(keys, manifest):
    record = cs.parse_statement(_row(_statement(Kind.REVOCATION, THREAT, {"reason": "false-positive"},
                                                keys[:2], manifest, sequence=4)), manifest, graph=VM_GRAPH)
    assert (record.kind, record.identifier, record.sequence, record.day) == (Kind.REVOCATION, THREAT, 4, "2026-10-02")
    assert record.field("reason") == "false-positive" and len(record.signers) == 2


def test_quorum_statements_need_the_threshold_single_key_notices_one_key(keys, manifest):
    """Plan §09: promotion, rejection, revocation, the counted-author list and
    anything raising enforcement need 2-of-3; only in-review, deferral-lapsed
    and away notices are single-key (one key can never reject or revoke alone)."""
    one = keys[:1]
    raising = [(Kind.CONFIRMATION, THREAT, {}),
               (Kind.REJECTION, THREAT, {"reason": "duplicate"}),
               (Kind.REVOCATION, THREAT, {"reason": "false-positive"}),
               (Kind.COUNTED_AUTHORS, "author:" + "a" * 64,
                {"listed": "yes", "class": "established", "org": "", "expires": "2027-01-01",
                 "address": "0x" + "a" * 40}),
               (Kind.BACKLOG, "curator", {"lanes": "3,4,5", "until": "2026-10-09"})]
    for kind, identifier, fields in raising:
        assert cs.parse_statement(_row(_statement(kind, identifier, fields, one, manifest)), manifest,
                                  graph=VM_GRAPH) is None, kind
        assert cs.parse_statement(_row(_statement(kind, identifier, fields, keys[:2], manifest)), manifest,
                                  graph=VM_GRAPH) is not None, kind
    advisory = [(Kind.IN_REVIEW, THREAT, {}), (Kind.DEFERRAL_LAPSED, THREAT, {}),
                (Kind.AWAY, "curator", {"key": signing.public_key_hex(keys[0]), "from": "2026-10-02",
                                        "until": "2026-10-05"})]
    for kind, identifier, fields in advisory:
        assert cs.parse_statement(_row(_statement(kind, identifier, fields, one, manifest)), manifest,
                                  graph=VM_GRAPH) is not None, kind


# ------------------------------------------------------------------ what is ignored


def test_statements_without_a_trusted_manifest_or_from_outside_keys_are_ignored(keys, manifest):
    row = _row(_statement(Kind.IN_REVIEW, THREAT, {}, keys[3:4], manifest))   # the outsider
    assert cs.parse_statement(row, manifest, graph=VM_GRAPH) is None
    assert cs.parse_statement(_row(_statement(Kind.IN_REVIEW, THREAT, {}, keys[:1], manifest)), None,
                              graph=VM_GRAPH) is None


def test_a_statement_signed_for_one_graph_does_not_count_in_another(keys, manifest):
    community = _statement(Kind.REJECTION, THREAT, {"reason": "benign"}, keys[:2], manifest, graph=COMMUNITY)
    assert cs.parse_statement(_row(community), manifest, graph=COMMUNITY) is not None
    assert cs.parse_statement(_row(community), manifest, graph=VM_GRAPH) is None


def test_a_shown_identifier_or_subject_that_disagrees_is_ignored(keys, manifest):
    row = _row(_statement(Kind.REVOCATION, THREAT, {"reason": "superseded"}, keys[:2], manifest))
    assert cs.parse_statement({**row, "identifier": "dep:npm:other@1"}, manifest, graph=VM_GRAPH) is None
    assert cs.parse_statement({**row, "r": "urn:guardian:curator:revocation:x:1"}, manifest, graph=VM_GRAPH) is None


@pytest.mark.parametrize("kind, identifier, fields", [
    (Kind.REVOCATION, THREAT, {"reason": "i changed my mind"}),             # not a closed reason
    (Kind.REJECTION, THREAT, {"reason": "benign", "note": "free text"}),    # an extra field
    (Kind.CONFIRMATION, "not an identifier", {}),
    (Kind.COUNTED_AUTHORS, "author:0x" + "a" * 40,                       # an ADDRESS is not an identity (LES-014)
     {"listed": "yes", "class": "established", "org": "", "expires": "2027-01-01", "address": "0x" + "a" * 40}),
    (Kind.COUNTED_AUTHORS, "author:" + "b" * 64,                         # a partner must name its org
     {"listed": "yes", "class": "partner", "org": "", "expires": "2027-01-01", "address": "0x" + "b" * 40}),
    (Kind.BACKLOG, "curator", {"lanes": "9", "until": "2026-10-09"}),
    (Kind.AWAY, "curator", {"key": "short", "from": "2026-10-02", "until": "2026-10-05"}),
    (Kind.PROMOTION, THREAT, {}),                                            # promotions are R6's vocabulary
])
def test_a_payload_outside_its_closed_schema_cannot_be_built(keys, manifest, kind, identifier, fields):
    with pytest.raises(ValueError):
        cs.sign_statement(kind, identifier, sequence=1, fields=fields, key=keys[0], manifest=manifest,
                          graph=VM_GRAPH, day=DAY)


def test_a_hand_built_envelope_outside_the_schema_is_ignored(keys, manifest):
    envelope = signing.sign(keys[0], statement_type=Kind.REVOCATION.value, environment=NETWORK, graph=VM_GRAPH,
                            payload={"identifier": THREAT, "day": "2026-10-02", "reason": "because"},
                            root_epoch=1, sequence=1)
    envelope = signing.cosign(envelope, keys[1])
    assert cs.parse_statement(_row(envelope), manifest, graph=VM_GRAPH) is None


# ------------------------------------------------------------------ the frozen reduction schema


def test_the_reduction_schema_is_frozen():
    """Every reader version must accept revocations and rejections (LES-016).
    Changing this set breaks old readers: never edit it."""
    assert cs.REDUCTION_SCHEMA == frozenset({"identifier", "reason", "day"})


def test_reductions_are_built_in_exactly_the_frozen_schema(keys, manifest):
    for kind, reason in ((Kind.REVOCATION, "dispute-upheld"), (Kind.REJECTION, "allowlisted")):
        envelope = _statement(kind, THREAT, {"reason": reason}, keys[:2], manifest)
        assert set(envelope.payload) == cs.REDUCTION_SCHEMA


def test_every_statement_is_a_new_asset():
    a = cs.statement_subject(Kind.REVOCATION, THREAT, 4)
    assert a != cs.statement_subject(Kind.REVOCATION, THREAT, 5) and a.endswith(":4")
