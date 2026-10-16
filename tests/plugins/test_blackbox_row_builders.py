"""P5 (trust-and-threat-lab §03.4) — the signed correction rows (``curate/publishing/row_builders``).

A correction suppresses exactly the subjects its signed payload names, one
signed ``CorrectionSignal`` row per target, and the R3 reader honours what it
writes. (Promotions no longer write rows — a report is promoted as itself:
``test_blackbox_one_graph_curator.py``; the rows earlier promotions wrote stay
served: ``test_blackbox_asset_tier.py``.)
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.curate.publishing import row_builders as rb
from plugins.blackbox.kernel import constants, signing, threat_ids
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement

NETWORK = "sandbox-net"
VERIFIED_GRAPH = "0xabc/agent-blackbox-vm"


@pytest.fixture(scope="module")
def keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


def _envelope(keys, payload, statement_type=CuratorStatement.PROMOTION.value):
    first = signing.sign(keys[0], statement_type=statement_type, environment=NETWORK, graph=VERIFIED_GRAPH,
                         payload=payload, root_epoch=1, sequence=1)
    return signing.cosign(first, keys[1])


def _plain(term: str) -> str:
    """A literal term's value (N-Triples escapes match JSON's for these)."""
    return json.loads(term)


def _signed_literal(quads):
    (term,) = [q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED]
    return _plain(term)


# ------------------------------------------------------------------ corrections (P5)

#: A legacy corpus row for 8.8.8.8 does not live at threat_uri(identifier) (F-031).
LEGACY_8888 = "urn:defender:signal:94f04f19bc0000000000000000000000"
OWN_8888 = threat_ids.threat_uri("ioc:ip:8.8.8.8")
CORRECTION_ASSET = f"{VERIFIED_GRAPH}/_verifiable_memory/7"


def _correction_envelope(signers, payload):
    first = signing.sign(signers[0], statement_type=rb.CORRECTION_STATEMENT, environment=NETWORK, graph=VERIFIED_GRAPH,
                         payload=payload, root_epoch=1, sequence=4)
    for key in signers[1:]:
        first = signing.cosign(first, key)
    return first


def _reader_rows(quads):
    """The correction lane's binding rows (graph_queries.CORRECTION_PROPERTIES) for *quads*."""
    variable = {constants.RDF_TYPE: "rdfType", constants.DEFENDER_CORRECTION_TARGET_PRED: "targetSubject",
                constants.DEFENDER_CORRECTION_ACTION_PRED: "correctionAction", constants.SIGNED_STATEMENT_PRED: "signedStatement"}
    rows = {}
    for quad in quads:
        if quad["predicate"] in variable:
            value = quad["object"] if quad["object"].startswith("urn:") else _plain(quad["object"])
            rows.setdefault(quad["subject"], {"g": CORRECTION_ASSET})[variable[quad["predicate"]]] = value
    return [(row, "public") for row in rows.values()]


def test_the_correction_payload_holds_the_looked_up_target_subjects():
    payload = rb.correction_payload("ioc:ip:8.8.8.8", [OWN_8888, LEGACY_8888, LEGACY_8888],
                                    reason="public DNS resolver", source="misp-warninglists:public-dns-v4")
    assert payload == {"action": "suppress", "targetSubjects": f"{LEGACY_8888} {OWN_8888}", "identifier": "ioc:ip:8.8.8.8",
                       "reason": "public DNS resolver", "source": "misp-warninglists:public-dns-v4"}
    assert all(isinstance(value, str) for value in payload.values())            # a flat str->str envelope payload


def test_the_rows_target_exactly_the_looked_up_subjects_never_the_identifiers_own_uri(keys):
    """F-031: 8.8.8.8 lives at urn:defender:signal:…; a row aimed at threat_uri(identifier) would miss it."""
    envelope = _correction_envelope(keys, rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888], reason="resolver",
                                                                source="misp"))
    quads = rb.correction_quads(envelope)
    targets = [q["object"] for q in quads if q["predicate"] == constants.DEFENDER_CORRECTION_TARGET_PRED]
    assert targets == [LEGACY_8888] and OWN_8888 not in json.dumps(quads)
    assert {q["object"] for q in quads if q["predicate"] == constants.RDF_TYPE} == {constants.DEFENDER_CORRECTION_TYPE_IRI}
    assert [_signed_literal(quads)] == [envelope.to_text()]                      # every row carries the envelope
    assert not any(q["predicate"] == constants.IDENTIFIER_PRED for q in quads)  # never a g:identifier rule


def test_each_target_gets_its_own_signed_row(keys):
    envelope = _correction_envelope(keys, rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888, OWN_8888],
                                                                reason="resolver", source="misp"))
    quads = rb.correction_quads(envelope)
    by_subject = {}
    for quad in quads:
        by_subject.setdefault(quad["subject"], {})[quad["predicate"]] = quad["object"]
    assert len(by_subject) == 2
    assert {row[constants.DEFENDER_CORRECTION_TARGET_PRED] for row in by_subject.values()} == {LEGACY_8888, OWN_8888}
    assert all(_plain(row[constants.SIGNED_STATEMENT_PRED]) == envelope.to_text() for row in by_subject.values())
    assert all(_plain(row["urn:defender:p:reason"]) == "resolver" for row in by_subject.values())


def test_the_r3_reader_honours_the_built_rows_with_a_curator_and_the_break_glass_key():
    """Round trip: what P5 writes is what ruleset/live/corrections honours — the break-glass key
    counts toward a correction (a reduction, K2), on the signed targets only."""
    from plugins.blackbox.ruleset.live import corrections

    curator_a, curator_b, break_glass = (Ed25519PrivateKey.generate() for _ in range(3))
    operators = {signing.public_key_hex(curator_a): "Umanitek", signing.public_key_hex(curator_b): "Umoja Ark",
                 signing.public_key_hex(break_glass): "Sealed"}
    manifest = km.KeyManifest(environment=NETWORK, graph=VERIFIED_GRAPH, chain="", root_epoch=1, version=1, threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]),
                              break_glass_key=signing.public_key_hex(break_glass), **km.roster(operators))
    payload = rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888, OWN_8888], reason="resolver", source="misp")
    rows = _reader_rows(rb.correction_quads(_correction_envelope((curator_a, break_glass), payload)))
    assert corrections.signed_suppressions(rows, {CORRECTION_ASSET: manifest}, frozenset()) == {LEGACY_8888, OWN_8888}
    alone = _reader_rows(rb.correction_quads(_correction_envelope((curator_a,), payload)))
    assert corrections.signed_suppressions(alone, {CORRECTION_ASSET: manifest}, frozenset()) == frozenset()


@pytest.mark.parametrize("subjects, reason, source, refused", [
    ([], "r", "s", "1 to 20 subjects"),
    ([f"urn:defender:signal:{n}" for n in range(21)], "r", "s", "1 to 20 subjects"),
    (["urn:x y"], "r", "s", "plain subject IRI"),
    (["urn:x>"], "r", "s", "plain subject IRI"),
    ([LEGACY_8888], " ", "s", "one-line reason"),
    ([LEGACY_8888], "r", "two\nlines", "one-line source"),
    ([LEGACY_8888], "r" * 201, "s", "one-line reason"),
])
def test_a_correction_payload_outside_its_shape_is_refused(subjects, reason, source, refused):
    with pytest.raises(rb.RowBuildError, match=refused):
        rb.correction_payload("ioc:ip:8.8.8.8", subjects, reason=reason, source=source)


def test_correction_rows_need_a_signed_suppress_correction(keys):
    payload = rb.correction_payload("ioc:ip:8.8.8.8", [LEGACY_8888], reason="r", source="s")
    with pytest.raises(rb.RowBuildError, match="signed blackbox.correction"):
        rb.correction_quads(_envelope(keys, payload))                             # a promotion envelope
    with pytest.raises(rb.RowBuildError, match="only a suppress"):
        rb.correction_quads(_correction_envelope(keys, {**payload, "action": "restore"}))
