"""Trust-and-threat-lab R3 — corrections published after the pin carry the same signed envelope as rules.

A correction in a legacy asset is honoured as before; a newer one only with a
quorum ``blackbox.correction`` envelope (break-glass counts: a correction
reduces enforcement), and only on the targets inside its signed payload.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.kernel import constants, signing, threat_ids
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.ruleset import compiler, graph_queries, live
from plugins.blackbox.ruleset.live import corrections

NETWORK = "sandbox-net"
CG = "did:dkg:base:8453/0x" + "a" * 40 + "/blackbox-threats"
VM = f"{CG}/_verifiable_memory/"
LEGACY_ASSET, NEW_ASSET, UNLISTED_ASSET = f"{VM}1", f"{VM}2", f"{VM}3"
CURATOR_A, CURATOR_B, BREAK_GLASS = (Ed25519PrivateKey.generate() for _ in range(3))
EVIL = threat_ids.threat_uri("dep:npm:evil-pkg@1.0.0")
LEGIT = threat_ids.threat_uri("dep:npm:left-pad@1.3.0")


def _manifest() -> km.KeyManifest:
    operators = {signing.public_key_hex(CURATOR_A): "Umanitek", signing.public_key_hex(CURATOR_B): "Umoja Ark",
                 signing.public_key_hex(BREAK_GLASS): "Sealed"}
    return km.KeyManifest(environment=NETWORK, graph=CG, chain="", root_epoch=1, version=1, threshold=2,
                          promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]),
                          break_glass_key=signing.public_key_hex(BREAK_GLASS), **km.roster(operators))


MANIFEST = _manifest()
MANIFESTS = {NEW_ASSET: MANIFEST, LEGACY_ASSET: MANIFEST}
LEGACY = frozenset({LEGACY_ASSET})


def _envelope(signers, *, targets=(EVIL,), action="suppress", statement_type=corrections.CORRECTION_STATEMENT):
    statement = signing.sign(signers[0], statement_type=statement_type, environment=NETWORK, graph=CG,
                             payload={"action": action, "targetSubjects": " ".join(targets)}, root_epoch=1, sequence=1)
    for key in signers[1:]:
        statement = signing.cosign(statement, key)
    return statement.to_text()


def _correction(target=EVIL, *, graph=NEW_ASSET, envelope="", action="suppress", source="public"):
    row = {"threat": f"urn:defender:correction:{graph[-1]}", "rdfType": constants.DEFENDER_CORRECTION_TYPE_IRI,
           "correctionAction": action, "targetSubject": target, "g": graph}
    if envelope:
        row["signedStatement"] = envelope
    return row, source


def _suppressed(*rows, manifests=MANIFESTS, legacy=LEGACY):
    return corrections.signed_suppressions(rows, manifests, legacy)


# ------------------------------------------------------------------ the acceptance cases


def test_a_legacy_correction_is_honoured_unsigned():
    assert _suppressed(_correction(graph=LEGACY_ASSET)) == {EVIL}


def test_before_the_pin_every_correction_is_honoured_as_today():
    assert _suppressed(_correction(graph=NEW_ASSET), legacy=None) == {EVIL}


def test_an_unsigned_post_pin_correction_is_ignored():
    assert _suppressed(_correction(graph=NEW_ASSET)) == frozenset()


def test_a_quorum_signed_post_pin_correction_is_honoured():
    assert _suppressed(_correction(envelope=_envelope((CURATOR_A, CURATOR_B)))) == {EVIL}


def test_a_re_aimed_correction_suppresses_nothing():
    """the wallet copies a valid correction's envelope onto a row aimed at a legitimate package."""
    re_aimed = _correction(LEGIT, envelope=_envelope((CURATOR_A, CURATOR_B), targets=(EVIL,)))
    assert _suppressed(re_aimed) == frozenset()


def test_break_glass_plus_one_curator_is_accepted():
    assert _suppressed(_correction(envelope=_envelope((CURATOR_A, BREAK_GLASS)))) == {EVIL}


# ------------------------------------------------------------------ what else must not suppress


def test_one_curator_alone_is_short_of_quorum():
    assert _suppressed(_correction(envelope=_envelope((CURATOR_A,)))) == frozenset()


def test_a_promotion_envelope_copied_onto_a_correction_is_ignored():
    """Break-glass cannot raise, and a promotion's signatures never vouch for a correction."""
    promotion = _envelope((CURATOR_A, CURATOR_B), statement_type="blackbox.promotion")
    assert _suppressed(_correction(envelope=promotion)) == frozenset()


def test_a_signed_non_suppress_payload_suppresses_nothing():
    assert _suppressed(_correction(envelope=_envelope((CURATOR_A, CURATOR_B), action="annotate"))) == frozenset()


def test_an_asset_without_a_manifest_in_force_suppresses_nothing():
    signed = _correction(graph=UNLISTED_ASSET, envelope=_envelope((CURATOR_A, CURATOR_B)))
    assert _suppressed(signed) == frozenset()


def test_a_malformed_envelope_suppresses_nothing():
    assert _suppressed(_correction(envelope="{not an envelope")) == frozenset()


def test_a_signed_correction_honours_only_the_row_target_among_several_signed():
    envelope = _envelope((CURATOR_A, CURATOR_B), targets=(EVIL, LEGIT))
    assert _suppressed(_correction(EVIL, envelope=envelope)) == {EVIL}


def test_community_rows_never_correct_anything():
    assert _suppressed(_correction(graph=LEGACY_ASSET, source="community"), legacy=None) == frozenset()


def test_only_a_correction_signal_row_can_suppress():
    """Review R3 (mutation pass): a row of another type that carries a target and a
    suppress action is not a correction, even in a legacy asset or before the pin."""
    row, source = _correction(graph=LEGACY_ASSET)
    impostor = ({**row, "rdfType": "urn:defender:DependencySignal"}, source)
    assert _suppressed(impostor) == frozenset()
    assert _suppressed(impostor, legacy=None) == frozenset()


# ------------------------------------------------------------------ the compiler and the query use it


def _threat_row(subject):
    return ({"threat": subject, "rdfType": "urn:defender:InjectionSignal", "identifier": "inj:" + subject[-8:],
             "kind": "injection", "severity": "high", "pattern": "ignore previous", "g": NEW_ASSET}, "public")


def test_the_compiler_withdraws_only_honoured_targets():
    rows = [_correction(graph=NEW_ASSET), _threat_row(EVIL)]
    assert compiler.build_from_rows(rows).suppressed_subjects == {EVIL}          # no pin passed: as today
    pin = live.CorrectionPin(MANIFESTS, LEGACY)
    assert compiler.build_from_rows(rows, pin=pin).suppressed_subjects == frozenset()
    signed = [_correction(envelope=_envelope((CURATOR_A, BREAK_GLASS))), _threat_row(EVIL)]
    built = compiler.build_from_rows(signed, pin=pin)
    assert built.suppressed_subjects == {EVIL}
    assert not built.graph_threats                                               # the withdrawn threat is not compiled
    assert compiler.build_from_rows(rows, pin=pin).graph_threats                 # an ignored correction withdraws nothing


def test_the_correction_lanes_fetch_the_envelope_literal():
    small = [lane for lane in graph_queries._verified_small_tier_lanes(10, "", VM) if "CorrectionSignal" in lane]
    paged = [lane for lane in graph_queries._defender_threats_sparql(10) if "CorrectionSignal" in lane]
    for lane in (*small, *paged):
        assert f"<{constants.SIGNED_STATEMENT_PRED}> ?signedStatement" in lane
        assert "?signedStatement" in lane.split("WHERE")[0]


def test_the_live_package_exports_signed_suppressions():
    assert live.signed_suppressions is corrections.signed_suppressions
    assert {"signed_suppressions", "CorrectionPin", "NO_PIN"} <= set(live.__all__)
    assert live.NO_PIN.legacy is None                                             # the default: no pin, as today
