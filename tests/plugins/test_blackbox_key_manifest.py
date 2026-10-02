"""Refine R7a — the curator signing envelope and the key-manifest format.

The plan's tests: a sandbox key is rejected on mainnet; replayed
lower-sequence statements lose to terminal ones; the legacy corpus keeps
serving. Plus the format's own guarantees: two signatures over the same
domain-separated bytes, 2-of-3 quorum, manifest order by (root epoch,
version), and a manifest signed by anything but the root is not trusted.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import statement_order as order

MAINNET, SANDBOX = "otp:2043", "sim-sandbox"
VM_GRAPH = "0x37b1Fdfd/agent-blackbox-vm"
CHAIN = "base:8453"
PROMOTION = order.CuratorStatement.PROMOTION.value
LEGACY = ["did:dkg:base:8453/0xabc/1", "did:dkg:base:8453/0xabc/2"]


def _keys(n):
    return [Ed25519PrivateKey.generate() for _ in range(n)]


def _hex(keys):
    return tuple(sorted(signing.public_key_hex(k) for k in keys))


def _manifest(curators, *, environment=MAINNET, root_epoch=1, version=1, threshold=2):
    return km.KeyManifest(environment=environment, graph=VM_GRAPH, chain=CHAIN, root_epoch=root_epoch,
                          version=version, curator_keys=_hex(curators), threshold=threshold,
                          promotion_author="0x1111111111111111111111111111111111111111",
                          legacy_assets_hash=km.legacy_assets_hash(LEGACY))


def _statement(signers, *, environment=MAINNET, root_epoch=1, sequence=1, statement_type=PROMOTION):
    first, *rest = signers
    envelope = signing.sign(first, statement_type=statement_type, environment=environment, graph=VM_GRAPH,
                            payload={"identifier": "dep:npm:evil@1.0.0"}, chain=CHAIN,
                            root_epoch=root_epoch, sequence=sequence)
    for key in rest:
        envelope = signing.cosign(envelope, key)
    return envelope


# ------------------------------------------------------------------ envelope


def test_two_signatures_cover_the_same_domain_separated_bytes():
    a, b = _keys(2)
    statement = signing.from_text(_statement([a, b]).to_text())
    assert signing.verified_signers(statement, statement_type=PROMOTION, environment=MAINNET, graph=VM_GRAPH,
                                    chain=CHAIN, root_epoch=1) == frozenset(_hex([a, b]))
    for field, value in (("chain", "base:84532"), ("root_epoch", 2), ("sequence", 99)):
        moved = signing.SignedEnvelope(**{**statement.__dict__, field: value})
        assert signing.verified_signers(moved, statement_type=PROMOTION, environment=MAINNET,
                                        graph=VM_GRAPH) == frozenset()


def test_a_key_cannot_sign_twice_and_reporter_verify_refuses_cosigned_statements():
    a, b = _keys(2)
    with pytest.raises(ValueError):
        signing.cosign(_statement([a]), a)
    assert signing.verify(_statement([a, b]), statement_type=PROMOTION, environment=MAINNET, graph=VM_GRAPH) is None


# ------------------------------------------------------------------ quorum + environments


def test_two_of_three_curator_keys_make_a_quorum_one_does_not():
    a, b, c = _keys(3)
    manifest = _manifest([a, b, c])
    assert manifest.has_quorum(_statement([a, c]), statement_type=PROMOTION)
    assert not manifest.has_quorum(_statement([b]), statement_type=PROMOTION)


def test_a_sandbox_key_is_rejected_on_mainnet():
    """The plan's test (KI-143): per-environment keys + the environment inside the signature."""
    main_a, main_b, main_c, sand_a, sand_b = _keys(5)
    mainnet = _manifest([main_a, main_b, main_c])
    # Sandbox keys signing a statement FOR mainnet: not mainnet's keys.
    assert not mainnet.has_quorum(_statement([sand_a, sand_b]), statement_type=PROMOTION)
    # Mainnet keys' signatures made in the sandbox cannot be replayed on mainnet.
    assert not mainnet.has_quorum(_statement([main_a, main_b], environment=SANDBOX), statement_type=PROMOTION)
    assert mainnet.has_quorum(_statement([main_a, main_b]), statement_type=PROMOTION)


def test_a_statement_from_another_root_epoch_does_not_count():
    a, b, c = _keys(3)
    assert not _manifest([a, b, c], root_epoch=2).has_quorum(_statement([a, b], root_epoch=1),
                                                            statement_type=PROMOTION)


# ------------------------------------------------------------------ manifest format


def test_a_root_signed_manifest_round_trips_and_nothing_else_is_trusted():
    root, impostor, *curators = _keys(5)
    manifest = _manifest(curators)
    envelope = signing.from_text(km.sign_manifest(manifest, root).to_text())
    roots = {signing.public_key_hex(root)}
    assert km.verify_manifest(envelope, environment=MAINNET, graph=VM_GRAPH, root_keys=roots) == manifest
    assert km.verify_manifest(km.sign_manifest(manifest, impostor), environment=MAINNET, graph=VM_GRAPH,
                              root_keys=roots) is None
    assert km.verify_manifest(envelope, environment=SANDBOX, graph=VM_GRAPH, root_keys=roots) is None
    forged = signing.SignedEnvelope(**{**envelope.__dict__, "payload": {**envelope.payload, "threshold": "1"}})
    assert km.verify_manifest(forged, environment=MAINNET, graph=VM_GRAPH, root_keys=roots) is None


def test_manifests_order_by_root_epoch_then_version():
    curators = _keys(3)
    old_root_max = _manifest(curators, root_epoch=1, version=2**31)
    rotated = _manifest(curators, root_epoch=2, version=1)
    assert km.newest([rotated, old_root_max]) == rotated
    assert km.newest([_manifest(curators, version=3), _manifest(curators, version=4)]).version == 4


@pytest.mark.parametrize("change", [
    {"threshold": 1},                                  # one key is never enough (KI-134)
    {"threshold": 4},                                  # more than the keys listed
    {"curator_keys": ("ab" * 32, "ab" * 32)},          # duplicate keys
    {"curator_keys": ("not-a-key",)},
    {"version": 0},
    {"legacy_assets_hash": "not-a-hash"},
    {"promotion_author": ""},
])
def test_an_invalid_manifest_cannot_be_built(change):
    valid = _manifest(_keys(3)).__dict__
    with pytest.raises(km.KeyManifestError):
        km.KeyManifest(**{**valid, **change})


# ------------------------------------------------------------------ ordering: replays lose


def test_replayed_lower_sequence_statements_lose_to_terminal_ones():
    """The plan's test: an old promotion re-shared after a revocation must not resurrect the rule."""
    threat = "dep:npm:evil@1.0.0"
    promotion = order.OrderedStatement(threat, order.CuratorStatement.PROMOTION, 3)
    revocation = order.OrderedStatement(threat, order.CuratorStatement.REVOCATION, 5)
    for arrival in ([promotion, revocation], [revocation, promotion]):
        assert order.current_by_threat(arrival)[threat] == revocation
    repromotion = order.OrderedStatement(threat, order.CuratorStatement.PROMOTION, 7)
    assert order.current_by_threat([revocation, promotion, repromotion])[threat] == repromotion
    tie = order.OrderedStatement(threat, order.CuratorStatement.PROMOTION, 5)
    assert order.current_by_threat([tie, revocation])[threat] == revocation   # safety is asymmetric


def test_statement_types_know_whether_they_raise_or_end_enforcement():
    kinds = order.CuratorStatement
    assert {k for k in kinds if k.raises_enforcement} == {kinds.PROMOTION, kinds.PAUSE, kinds.CONFIRMATION,
                                                         kinds.COUNTED_AUTHORS, kinds.BACKLOG}
    assert {k for k in kinds if k.terminal} == {kinds.REVOCATION, kinds.REJECTION}


# ------------------------------------------------------------------ legacy corpus


def test_the_legacy_corpus_is_grandfathered_by_its_content_hash():
    """KI-118: requiring signatures must never un-serve the existing corpus.
    The first manifest pins EXACTLY the legacy asset set: order and repeats
    don't matter, but an asset added afterwards is not legacy."""
    manifest = _manifest(_keys(3))
    assert manifest.grandfathers(list(reversed(LEGACY)) + LEGACY[:1])
    assert not manifest.grandfathers(LEGACY + ["did:dkg:base:8453/0xabc/3"])


def test_the_canonical_signed_bytes_are_pinned_to_the_envelope_version():
    """Every reader on every machine must build the SAME bytes. If this test
    fails, the encoding changed: bump ENVELOPE_VERSION (old signatures must
    then fail, not silently verify differently) and re-pin both values."""
    import hashlib
    from plugins.blackbox.kernel.signing import envelope
    fixed = envelope.SignedEnvelope(statement_type="blackbox.promotion", environment="otp:2043", graph="g",
                                    schema_version=1, payload={"identifier": "dep:npm:evil@1.0.0"}, signatures=(),
                                    chain="base:8453", root_epoch=1, sequence=7)
    assert envelope.ENVELOPE_VERSION == 2
    assert hashlib.sha256(envelope._signed_message(fixed)).hexdigest() == (
        "acea28b35f71bf06324e291744cd48470618d62744079518467144bca619fd62")
