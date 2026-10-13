"""kernel.signing.graph_migration — the authority may name a successor graph.

A graph migration is a root-signed statement, verified with the same
epoch-bound rules as a key manifest: these tests pin the round trip, that
every signed field (the cut-off day above all) is bound by the signature,
that a root pinned for another epoch can only conflict (``freeze_only``), and
the migration's row in the authority table. How readers follow a migration is
reader policy (community/trust) and is tested there. Keys are generated at runtime.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing import graph_migration as gm
from plugins.blackbox.kernel.signing.authority import (
    COMMUNITY_GRAPH,
    VERIFIED_GRAPH,
    Authority,
    RootStatement,
    allowed_kinds,
    home_graph,
)
from plugins.blackbox.kernel.signing.trust_anchors import RootPins

NETWORK = "otp:20430"
OLD_GRAPH = "0x37b1Fdfd/agent-blackbox-vm"
NEW_GRAPH = "0x9a0cE11e/agent-blackbox-vm"


@pytest.fixture
def root():
    return Ed25519PrivateKey.generate()


def _migration(**changes) -> gm.GraphMigration:
    fields = dict(environment=NETWORK, from_graph=OLD_GRAPH, to_graph=NEW_GRAPH, from_day="2026-10-10",
                  issued_day="2026-10-11", root_epoch=1, sequence=1)
    fields.update(changes)
    return gm.GraphMigration(**fields)


def _pins(root, epoch=1) -> RootPins:
    return RootPins(by_epoch=((epoch, frozenset({signing.public_key_hex(root)})),))


def _verify(envelope, roots, **overrides):
    args = {"environment": NETWORK, "graph": OLD_GRAPH, "roots": roots}
    args.update(overrides)
    return gm.verify_migration(envelope, **args)


def _resigned(root, envelope, payload):
    """*envelope*'s domain with another payload, validly signed by *root*."""
    return signing.sign(root, statement_type=envelope.statement_type, environment=envelope.environment,
                        graph=envelope.graph, payload=payload, root_epoch=envelope.root_epoch,
                        sequence=envelope.sequence)


# ------------------------------------------------------------------ sign, parse, verify


def test_a_root_signed_migration_round_trips_through_text(root):
    migration = _migration()
    text = gm.sign_migration(migration, root).to_text()
    verdict = _verify(signing.from_text(text), _pins(root))
    assert verdict == gm.MigrationVerdict(migration, freeze_only=False)
    assert gm.parse_migration(migration.to_payload()) == migration


def test_a_tampered_from_day_fails_verification(root):
    envelope = gm.sign_migration(_migration(), root)
    tampered = replace(envelope, payload={**envelope.payload, "fromDay": "2026-01-01"})
    assert _verify(tampered, _pins(root)) is None


@pytest.mark.parametrize("field, value", [
    ("toGraph", "0xdead/agent-blackbox-vm"), ("issuedDay", "2026-10-01"), ("environment", "otp:2043"),
    ("fromGraph", "0xother/graph"), ("rootEpoch", "2"), ("sequence", "9"),
])
def test_every_payload_field_is_bound_by_the_signature(root, field, value):
    envelope = gm.sign_migration(_migration(), root)
    assert _verify(replace(envelope, payload={**envelope.payload, field: value}), _pins(root)) is None


def test_a_wrong_epoch_root_yields_freeze_only(root):
    """A root pinned for epoch 1 that signs an epoch-2 migration is recognised
    but can only conflict, never be followed."""
    verdict = _verify(gm.sign_migration(_migration(root_epoch=2), root), _pins(root, epoch=1))
    assert verdict is not None and verdict.freeze_only


def test_an_unbound_root_may_sign_any_epoch(root):
    roots = RootPins.unbound([signing.public_key_hex(root)])
    assert not _verify(gm.sign_migration(_migration(root_epoch=5), root), roots).freeze_only


def test_one_signer_pinned_for_the_epoch_makes_the_migration_followable(root):
    """freeze_only only when NO signer may sign the epoch: a co-signature by
    the epoch's own root lifts a wrong-epoch root's verdict."""
    current_root = Ed25519PrivateKey.generate()
    roots = RootPins(by_epoch=((1, frozenset({signing.public_key_hex(root)})),
                               (2, frozenset({signing.public_key_hex(current_root)}))))
    envelope = gm.sign_migration(_migration(root_epoch=2), root)
    assert _verify(envelope, roots).freeze_only
    assert not _verify(signing.cosign(envelope, current_root), roots).freeze_only


def test_an_untrusted_signer_is_not_a_migration(root):
    envelope = gm.sign_migration(_migration(), Ed25519PrivateKey.generate())
    assert _verify(envelope, _pins(root)) is None
    assert _verify(None, _pins(root)) is None
    assert _verify(gm.sign_migration(_migration(), root), RootPins()) is None


@pytest.mark.parametrize("override", [{"environment": "otp:2043"}, {"graph": NEW_GRAPH}, {"graph": "0xother/graph"}])
def test_a_migration_is_bound_to_its_environment_and_from_graph(root, override):
    assert _verify(gm.sign_migration(_migration(), root), _pins(root), **override) is None


def test_a_root_signed_manifest_is_never_read_as_a_migration(root):
    """The statement type is signed: another root statement with the same payload does not verify."""
    envelope = gm.sign_migration(_migration(), root)
    other_type = signing.sign(root, statement_type=signing.key_manifest.KEY_MANIFEST_STATEMENT, environment=NETWORK,
                              graph=OLD_GRAPH, payload=envelope.payload, root_epoch=1, sequence=1)
    assert _verify(other_type, _pins(root)) is None


def test_a_payload_that_disagrees_with_its_signed_domain_is_refused(root):
    """Signed, but the payload's order is not the envelope's: refused, so
    the order readers compare is the one the signature binds."""
    envelope = gm.sign_migration(_migration(), root)
    assert _verify(_resigned(root, envelope, {**envelope.payload, "sequence": "2"}), _pins(root)) is None
    assert _verify(_resigned(root, envelope, {**envelope.payload, "rootEpoch": "0"}), _pins(root)) is None
    on_chain = signing.sign(root, statement_type=gm.GRAPH_MIGRATION_STATEMENT, environment=NETWORK, graph=OLD_GRAPH,
                            payload=envelope.payload, chain="base:8453", root_epoch=1, sequence=1)
    assert _verify(on_chain, _pins(root)) is None


@pytest.mark.parametrize("payload_change", [{"sequence": "01"}, {"extra": "x"}])
def test_only_the_canonical_payload_verifies(root, payload_change):
    """One migration has one signed form, so it has one statement identity."""
    envelope = gm.sign_migration(_migration(), root)
    assert _verify(_resigned(root, envelope, {**envelope.payload, **payload_change}), _pins(root)) is None


# ------------------------------------------------------------------ the value object


def test_migrations_order_by_root_epoch_then_sequence():
    ordered = [_migration(root_epoch=1, sequence=9), _migration(root_epoch=2, sequence=1),
               _migration(root_epoch=2, sequence=3)]
    shuffled = [ordered[2], ordered[0], ordered[1]]
    assert sorted(shuffled, key=lambda m: m.order) == ordered
    assert _migration(root_epoch=2, sequence=1).order > _migration(root_epoch=1, sequence=99).order


@pytest.mark.parametrize("change", [
    {"to_graph": OLD_GRAPH}, {"environment": ""}, {"from_graph": " 0xpadded"}, {"to_graph": ""},
    {"from_day": "2026-10-1"}, {"from_day": "2026-13-01"}, {"issued_day": ""}, {"issued_day": "20261011"},
    # A day that does not exist, and a 10-character ISO week date fromisoformat accepts.
    {"from_day": "2026-02-30"}, {"issued_day": "2026-W41-1"},
    {"root_epoch": -1}, {"sequence": 0},
])
def test_an_invalid_migration_cannot_be_built(change):
    with pytest.raises(gm.GraphMigrationError):
        _migration(**change)


@pytest.mark.parametrize("payload, message", [
    ({}, "missing"), ({"rootEpoch": "one"}, "integers"), ({"toGraph": OLD_GRAPH}, "differ"),
])
def test_a_malformed_payload_is_a_clear_parse_error(payload, message):
    full = _migration().to_payload()
    candidate = payload if not payload else {**full, **payload}
    with pytest.raises(gm.GraphMigrationError, match=message):
        gm.parse_migration(candidate)


# ------------------------------------------------------------------ the authority table


def test_only_the_verified_authority_names_a_successor_and_it_lives_in_the_verified_graph():
    assert home_graph(Authority.VERIFIED, RootStatement.GRAPH_MIGRATION) == VERIFIED_GRAPH
    assert home_graph(Authority.COMMUNITY, RootStatement.GRAPH_MIGRATION) is None


def test_each_authoritys_manifest_lives_in_its_own_graph():
    assert home_graph(Authority.VERIFIED, RootStatement.KEY_MANIFEST) == VERIFIED_GRAPH
    assert home_graph(Authority.COMMUNITY, RootStatement.KEY_MANIFEST) == COMMUNITY_GRAPH


def test_root_statements_carry_the_signed_statement_types_and_stay_out_of_curator_filters():
    assert RootStatement.GRAPH_MIGRATION.value == gm.GRAPH_MIGRATION_STATEMENT
    assert RootStatement.KEY_MANIFEST.value == signing.key_manifest.KEY_MANIFEST_STATEMENT
    for authority in Authority:
        for in_verified_graph in (True, False):
            assert not any(isinstance(kind, RootStatement)
                           for kind in allowed_kinds(authority, in_verified_graph=in_verified_graph))
