"""Epoch-bound root pins and the freeze-only manifest verdict (trust-and-threat-lab K1).

A pinned root may sign key manifests of its own root epoch only. A pinned root
signing another epoch is recognised but FREEZE-ONLY: its manifest may conflict
with others at its order, never become the list readers act on — so no root can sign ahead into
another epoch's rotation, while the other root can still freeze
a conflicting list. The T1 reader cases (D31, "a freeze holds") follow: a conflict at
or below the sticky order never moves a reader, a conflict above it freezes its
order and every order above, and a narrowing list stays challengeable for 3 days.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.community.trust import authority_read
from plugins.blackbox.community.trust import manifests as trust_manifests
from plugins.blackbox.kernel import constants, signing
from plugins.blackbox.kernel.signing import ManifestVerdict, RootPins, trust_anchors
from plugins.blackbox.kernel.signing import key_manifest as km

MAINNET, SANDBOX = "otp:2043", "sim-sandbox"
VM_GRAPH = "0x37b1Fdfd/agent-blackbox-vm"
ROOT_ENV = "BLACKBOX_CURATOR_ROOT_KEYS"


@pytest.fixture
def roots(monkeypatch):
    """Root A pinned for epoch 1 and root B for epoch 2 on MAINNET (the K1 shape)."""
    root_a, root_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    monkeypatch.setattr(constants, "CURATOR_ROOT_KEYS", {MAINNET: {1: (signing.public_key_hex(root_a),),
                                                                   2: (signing.public_key_hex(root_b),)}})
    return root_a, root_b


def _manifest(*, root_epoch=1, version=1, environment=MAINNET, author="1"):
    curators = sorted(signing.public_key_hex(Ed25519PrivateKey.generate()) for _ in range(3))
    return km.KeyManifest(environment=environment, graph=VM_GRAPH, chain="base:8453", root_epoch=root_epoch,
                          version=version, curator_keys=tuple(curators),
                          curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2,
                          promotion_author="0x" + author * 40, legacy_assets_hash=km.legacy_assets_hash(["ual"]))


def _verify(manifest, root, environment=MAINNET, env=None):
    envelope = signing.from_text(km.sign_manifest(manifest, root).to_text())
    return km.verify_manifest(envelope, environment=environment, graph=VM_GRAPH,
                              roots=RootPins.for_environment(environment, env or {}))


def _row(manifest, root):
    return {"signedStatement": km.sign_manifest(manifest, root).to_text()}


def test_a_root_at_its_own_epoch_yields_a_candidate(roots):
    root_a, root_b = roots
    first, rotated = _manifest(root_epoch=1), _manifest(root_epoch=2)
    assert _verify(first, root_a) == ManifestVerdict(first, freeze_only=False)
    assert _verify(rotated, root_b) == ManifestVerdict(rotated, freeze_only=False)
    assert trust_manifests.effective_manifest(
        trust_manifests.trusted_manifests([_row(first, root_a), _row(rotated, root_b)], MAINNET, VM_GRAPH,
                                          RootPins.for_environment(MAINNET, {})), "2026-10-11") == rotated


def test_a_root_at_the_wrong_epoch_is_freeze_only(roots):
    root_a, root_b = roots
    leapfrog = _manifest(root_epoch=2)            # root A signs for the rotation epoch
    assert _verify(leapfrog, root_a) == ManifestVerdict(leapfrog, freeze_only=True)
    early = _manifest(root_epoch=1)               # root B signs epoch 1 (its counter-list in a freeze)
    assert _verify(early, root_b).freeze_only


def test_a_freeze_only_manifest_conflicts_but_never_becomes_the_list(roots):
    root_a, root_b = roots
    pins = RootPins.for_environment(MAINNET, {})
    current = _manifest(root_epoch=1, version=1)
    leapfrog = _manifest(root_epoch=2, version=1)
    verdicts = trust_manifests.trusted_manifests([_row(current, root_a), _row(leapfrog, root_a)], MAINNET, VM_GRAPH, pins)
    assert trust_manifests.effective_manifest(verdicts, "2026-10-11") == current   # the leapfrog is not acted on
    assert trust_manifests.newest_trusted_manifest([_row(current, root_a), _row(leapfrog, root_a)],
                                                   MAINNET, VM_GRAPH, pins) == current
    conflicting = _manifest(root_epoch=1, version=2, author="2")
    counter = _manifest(root_epoch=1, version=2, author="3")           # root B answers at the same order
    verdicts = trust_manifests.trusted_manifests([_row(current, root_a), _row(conflicting, root_a), _row(counter, root_b)],
                                                 MAINNET, VM_GRAPH, pins)
    assert trust_manifests.manifests_conflict(verdicts)
    assert trust_manifests.effective_manifest(verdicts, "2026-10-11") == current   # the conflicting v2 is frozen out


def test_a_fake_root_is_ignored_on_mainnet(roots):
    fake = Ed25519PrivateKey.generate()
    env = {ROOT_ENV: signing.public_key_hex(fake)}
    assert _verify(_manifest(root_epoch=1), fake, env=env) is None
    assert _verify(_manifest(root_epoch=2), fake, env=env) is None


def test_the_environment_override_is_ignored_once_pinned(roots):
    root_a, root_b = roots
    sandbox_root = signing.public_key_hex(Ed25519PrivateKey.generate())
    env = {ROOT_ENV: sandbox_root}
    pinned = RootPins.for_environment(MAINNET, env)
    assert pinned.pinned and sandbox_root not in pinned.keys
    assert pinned.keys == {signing.public_key_hex(root_a), signing.public_key_hex(root_b)}
    assert trust_anchors.trusted_roots(MAINNET, env) == pinned.keys
    unpinned = RootPins.for_environment(SANDBOX, env)          # an unlisted network still takes the variable
    assert not unpinned.pinned and unpinned.keys == {sandbox_root}
    assert unpinned.may_sign(sandbox_root, 1) and unpinned.may_sign(sandbox_root, 7)


def test_an_unpinned_network_root_signs_any_epoch():
    root = Ed25519PrivateKey.generate()
    env = {ROOT_ENV: signing.public_key_hex(root)}
    manifest = _manifest(root_epoch=5, environment=SANDBOX)
    assert _verify(manifest, root, environment=SANDBOX, env=env) == ManifestVerdict(manifest, freeze_only=False)


def test_root_pins_ignore_malformed_keys_and_empty_epochs(monkeypatch):
    good = "a" * 64
    monkeypatch.setattr(constants, "CURATOR_ROOT_KEYS", {MAINNET: {1: (good.upper(), "not-a-key"), 2: ()}})
    pins = RootPins.for_environment(MAINNET, {})
    assert pins.by_epoch == ((1, frozenset({good})),)
    assert pins.may_sign(good, 1) and not pins.may_sign(good, 2)
    assert not RootPins() and not RootPins.unbound(["", "zz"])


def test_a_listed_network_with_only_malformed_pins_fails_closed(monkeypatch):
    # Review of K1: a network listed in CURATOR_ROOT_KEYS must never fall back to the
    # environment variable, even when none of its pinned keys are well-formed.
    monkeypatch.setattr(constants, "CURATOR_ROOT_KEYS", {MAINNET: {1: ("not-a-key",), 2: ()}})
    env = {ROOT_ENV: "b" * 64}
    assert not RootPins.for_environment(MAINNET, env)
    assert trust_anchors.trusted_roots(MAINNET, env) == frozenset()


def test_the_shipped_root_pins_have_the_epoch_mapping_shape():
    for network, pins in constants.CURATOR_ROOT_KEYS.items():
        assert isinstance(network, str) and isinstance(pins, Mapping)
        assert all(isinstance(epoch, int) and isinstance(keys, tuple) for epoch, keys in pins.items())


def test_the_authority_read_stores_freeze_only_manifests(roots):
    # K1 review: the reader's store must keep a freeze-only manifest row, or the
    # conflict it raises (root A against root B) is forgotten on the next read.
    root_a, root_b = roots
    pins = RootPins.for_environment(MAINNET, {})
    leapfrog = _manifest(root_epoch=2)                        # freeze-only: root A at epoch 2
    stranger = _manifest(root_epoch=1)                        # not signed by any trusted root
    rows = [{"r": "leapfrog", **_row(leapfrog, root_a)},
            {"r": "stranger", **_row(stranger, Ed25519PrivateKey.generate())}]
    kept = authority_read._trusted_manifest_rows(rows, MAINNET, VM_GRAPH, pins)
    assert [row["r"] for row in kept] == ["leapfrog"]


# ------------------------------------------------------------------ T1: a freeze holds (D31)

DAY0 = "2026-10-01"                  # the day the lists below were issued
IN_FORCE = "2026-10-11"              # well past every 3-day time-lock
CURATORS = tuple(sorted(signing.public_key_hex(Ed25519PrivateKey.generate()) for _ in range(3)))


def _listed(version, *, issued=DAY0, curators=CURATORS, author="1"):
    """A dated epoch-1 list at *version* with fixed curators (so one can narrow another)."""
    operators = {key: f"operator-{index}" for index, key in enumerate(CURATORS)}
    return km.KeyManifest(environment=MAINNET, graph=VM_GRAPH, chain="base:8453", root_epoch=1, version=version,
                          curator_keys=tuple(curators), curator_operators=tuple(operators[key] for key in curators),
                          threshold=2, promotion_author="0x" + author * 40,
                          legacy_assets_hash=km.legacy_assets_hash(["ual"]), issued_day=issued)


def _trusted(*signed):
    """The trusted verdicts for (manifest, root) pairs, as a reader finds them."""
    return trust_manifests.trusted_manifests([_row(manifest, root) for manifest, root in signed], MAINNET, VM_GRAPH,
                                             RootPins.for_environment(MAINNET, {}))


def _read(verdicts, sticky, today=IN_FORCE):
    """(effective manifest, freezing conflict, ignored conflict) for a reader holding *sticky*."""
    order, content_hash = (sticky.order, sticky.content_hash()) if sticky else (None, "")
    return (trust_manifests.effective_manifest(verdicts, today, order, sticky_hash=content_hash),
            trust_manifests.manifests_conflict(verdicts, order), trust_manifests.ignored_conflict(verdicts, order))


def test_a_conflict_at_the_current_order_leaves_the_reader_where_it_is(roots):
    root_a, root_b = roots
    v3, v4 = _listed(3), _listed(4)
    conflicting_v4 = _listed(4, author="2")                     # root A conflicts the CURRENT list
    verdicts = _trusted((v3, root_a), (v4, root_a), (conflicting_v4, root_a))
    assert _read(verdicts, sticky=v4) == (v4, False, True)            # held, not rolled back — and alarmed
    counter = _trusted((v3, root_a), (v4, root_a), (conflicting_v4, root_b))   # root B's freeze-only verdict at v4
    assert _read(counter, sticky=v4) == (v4, False, True)
    # The accepted residual: a fresh install (no sticky memory) takes the newest order below the conflict.
    assert _read(verdicts, sticky=None) == (v3, True, False)


def test_a_conflict_at_v5_skips_v5_to_v7(roots):
    root_a, root_b = roots
    v4, v5, v6, v7 = (_listed(version) for version in (4, 5, 6, 7))
    counter_v5 = _listed(5, author="3")                   # one counter-list from the honest root
    verdicts = _trusted((v4, root_a), (v5, root_a), (counter_v5, root_b), (v6, root_a), (v7, root_a))
    assert _read(verdicts, sticky=v4) == (v4, True, False)            # v6 and v7 are above the conflict: frozen out
    assert _read(verdicts, sticky=None) == (v4, True, False)
    assert trust_manifests.conflict_orders(verdicts) == {(1, 5)}
    unconflicted = _trusted((v4, root_a), (v5, root_a), (v6, root_a), (v7, root_a))
    assert _read(unconflicted, sticky=v4) == (v7, False, False)       # without it, the reader moves on as before


def test_a_conflict_below_the_sticky_order_changes_nothing_and_flags_an_alarm(roots):
    root_a, root_b = roots
    v2, v3, v4 = _listed(2), _listed(3), _listed(4)
    conflicting_v2 = _listed(2, author="2")
    verdicts = _trusted((v2, root_a), (conflicting_v2, root_a), (v3, root_a), (v4, root_a))
    assert _read(verdicts, sticky=v4) == (v4, False, True)
    assert _read(_trusted((v2, root_a), (v3, root_a), (v4, root_a)), sticky=v4) == (v4, False, False)
    # A freeze-only verdict counts as a conflict at its order, never as a candidate (K1).
    leapfrog_below = _trusted((v3, root_a), (v4, root_a), (_listed(2, author="4"), root_b))
    assert _read(leapfrog_below, sticky=v4) == (v4, False, True)


def test_a_narrowing_list_conflicted_on_day_2_is_undone(roots):
    root_a, root_b = roots
    v1 = _listed(1)
    narrowed = _listed(2, issued="2026-10-11", curators=CURATORS[1:])  # drops ONE curator, issued today
    assert narrowed.narrows(v1)
    day0, day2, day3 = "2026-10-11", "2026-10-13", "2026-10-14"
    verdicts = _trusted((v1, root_a), (narrowed, root_a))
    assert _read(verdicts, sticky=v1, today=day0) == (narrowed, False, False)   # effective at once …
    # … but not sticky inside its 3 days: the in-force list it narrowed is (even for a reader with no memory yet).
    assert trust_manifests.sticky_after(verdicts, day0, v1.order, v1.content_hash()) == (v1.order, v1.content_hash())
    assert trust_manifests.sticky_after(verdicts, day0, None) == (v1.order, v1.content_hash())
    counter = _listed(2, issued="2026-10-13", author="5")                        # … but challengeable on day 2
    conflicted = _trusted((v1, root_a), (narrowed, root_a), (counter, root_b))
    assert _read(conflicted, sticky=v1, today=day2) == (v1, True, False)         # back to the sticky list
    # Unchallenged for its own 3 days, the narrowing list becomes sticky.
    assert trust_manifests.sticky_after(verdicts, day3, v1.order) == (narrowed.order, narrowed.content_hash())
    assert trust_manifests.sticky_after(conflicted, day3, v1.order, v1.content_hash()) == (v1.order, v1.content_hash())


def test_a_pending_list_that_does_not_narrow_still_waits(roots):
    root_a, _ = roots
    v1 = _listed(1)
    widened = _listed(2, issued="2026-10-11", author="6")                       # a new promotion author: not narrowing
    assert _read(_trusted((v1, root_a), (widened, root_a)), sticky=v1, today="2026-10-11")[0] == v1
    # narrows() ignores the order, so the reader checks it: a list BELOW the current one never narrows it.
    v3 = _listed(3)
    older = _listed(2, issued="2026-10-11", curators=CURATORS[1:])
    assert older.narrows(v3)
    assert _read(_trusted((v1, root_a), (older, root_a), (v3, root_a)), sticky=v3, today="2026-10-11")[0] == v3
    assert trust_manifests.effective_manifest([], "2026-10-11", v1.order) is None


def test_the_sticky_order_never_goes_down(roots):
    root_a, _ = roots
    v3, v4 = _listed(3), _listed(4)
    assert trust_manifests.sticky_after(_trusted((v3, root_a)), IN_FORCE, v4.order, "h") == (v4.order, "h")
    assert trust_manifests.sticky_after([], IN_FORCE, v4.order, "h") == (v4.order, "h")
    assert trust_manifests.sticky_after(_trusted((v3, root_a), (v4, root_a)), IN_FORCE, None) == (v4.order, v4.content_hash())


def test_at_the_sticky_order_the_reader_keeps_the_content_it_acted_on(roots):
    # T1 review: at a conflicted sticky order the stored content hash picks the list, never
    # the order the rows arrive in (newest() keeps the first of a tie).
    root_a, _ = roots
    v3, v4, conflicting_v4 = _listed(3), _listed(4), _listed(4, author="2")
    verdicts = _trusted((v3, root_a), (conflicting_v4, root_a), (v4, root_a))
    assert _read(verdicts, sticky=v4) == (v4, False, True)
    assert _read(_trusted((v3, root_a), (v4, root_a), (conflicting_v4, root_a)), sticky=conflicting_v4)[0] == conflicting_v4
    # Without a hash, an ambiguous sticky order is skipped, never guessed.
    assert trust_manifests.effective_manifest(verdicts, IN_FORCE, v4.order) == v3
