"""Community Curation C2 — two authorities that cannot speak for each other.

The VERIFIED authority (roots pinned per network, manifest in the verified
graph) may say everything. The COMMUNITY authority (roots pinned per community
graph, manifest and statements in the community graph) may list and delist
counted authors, confirm, reject, defer and attest community threats, pause
community intake and publish notices — and nothing that touches the verified
tier. Each authority is verified against its own manifest and ordered in its
own sequence; between them the most restrictive current word wins.

Every test here drives one attack or one rule from the proposal (KI-242,
KI-243, KI-245), on rows served by a fake node — keys are generated at runtime.
"""

from __future__ import annotations

from datetime import date

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_blackbox_curator_view import _curator_row, _entry, _manifest_row

from plugins.blackbox.community import read_curator_view
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust.combine import combine
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import trust_anchors
from plugins.blackbox.kernel.signing.authority import Authority, allowed_kinds, home_graph
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

VM_GRAPH = "0x37b1Fdfd/agent-blackbox-vm"
CFG = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id=VM_GRAPH)
THREAT = "ioc:domain:evil.example"
TODAY = date(2026, 10, 2).isoformat()   # the day the helper rows are signed
#: What a community confirmation must carry: the signed reference to the evidence its curators checked.
CITED = {"evidence": "advisory:MAL-2026-0001"}


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


class Side:
    """One authority's keys and manifest: a root, three curator keys, 2-of-3."""

    def __init__(self, graph: str) -> None:
        self.root = Ed25519PrivateKey.generate()
        self.curators = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.graph = graph
        self.manifest = km.KeyManifest(
            environment=NETWORK, graph=graph, chain="", root_epoch=1, version=1,
            curator_keys=tuple(sorted(signing.public_key_hex(k) for k in self.curators)), threshold=2,
            promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))

    @property
    def root_hex(self) -> str:
        return signing.public_key_hex(self.root)

    def manifest_row(self):
        return _manifest_row(self.manifest, self.root)

    def row(self, kind, identifier, fields, *, graph=None, sequence=1, signers=2):
        return _curator_row(kind, identifier, fields, self.curators[:signers], self.manifest,
                            graph=graph or self.graph, sequence=sequence)


class Graphs:
    """A node serving two graphs. Rows are never consumed; a graph listed in
    *failing* answers every query with the caller's error sentinel."""

    def __init__(self, verified=(), community=(), failing=()):
        self.rows = {VM_GRAPH: list(verified), GRAPH: list(community)}
        self.failing = set(failing)

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if cg_id in self.failing:
            return on_error
        rows = self.rows.get(cg_id, [])
        if "g:KeyManifest" in sparql:
            return [r for r in rows if "key-manifest" in r["r"]]
        if "g:CuratorStatement" in sparql:
            return [r for r in rows if "curator:" in r["r"]]
        return []


@pytest.fixture
def verified():
    return Side(VM_GRAPH)


@pytest.fixture
def community():
    return Side(GRAPH)


@pytest.fixture
def both_trusted(monkeypatch, verified, community):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", community.root_hex)


@pytest.fixture
def community_trusted(monkeypatch, community):
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", community.root_hex)


# ------------------------------------------------------------------ the table

#: Every statement kind, decided explicitly: (verified authority's home, community authority's home).
EXPECTED_HOMES = {
    Kind.PROMOTION: ("verified", None),
    Kind.REVOCATION: ("verified", None),
    Kind.PAUSE: ("verified", "community"),
    Kind.COUNTED_AUTHORS: ("verified", "community"),
    Kind.CONFIRMATION: ("community", "community"),
    Kind.REJECTION: ("community", "community"),
    Kind.ATTESTATION: ("community", "community"),
    Kind.IN_REVIEW: ("community", "community"),
    Kind.DEFERRAL: ("community", "community"),
    Kind.DEFERRAL_LAPSED: ("community", "community"),
    Kind.BACKLOG: ("community", "community"),
    Kind.AWAY: ("community", "community"),
    Kind.HEARTBEAT: ("community", "community"),
}


def test_every_statement_kind_has_a_decided_home_for_both_authorities():
    assert set(EXPECTED_HOMES) == set(Kind), "a new statement kind needs a row in the authority table and here"
    for kind, (verified_home, community_home) in EXPECTED_HOMES.items():
        assert home_graph(Authority.VERIFIED, kind) == verified_home, kind
        assert home_graph(Authority.COMMUNITY, kind) == community_home, kind


def test_the_community_authority_has_no_place_in_the_verified_graph_and_no_verified_tier_powers():
    assert allowed_kinds(Authority.COMMUNITY, in_verified_graph=True) == frozenset()
    in_community = allowed_kinds(Authority.COMMUNITY, in_verified_graph=False)
    assert Kind.PROMOTION not in in_community and Kind.REVOCATION not in in_community


# ------------------------------------------------------------------ roots are separated


def test_a_community_root_cannot_sign_a_manifest_for_the_verified_graph(community_trusted, community):
    """KI-242: the community root is trusted for the community graph only."""
    forged = Side(VM_GRAPH)
    forged.root = community.root   # the community root signs a VERIFIED-graph manifest
    alice = Reporter("0xa")
    node = Graphs(verified=[forged.manifest_row(),
                            forged.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author)),
                            forged.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"})])
    view = read_curator_view(node, CFG)
    assert view.manifest is None and not view.counted and view.revoked == frozenset()


def test_a_verified_root_is_not_accepted_for_a_community_manifest(monkeypatch, verified):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    impostor = Side(GRAPH)
    impostor.root = verified.root   # the verified root signs a COMMUNITY-graph manifest
    alice = Reporter("0xa")
    node = Graphs(community=[impostor.manifest_row(),
                             impostor.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))])
    view = read_curator_view(node, CFG)
    assert not view.counted and view.community is None


def test_without_any_trusted_root_nothing_counts(verified, community):
    alice = Reporter("0xa")
    node = Graphs(verified=[verified.manifest_row()],
                  community=[community.manifest_row(),
                             community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))])
    assert read_curator_view(node, CFG) == cv.CuratorView()


def test_a_pinned_community_graph_ignores_the_environment(monkeypatch, community):
    pinned = "ab" * 32
    monkeypatch.setattr(trust_anchors, "COMMUNITY_ROOT_KEYS", {GRAPH: (pinned, "cd" * 32)})
    env = {"BLACKBOX_COMMUNITY_ROOT_KEYS": community.root_hex}
    assert trust_anchors.community_roots(GRAPH, env) == {pinned, "cd" * 32}
    assert trust_anchors.community_roots("0xother/dev-graph", env) == {community.root_hex}
    assert trust_anchors.community_root_pinned(GRAPH) and not trust_anchors.community_root_pinned("0xother/dev-graph")
    assert trust_anchors.community_roots("", env) == frozenset()


def test_the_two_authorities_never_share_a_graph(community_trusted, community):
    """A community graph that is also the configured verified graph gets no community authority."""
    alice = Reporter("0xa")
    node = Graphs(community=[community.manifest_row(),
                             community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))])
    same = BlackboxConfig(report=True, community_graph_id=GRAPH, context_graph_id=GRAPH)
    assert not read_curator_view(node, same).counted


# ------------------------------------------------------------------ what the community authority can do


def test_the_community_authority_lists_a_reporter_from_the_community_graph(community_trusted, community):
    alice, bob = Reporter("0xa"), Reporter("0xb")
    node = Graphs(community=[community.manifest_row(),
                             community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author)),
                             community.row(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _entry(bob.author), signers=1)])
    view = read_curator_view(node, CFG)
    assert set(view.counted) == {alice.author}            # bob's listing has one signature: no quorum
    assert view.manifest is None                          # the VERIFIED manifest stays what `manifest` means
    assert view.community is not None and view.community.manifest == community.manifest
    assert view.community.authority is Authority.COMMUNITY


def test_the_community_authority_confirms_rejects_and_pauses(community_trusted, community):
    node = Graphs(community=[community.manifest_row(),
                             community.row(Kind.CONFIRMATION, THREAT, CITED),
                             community.row(Kind.REJECTION, "dep:npm:left-pad@1.0.0", {"reason": "benign"}),
                             community.row(Kind.PAUSE, "curator", {"until": "2026-10-05"})])
    view = read_curator_view(node, CFG)
    assert view.verdict(THREAT) is Kind.CONFIRMATION
    assert view.rejected("dep:npm:left-pad@1.0.0")
    assert view.pause_active("2026-10-04") and not view.pause_active("2026-10-06")


def test_the_community_authority_cannot_revoke_whatever_its_keys_sign(community_trusted, community):
    """A revocation acts on the verified tier: refused from the community authority in either graph."""
    in_community = community.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"})
    in_verified = community.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, graph=VM_GRAPH)
    node = Graphs(verified=[in_verified], community=[community.manifest_row(), in_community])
    view = read_curator_view(node, CFG)
    assert view.revoked == frozenset() and view.verdict(THREAT) is None


# ------------------------------------------------------------------ between the two: the most restrictive word wins


def _both(verified, community, *, verified_rows=(), community_rows=()):
    return Graphs(verified=[verified.manifest_row(), *verified_rows],
                  community=[community.manifest_row(), *community_rows])


def test_a_community_confirmation_never_displaces_a_verified_revocation(both_trusted, verified, community):
    """KI-243: each authority counts in its own sequence — a higher community number wins nothing."""
    node = _both(verified, community,
                 verified_rows=[verified.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, sequence=1)],
                 community_rows=[community.row(Kind.CONFIRMATION, THREAT, CITED, sequence=99)])
    view = read_curator_view(node, CFG)
    assert view.verdict(THREAT) is Kind.REVOCATION and THREAT in view.revoked


def test_a_rejection_from_either_authority_beats_the_other_authoritys_confirmation(both_trusted, verified, community):
    other = "ioc:domain:other.example"
    node = _both(verified, community, community_rows=[
        verified.row(Kind.REJECTION, THREAT, {"reason": "benign"}, graph=GRAPH, sequence=1),
        community.row(Kind.CONFIRMATION, THREAT, CITED, sequence=7),
        verified.row(Kind.CONFIRMATION, other, {}, graph=GRAPH, sequence=7),
        community.row(Kind.REJECTION, other, {"reason": "benign"}, sequence=1)])
    view = read_curator_view(node, CFG)
    assert view.rejected(THREAT) and view.rejected(other)


def test_a_notice_does_not_cancel_the_other_authoritys_confirmation_but_a_live_deferral_does(both_trusted, verified, community):
    deferred, lapsed = "ioc:domain:deferred.example", "ioc:domain:lapsed.example"
    node = _both(verified, community, community_rows=[
        verified.row(Kind.IN_REVIEW, THREAT, {}, graph=GRAPH, signers=1),
        community.row(Kind.CONFIRMATION, THREAT, CITED),
        verified.row(Kind.DEFERRAL, deferred, {}, graph=GRAPH, signers=1),
        community.row(Kind.CONFIRMATION, deferred, CITED),
        verified.row(Kind.DEFERRAL, lapsed, {}, graph=GRAPH, signers=1),
        community.row(Kind.CONFIRMATION, lapsed, CITED)])
    view = read_curator_view(node, CFG)
    assert view.verdict(THREAT) is Kind.CONFIRMATION
    assert view.verdict(deferred) is Kind.DEFERRAL
    later = combine(cv.CuratorView(verdicts={lapsed: view.verdicts[deferred]}),
                    cv.CuratorView(verdicts={lapsed: view.community.verdicts[lapsed]}), today="2026-11-15")
    assert later.verdict(lapsed) is Kind.CONFIRMATION       # 44 days on, the deferral no longer holds it down


def test_a_delisting_by_either_authority_removes_the_reporter(both_trusted, verified, community):
    alice, bob, carol = Reporter("0xa"), Reporter("0xb"), Reporter("0xc")
    node = _both(verified, community,
                 verified_rows=[verified.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author, listed="no")),
                                verified.row(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _entry(bob.author)),
                                verified.row(Kind.COUNTED_AUTHORS, f"author:{carol.author}", _entry(carol.author))],
                 community_rows=[community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author)),
                                 community.row(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _entry(bob.author, listed="no"))])
    view = read_curator_view(node, CFG)
    assert set(view.counted) == {carol.author}
    assert view.delisted == {alice.author, bob.author}


def test_a_listing_and_a_delisting_with_the_same_number_resolve_to_delisted_in_either_order(community_trusted, community):
    """KI-245: the outcome must not depend on which row the node returns first."""
    alice = Reporter("0xa")
    listed = community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author), sequence=4)
    delisted = dict(community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author, listed="no"), sequence=4))
    for order in ([listed, delisted], [delisted, listed]):
        view = read_curator_view(Graphs(community=[community.manifest_row(), *order]), CFG)
        assert not view.counted and view.delisted == {alice.author}


def test_two_attestations_resolve_to_the_one_that_enforces_less(both_trusted, verified, community):
    tied = "ioc:domain:tied.example"
    node = _both(verified, community, community_rows=[
        verified.row(Kind.ATTESTATION, THREAT, {"stage": "held"}, graph=GRAPH),
        community.row(Kind.ATTESTATION, THREAT, {"stage": "corroborated"}, sequence=9),
        community.row(Kind.ATTESTATION, tied, {"stage": "corroborated"}, sequence=3),
        dict(community.row(Kind.ATTESTATION, tied, {"stage": "reported"}, sequence=3))])
    view = read_curator_view(node, CFG)
    assert view.attestation(THREAT).field("stage") == "held"           # across authorities
    assert view.community.attestation(tied).field("stage") == "reported"   # a tie inside one authority


def test_a_pause_from_either_authority_is_in_force(both_trusted, verified, community):
    node = _both(verified, community,
                 verified_rows=[verified.row(Kind.PAUSE, "curator", {"until": "2026-10-03"})],
                 community_rows=[community.row(Kind.PAUSE, "curator", {"until": "2026-10-06"})])
    view = read_curator_view(node, CFG)
    assert view.pause_until == "2026-10-06" and view.pause_active("2026-10-05")


def test_the_combined_view_keeps_the_verified_manifest_for_the_verified_tier(both_trusted, verified, community):
    view = read_curator_view(_both(verified, community), CFG)
    assert view.manifest == verified.manifest and view.authority is Authority.VERIFIED
    assert view.community.manifest == community.manifest


# ------------------------------------------------------------------ failure is not emptiness


def test_a_failed_community_page_freezes_the_view_instead_of_delisting_everyone(community_trusted, community):
    """KI-244: with trust hosted in the community graph, a failed page must not read as 'no statements'."""
    view = read_curator_view(Graphs(community=[community.manifest_row()], failing={GRAPH}), CFG)
    assert view.unavailable


def test_a_node_with_no_community_root_reads_exactly_as_before(monkeypatch, verified, community):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    alice = Reporter("0xa")
    node = Graphs(verified=[verified.manifest_row(),
                            verified.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))],
                  community=[community.manifest_row(),
                             community.row(Kind.COUNTED_AUTHORS, f"author:{Reporter('0xb').author}", _entry(Reporter("0xb").author))])
    view = read_curator_view(node, CFG)
    assert set(view.counted) == {alice.author} and view.community is None


# ------------------------------------------------------------------ end to end: the community tier finally fires


class Network(Graphs):
    """Graphs plus the community graph's reports, on a node that says it is subscribed and synced."""

    def __init__(self, reports=(), **kw):
        super().__init__(**kw)
        self.reports = list(reports)

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if cg_id == GRAPH and "g:ThreatReport" in sparql and cg_id not in self.failing:
            return list(self.reports)
        return super().query(sparql, cg_id, view=view, on_error=on_error, **kw)


def _tier(node):
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, node, CFG, None)
    return rs


def test_a_report_by_a_community_listed_reporter_flags_and_becomes_matchable(monkeypatch, community_trusted, community):
    """The point of the proposal: with a community-authority listing, a report
    stops being 'reported, monitor only' and can fire on another node — and a
    report by an unlisted reporter still cannot."""
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    alice, mallory = Reporter("0xa"), Reporter("0xb")
    trusted, untrusted = "ioc:ip:203.0.113.7", "ioc:ip:203.0.113.9"
    reports = [signed_row(trusted, alice), signed_row(untrusted, mallory)]
    listing = community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))

    without = _tier(Network(reports=reports, community=[community.manifest_row()]))
    assert without.community[trusted]["enforcement"] == "monitor" and trusted not in without.ioc

    rs = _tier(Network(reports=reports, community=[community.manifest_row(), listing]))
    assert (rs.community[trusted]["stage"], rs.community[trusted]["enforcement"], rs.community[trusted]["counted"]) == ("reported", "flag", "1")
    assert rs.community[untrusted]["enforcement"] == "monitor"
    assert trusted in rs.ioc and rs.ioc[trusted]["source"] == "community"
    assert untrusted not in rs.ioc


def test_a_community_rejection_ends_a_listed_reporters_threat(monkeypatch, community_trusted, community):
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    alice = Reporter("0xa")
    threat = "ioc:ip:203.0.113.7"
    rows = [community.manifest_row(),
            community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author)),
            community.row(Kind.REJECTION, threat, {"reason": "benign"})]
    rs = _tier(Network(reports=[signed_row(threat, alice)], community=rows))
    assert threat not in rs.ioc and threat not in rs.community    # rejected reports stop counting (terminal)
