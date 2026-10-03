"""Community Curation C3 — the reader's daily cap on what the community curators can raise.

The community authority's keys sign routine statements on their own, so they are
online keys (KI-258). Every reader admits at most 100 new confirmations or
attestations and 20 new listings per day of its own clock from that authority;
the rest are HELD and admitted on the following days, oldest first. Reductions
(rejections, delistings, pauses) are never held. A node's first read is a
baseline and admits everything.
"""

from __future__ import annotations

import pytest
from _community_rows import GRAPH, Reporter
from test_blackbox_authority import CFG, TODAY, Side
from test_blackbox_trust_store import Store, _listing

from plugins.blackbox.community import read_curator_view
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust import raising_budget
from plugins.blackbox.community.trust.trust_store import statement_key
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

TOMORROW = "2026-10-03"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


@pytest.fixture
def community(monkeypatch):
    side = Side(GRAPH)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", side.root_hex)
    return side


def _threats(n):
    return [f"ioc:ip:10.1.{i // 250}.{i % 250}" for i in range(n)]


def _baselined(community):
    """A node whose first read (the baseline) has happened: it knows the manifest and nothing else."""
    assert read_curator_view(Store(community=[community.manifest_row()]), CFG).community.manifest is not None


# ------------------------------------------------------------------ through the reader


def test_a_burst_of_confirmations_is_admitted_at_the_daily_rate_and_none_is_dropped(monkeypatch, community):
    _baselined(community)
    threats = _threats(raising_budget.CONFIRMATIONS_PER_DAY + 1)
    rows = [community.row(Kind.CONFIRMATION, threat, {}, sequence=i + 1) for i, threat in enumerate(threats)]
    node = Store(community=[community.manifest_row(), *rows])
    view = read_curator_view(node, CFG, interest=threats)
    confirmed = [t for t in threats if view.verdict(t) is Kind.CONFIRMATION]
    assert len(confirmed) == raising_budget.CONFIRMATIONS_PER_DAY and view.community.held_raising == 1
    assert view.verdict(threats[-1]) is None                           # the newest (highest sequence) waits
    again = read_curator_view(node, CFG, interest=threats)
    assert again.community.held_raising == 1                           # the same day admits no more
    monkeypatch.setattr(cv, "_today", lambda: TOMORROW)
    tomorrow = read_curator_view(node, CFG, interest=threats)
    assert tomorrow.verdict(threats[-1]) is Kind.CONFIRMATION and tomorrow.community.held_raising == 0


def test_reductions_are_never_held_whatever_their_number(community):
    _baselined(community)
    threats = _threats(300)
    rows = [community.row(Kind.REJECTION, threat, {"reason": "benign"}) for threat in threats]
    view = read_curator_view(Store(community=[community.manifest_row(), *rows]), CFG, interest=threats)
    assert all(view.rejected(threat) for threat in threats) and view.community.held_raising == 0


def test_listings_are_capped_and_delistings_are_not(community):
    _baselined(community)
    reporters = [Reporter(f"0xr{i}") for i in range(raising_budget.LISTINGS_PER_DAY + 5)]
    gone = [Reporter(f"0xg{i}") for i in range(40)]
    rows = [_listing(community, r, sequence=1) for r in reporters] + [_listing(community, r, listed="no") for r in gone]
    view = read_curator_view(Store(community=[community.manifest_row(), *rows]), CFG,
                             interest=[f"author:{r.author}" for r in (*reporters, *gone)])
    assert len(view.counted) == raising_budget.LISTINGS_PER_DAY and view.community.held_raising == 5
    assert view.delisted == {r.author for r in gone}


def test_a_nodes_first_read_is_a_baseline_and_admits_everything(community):
    threats = _threats(raising_budget.CONFIRMATIONS_PER_DAY + 50)
    rows = [community.row(Kind.CONFIRMATION, threat, {}) for threat in threats]
    view = read_curator_view(Store(community=[community.manifest_row(), *rows]), CFG, interest=threats)
    assert all(view.verdict(threat) is Kind.CONFIRMATION for threat in threats) and view.community.held_raising == 0


def test_a_held_confirmation_does_not_hold_back_a_rejection_of_the_same_threat(community):
    _baselined(community)
    threats = _threats(raising_budget.CONFIRMATIONS_PER_DAY + 1)
    rows = [community.row(Kind.CONFIRMATION, threat, {}, sequence=1) for threat in threats]
    rows.append(community.row(Kind.REJECTION, threats[-1], {"reason": "benign"}, sequence=2))
    view = read_curator_view(Store(community=[community.manifest_row(), *rows]), CFG, interest=threats)
    assert view.rejected(threats[-1])


# ------------------------------------------------------------------ the pure function


def test_every_reader_drains_held_statements_in_the_same_order():
    side = Side(GRAPH)
    rows = [side.row(Kind.CONFIRMATION, threat, {}, sequence=i + 1) for i, threat in enumerate(_threats(105))]
    forward = raising_budget.admit(rows, {}, first_read=False, today=TODAY)
    backward = raising_budget.admit(list(reversed(rows)), {}, first_read=False, today=TODAY)
    assert forward.held == backward.held == {statement_key(row) for row in rows[100:]}
    drained = raising_budget.admit(rows, forward.admitted, first_read=False, today=TOMORROW)
    assert not drained.held and len(drained.admitted) == 105


def test_only_raising_statements_are_ever_bucketed():
    side = Side(GRAPH)
    alice = Reporter("0xa")
    assert raising_budget.bucket(side.row(Kind.CONFIRMATION, "ioc:ip:10.0.0.1", {}))[0] == "confirm"
    assert raising_budget.bucket(side.row(Kind.ATTESTATION, "ioc:ip:10.0.0.1", {"stage": "corroborated"}))[0] == "confirm"
    assert raising_budget.bucket(_listing(side, alice))[0] == "list"
    for row in (_listing(side, alice, listed="no"), side.row(Kind.REJECTION, "ioc:ip:10.0.0.1", {"reason": "benign"}),
                side.row(Kind.PAUSE, "curator", {"until": "2026-10-05"}), side.row(Kind.DEFERRAL, "ioc:ip:10.0.0.1", {}, signers=1),
                {"signedStatement": "not an envelope"}):
        assert raising_budget.bucket(row) is None
