"""Refine R7b — keys and reader policy: no single key raises enforcement, no
single absence freezes a reduction, reductions always get through, and every
operator keeps a local release valve.

* `blackbox rules unblock` demotes BLOCK → FLAG on this machine only; the
  audit decision says "flag (local override)"; `reblock` restores; there is
  no `rules block`.
* The break-glass key counts only on reductions; one key cannot attest or
  pause; a pause longer than 7 days is not a valid statement.
* After 7 days of curator silence the root alone may sign a revocation —
  and nothing else.
* A dated manifest takes effect 72 h later (pending) and goes STALE at 60 d:
  clock-forward keeps the malware rule blocking, freezes new raising
  statements, lets a revocation through, and shows STALE on status; the
  expiry alarm fires 30 days ahead.
* Fifty revocations in one read all apply (no velocity hold on reductions).
"""

from __future__ import annotations

import argparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _community_rows import GRAPH, NETWORK
from plugins.blackbox import overrides
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.detection import Finding
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import health, signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import compiler
from test_blackbox_curator_view import _curator_row

THREAT = "dep:npm:evil@1.0.0"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


@pytest.fixture
def keys():
    curators = [Ed25519PrivateKey.generate() for _ in range(3)]
    root = Ed25519PrivateKey.generate()
    return {"curators": curators, "root": root, "hex": [signing.public_key_hex(k) for k in curators]}


def _manifest(keys, **over):
    base = dict(environment=NETWORK, graph="0xabc/agent-blackbox-vm", chain="", root_epoch=1, version=1,
                curator_keys=tuple(sorted(keys["hex"])), threshold=2, promotion_author="0x" + "1" * 40,
                legacy_assets_hash=km.legacy_assets_hash([]))
    base.update(over)
    return km.KeyManifest(**base)


def _finding(identifier=THREAT, severity="critical"):
    return Finding(identifier=identifier, category="dependency", severity=severity, title="evil", confirmed=True,
                   source="public", kind="malware")


# ------------------------------------------------------------------ the local release valve


def test_unblock_demotes_block_to_flag_here_and_the_audit_says_so(monkeypatch):
    cfg = BlackboxConfig(mode="block", block_severity="critical")
    store = overrides.OverrideStore()
    assert hooks._blocking(cfg, [_finding()]) and hooks._decision(cfg, [_finding()], hooks._blocking(cfg, [_finding()])) == "block"
    override = store.unblock(THREAT, "false positive in our CI")
    assert override.day and store.is_unblocked(THREAT)
    assert hooks._blocking(cfg, [_finding()]) == []
    assert hooks._decision(cfg, [_finding()], []) == "flag (local override)"
    assert hooks._blocking(cfg, [_finding("dep:npm:other@1")]) != []                # only the named rule
    assert store.reblock(THREAT) and not store.reblock(THREAT)
    assert hooks._blocking(cfg, [_finding()]) != [] and hooks._decision(cfg, [_finding()], [_finding()]) == "block"
    assert hooks._decision(BlackboxConfig(mode="audit"), [_finding()], []) == "flag"   # audit mode: no override involved


def test_the_rules_cli_has_no_block_verb_and_lists_overrides(capsys):
    parser = argparse.ArgumentParser()
    overrides.add_rules_parser(parser.add_subparsers())
    with pytest.raises(SystemExit):
        parser.parse_args(["rules", "block", THREAT])
    args = parser.parse_args(["rules", "unblock", THREAT, "--reason", "known-good fork"])
    assert args.func(args) == 0 and "LOCAL OVERRIDE" in capsys.readouterr().out
    args = parser.parse_args(["rules", "list"])
    assert args.func(args) == 0 and "known-good fork" in capsys.readouterr().out
    assert parser.parse_args(["rules", "reblock", THREAT]).func(parser.parse_args(["rules", "reblock", THREAT])) == 0
    assert "No local overrides" in (parser.parse_args(["rules", "list"]).func(parser.parse_args(["rules", "list"])), capsys.readouterr().out)[1]


def test_a_garbage_override_file_overrides_nothing(tmp_path):
    (tmp_path / "overrides.json").write_text("{nope", encoding="utf-8")
    assert overrides.OverrideStore(tmp_path / "overrides.json").unblocked() == frozenset()


# ------------------------------------------------------------------ keys: 2-of-3, break-glass, pause, root-alone


def test_the_break_glass_key_counts_only_on_reductions(keys):
    manifest = _manifest(keys, break_glass_key=keys["hex"][2])
    glass = keys["curators"][2]
    rejection = cs.sign_statement(Kind.REJECTION, THREAT, sequence=1, fields={"reason": "benign"}, key=keys["curators"][0],
                                  manifest=manifest, graph=GRAPH)
    rejection = signing.cosign(rejection, glass)
    assert len(manifest.curator_signers(rejection, statement_type=Kind.REJECTION.value, graph=GRAPH)) == 2
    attestation = cs.sign_statement(Kind.ATTESTATION, THREAT, sequence=1, fields={"stage": "corroborated"},
                                    key=keys["curators"][0], manifest=manifest, graph=GRAPH)
    attestation = signing.cosign(attestation, glass)
    assert len(manifest.curator_signers(attestation, statement_type=Kind.ATTESTATION.value, graph=GRAPH)) == 1   # glass excluded
    with pytest.raises(km.KeyManifestError):
        _manifest(keys, break_glass_key="f" * 64)


def test_one_key_cannot_attest_or_pause_and_a_pause_lasts_at_most_seven_days(keys):
    manifest = _manifest(keys)
    one = keys["curators"][:1]
    for kind, fields in ((Kind.ATTESTATION, {"stage": "held"}), (Kind.PAUSE, {"until": "2026-10-05"})):
        row = _curator_row(kind, THREAT if kind is Kind.ATTESTATION else "curator", fields, one, manifest,
                           graph=manifest.graph if kind is Kind.PAUSE else GRAPH)
        assert cs.parse_statement(row, manifest, graph=manifest.graph if kind is Kind.PAUSE else GRAPH) is None
    with pytest.raises(ValueError):
        cs.sign_statement(Kind.PAUSE, "curator", sequence=1, fields={"until": "2026-12-01"}, key=one[0], manifest=manifest,
                          graph=manifest.graph, day=__import__("datetime").date(2026, 10, 2))


def test_after_seven_silent_days_the_root_alone_may_revoke_and_nothing_else(keys):
    manifest = _manifest(keys)
    root_hex = signing.public_key_hex(keys["root"])
    revocation = cs.sign_statement(Kind.REVOCATION, THREAT, sequence=1, fields={"reason": "false-positive"},
                                   key=keys["root"], manifest=manifest, graph=manifest.graph)
    row = _rows_of(revocation)
    assert cs.parse_statement(row, manifest, graph=manifest.graph) is None                             # no curator quorum
    assert cs.parse_statement(row, manifest, graph=manifest.graph, root_keys={root_hex}, curators_silent=False) is None
    assert cs.parse_statement(row, manifest, graph=manifest.graph, root_keys={root_hex}, curators_silent=True) is not None
    promotion_like = cs.sign_statement(Kind.CONFIRMATION, THREAT, sequence=1, fields={}, key=keys["root"], manifest=manifest, graph=GRAPH)
    assert cs.parse_statement(_rows_of(promotion_like), manifest, graph=GRAPH, root_keys={root_hex}, curators_silent=True) is None
    # the view computes the silence from heartbeats: a fresh heartbeat keeps the root out
    beat = _curator_row(Kind.HEARTBEAT, "curator", {"key": keys["hex"][0]}, keys["curators"][:1], manifest, graph=GRAPH, sequence=9)
    view = cv.build_view(manifest, [row], [beat], verified_graph=manifest.graph, community_graph=GRAPH, today="2026-10-02",
                         root_keys={root_hex})
    assert THREAT not in view.revoked
    silent = cv.build_view(manifest, [row], [], verified_graph=manifest.graph, community_graph=GRAPH, today="2026-10-02",
                           root_keys={root_hex})
    assert THREAT in silent.revoked


def _rows_of(envelope):
    quads = cs.statement_quads(envelope)
    import json
    row = {"r": quads[0]["subject"]}
    for quad in quads:
        if quad["object"].startswith('"'):
            row[quad["predicate"].rsplit("/", 1)[-1]] = json.loads(quad["object"])
    return row


# ------------------------------------------------------------------ the manifest clock: time-lock, stale, expiry


def test_the_manifest_clock_pending_valid_stale(keys):
    dated = _manifest(keys, issued_day="2026-10-01")
    assert km.manifest_clock(dated, "2026-10-02") == ("pending", "2026-10-04")
    assert km.manifest_clock(dated, "2026-10-04") == ("", "2026-11-30")
    assert km.manifest_clock(dated, "2026-12-01") == ("stale", "2026-11-30")
    assert km.manifest_clock(_manifest(keys), "2030-01-01") == ("", "")                # undated: no clock
    assert "issuedDay" not in _manifest(keys).to_payload() and dated.to_payload()["issuedDay"] == "2026-10-01"
    with pytest.raises(km.KeyManifestError):
        _manifest(keys, issued_day="yesterday")


def test_clock_forward_past_expiry_keeps_blocking_freezes_raising_and_lets_a_revocation_through(keys):
    manifest = _manifest(keys, issued_day="2026-08-01")                                # stale after 2026-09-30
    two = keys["curators"][:2]
    late_listing = _curator_row(Kind.COUNTED_AUTHORS, "author:" + "a" * 64,
                                {"listed": "yes", "class": "established", "org": "", "expires": "2027-01-01", "address": "0x" + "b" * 40},
                                two, manifest, graph=manifest.graph, sequence=3)
    late_revocation = _curator_row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, two, manifest, graph=manifest.graph, sequence=4)
    view = cv.build_view(manifest, [late_listing, late_revocation], [], verified_graph=manifest.graph, community_graph=GRAPH,
                         today="2026-12-01")
    assert view.manifest_state == "stale" and view.manifest_state_day == "2026-09-30"
    assert "a" * 64 not in view.counted                                                   # the raising statement is frozen out
    assert THREAT in view.revoked                                                         # the reduction applies
    # a verified malware rule in the compiled ruleset is untouched by the freeze: it still blocks
    rs = compiler.Ruleset(synced_at=1.0)
    rs.dependency["npm:evil@1.0.0"] = {"identifier": THREAT, "severity": "critical", "source": "public", "kind": "malware", "confirmed": True}
    assert hooks._blocking(BlackboxConfig(mode="block", block_severity="critical"), [_finding()]) != []
    assert rs.dependency["npm:evil@1.0.0"]["kind"] == "malware"
    inputs = health.HealthInputs(node_reachable=True, ruleset_age_s=1.0, sync_interval_s=300.0, rule_count=1, community_configured=True,
                                 curator_trusted=True, today="2026-12-01", manifest_state="stale", manifest_state_day="2026-09-30")
    stale = [i for i in health.operator_health(inputs) if "STALE" in i.message]
    assert len(stale) == 1 and stale[0].klass is health.HealthClass.ACTION


def test_a_pending_manifest_and_an_expiring_one_are_info_alarms(keys):
    pending = health.HealthInputs(node_reachable=True, ruleset_age_s=1.0, sync_interval_s=300.0, rule_count=1, community_configured=True,
                                  curator_trusted=True, today="2026-10-02", manifest_state="pending", manifest_state_day="2026-10-04")
    assert [i.klass for i in health.operator_health(pending) if "takes effect" in i.message] == [health.HealthClass.INFO]
    soon = health.HealthInputs(node_reachable=True, ruleset_age_s=1.0, sync_interval_s=300.0, rule_count=1, community_configured=True,
                               curator_trusted=True, today="2026-10-02", manifest_expires_day="2026-10-20")
    assert [i.klass for i in health.operator_health(soon) if "expires on 2026-10-20" in i.message] == [health.HealthClass.INFO]
    far = health.HealthInputs(node_reachable=True, ruleset_age_s=1.0, sync_interval_s=300.0, rule_count=1, community_configured=True,
                              curator_trusted=True, today="2026-10-02", manifest_expires_day="2026-12-20")
    assert not [i for i in health.operator_health(far) if "expires on" in i.message]


def test_fifty_revocations_in_one_read_all_apply(keys):
    manifest = _manifest(keys)
    two = keys["curators"][:2]
    rows = [_curator_row(Kind.REVOCATION, f"dep:npm:cleanup-{i}@1", {"reason": "false-positive"}, two, manifest,
                         graph=manifest.graph, sequence=i + 1) for i in range(50)]
    view = cv.build_view(manifest, rows, [], verified_graph=manifest.graph, community_graph=GRAPH, today="2026-10-02")
    assert len(view.revoked) == 50                                                       # no velocity hold on reductions
