"""A Hermes plugin-catalog install brings the plugin only — no DKG node.

Proven on a fresh Hermes home (2026-10-14): the built-in rules protect, but
`blackbox status` called the machine UNPROTECTED and told the operator to run
`blackbox sync --wait`, and sync answered that "the DKG node is still recovering
the graph" — there was no node. With no node for Blackbox (none answers and its
DKG command is not installed), the alarm, the status line and sync now say the
node is not installed and how to install it.
"""

from __future__ import annotations

import argparse

from _blackbox_loader import load_blackbox

health = load_blackbox("kernel.health")
config_mod = load_blackbox("kernel.config")
sync_pkg = load_blackbox("sync")


def _cfg(tmp_path, *, with_dkg_command: bool):
    command = tmp_path / "dkg"
    if with_dkg_command:
        command.write_text("#!/bin/sh\n", encoding="utf-8")
    return config_mod.BlackboxConfig(dkg_bin=str(command))


def _inputs(**overrides):
    base = {"node_reachable": False, "ruleset_age_s": None, "sync_interval_s": 3600.0, "rule_count": 0}
    return health.HealthInputs(**{**base, **overrides})


def test_no_node_and_no_dkg_command_is_not_installed(tmp_path):
    assert health.node_installed(_cfg(tmp_path, with_dkg_command=False), node_reachable=False) is False


def test_an_installed_dkg_command_counts_even_while_the_node_is_down(tmp_path):
    assert health.node_installed(_cfg(tmp_path, with_dkg_command=True), node_reachable=False) is True


def test_a_node_that_answers_counts_without_blackboxs_own_command(tmp_path):
    """An operator who runs their own DKG node elsewhere never sees the install alarm."""
    assert health.node_installed(_cfg(tmp_path, with_dkg_command=False), node_reachable=True) is True


def test_without_a_node_the_one_alarm_says_how_to_install_it():
    items = [item for item in health.operator_health(_inputs(node_installed=False)) if item.audience == "operator"]
    node_items = [item for item in items if "DKG node" in item.message or "ruleset" in item.message]

    assert [item.message for item in node_items] == [
        "Blackbox's DKG node is not installed: the verified threat graph is not loaded"]
    assert node_items[0].what_to_do == health.NODE_INSTALL_HINT
    assert not any("blackbox sync" in item.what_to_do for item in items)


def test_with_a_node_an_empty_ruleset_is_still_unprotected():
    messages = [item.message for item in health.operator_health(_inputs(node_installed=True, node_reachable=True))]

    assert "UNPROTECTED: the threat ruleset is empty" in messages


def test_gather_marks_a_catalog_only_machine(tmp_path):
    class EmptyRuleset:
        synced_at = 0
        kill_list = {}

        def counts(self):
            return {}

    inputs = health.gather(_cfg(tmp_path, with_dkg_command=False), EmptyRuleset(), False, None, {}, 0.0)

    assert inputs.node_installed is False


def test_sync_without_a_node_says_how_to_install_it_and_does_not_wait(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sync_pkg, "load_blackbox_config", lambda: _cfg(tmp_path, with_dkg_command=False))
    monkeypatch.setattr(sync_pkg.DkgClient, "reachable", lambda self: False)
    monkeypatch.setattr(sync_pkg, "_sync_with_node", lambda args: (_ for _ in ()).throw(AssertionError("no node to sync")))

    code = sync_pkg.cmd_sync(argparse.Namespace(wait=True, require_rules=False, timeout=60))

    assert code == 2
    out = capsys.readouterr().out
    assert "DKG node is not installed" in out and "Blackbox installer" in out


def test_sync_with_a_node_runs_the_sync(tmp_path, monkeypatch):
    monkeypatch.setattr(sync_pkg, "load_blackbox_config", lambda: _cfg(tmp_path, with_dkg_command=True))
    monkeypatch.setattr(sync_pkg.DkgClient, "reachable", lambda self: False)
    monkeypatch.setattr(sync_pkg, "_sync_with_node", lambda args: 0)

    assert sync_pkg.cmd_sync(argparse.Namespace(wait=True)) == 0
