"""Blackbox reads and writes config.yaml through the host's YAML library.

Hermes 0.21.7 removed PyYAML and reads YAML through its own ruamel-backed
``hermes_yaml``. Blackbox's helper imported ``yaml`` behind a fail-open guard, so on the
new host every config read came back empty and Blackbox silently ran on its defaults —
block mode and Trader Shield settings ignored. These tests run the real helper against
the real host library.
"""

from __future__ import annotations

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import yaml_files


def test_the_helper_has_a_yaml_library():
    assert yaml_files.yaml is not None


def test_a_config_written_by_the_helper_reads_back_the_same(tmp_path):
    path = tmp_path / "config.yaml"
    data = {"plugins": {"entries": {"blackbox": {"mode": "block", "wallet_protection": True,
                                                  "protected_wallets": ["metamask", "solana-cli"],
                                                  "protected_paths": ["~/.ssh/*", ".env"]}}}}
    yaml_files.dump_yaml(path, data)
    assert yaml_files.load_yaml(path) == data


def test_yaml_1_1_booleans_in_a_hand_written_config_still_read(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("plugins:\n  entries:\n    blackbox:\n      mode: block\n      report: no\n      discover: yes\n",
                    encoding="utf-8")
    entry = yaml_files.load_yaml(path)["plugins"]["entries"]["blackbox"]
    assert entry == {"mode": "block", "report": False, "discover": True}


def test_block_mode_in_config_yaml_reaches_blackbox(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    yaml_files.dump_yaml(home / "config.yaml", {"plugins": {"entries": {"blackbox": {"mode": "block"}}}})
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert config_mod.load_blackbox_config().block_enabled
