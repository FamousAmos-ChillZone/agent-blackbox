"""App wallets: Exodus, Electrum and the Solana CLI keep their keys in folders of their own
(detection/app_wallets.py).

The layouts below are copied from the real software installed on bench bb-trader-1
(2026-10-13): Exodus 26.10.7 (.deb) wrote ``~/.config/Exodus/exodus.wallet/{seed.seco,
passphrase.json,storage.seco}``; Electrum 4.8.2 (AppImage) wrote
``~/.electrum/wallets/default_wallet`` and ``~/.electrum/testnet/wallets/default_wallet``;
the Solana CLI 4.3.0 wrote ``~/.config/solana/id.json`` and a ``cli/config.yml`` naming it.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import app_wallets, wallet_files
from plugins.blackbox.detection.wallet_files import detect_wallet_files
from plugins.blackbox.kernel.crypto_secrets import wallet_mode


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A Linux home with the three apps' real layouts."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    exodus = tmp_path / ".config" / "Exodus" / "exodus.wallet"
    electrum = tmp_path / ".electrum" / "wallets"
    electrum_testnet = tmp_path / ".electrum" / "testnet" / "wallets"
    solana = tmp_path / ".config" / "solana"
    for folder in (exodus, electrum, electrum_testnet, solana / "cli"):
        folder.mkdir(parents=True)
    for name in ("seed.seco", "passphrase.json", "storage.seco"):
        (exodus / name).write_text("x", encoding="utf-8")
    (electrum / "default_wallet").write_text("{}", encoding="utf-8")
    (electrum_testnet / "default_wallet").write_text("{}", encoding="utf-8")
    (solana / "id.json").write_text("[1,2,3]", encoding="utf-8")
    (solana / "cli" / "config.yml").write_text(
        f"---\njson_rpc_url: https://api.devnet.solana.com\nkeypair_path: {solana / 'id.json'}\ncommitment: confirmed\n",
        encoding="utf-8")
    app_wallets.SOLANA_KEY_FILE.reset()
    wallet_files.EXISTING_STORES.reset()
    yield tmp_path
    app_wallets.SOLANA_KEY_FILE.reset()
    wallet_files.EXISTING_STORES.reset()


def _wallets(tool, args):
    return sorted(finding.fields["wallet"] for finding in detect_wallet_files(tool, args))


@pytest.mark.parametrize("tool, args, wallet", [
    ("read_file", {"path": "~/.config/Exodus/exodus.wallet/passphrase.json"}, "exodus"),
    ("terminal", {"command": "zip -r backups/e.zip ~/.config/Exodus/exodus.wallet"}, "exodus"),
    ("terminal", {"command": "cat ~/.electrum/wallets/default_wallet"}, "electrum"),
    ("terminal", {"command": "cp ~/.electrum/testnet/wallets/default_wallet out/"}, "electrum"),
    ("terminal", {"command": "cat ~/.config/solana/id.json"}, "solana-cli"),
    ("read_file", {"path": "$HOME/.config/solana/id.json"}, "solana-cli"),
])
def test_reading_an_app_wallet_is_found(machine, tool, args, wallet):
    assert _wallets(tool, args) == [wallet]


def test_archiving_a_folder_that_holds_app_wallets_names_each(machine):
    assert _wallets("terminal", {"command": "tar czf conf.tgz ~/.config"}) == ["exodus", "solana-cli"]
    assert _wallets("terminal", {"command": "tar czf home.tgz ~"}) == ["electrum", "exodus", "solana-cli"]


def test_a_key_file_the_solana_config_names_elsewhere_is_protected(machine):
    elsewhere = machine / "keys" / "trading.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text("[1]", encoding="utf-8")
    config = machine / ".config" / "solana" / "cli" / "config.yml"
    config.write_text(f"keypair_path: '{elsewhere}'\n", encoding="utf-8")
    app_wallets.SOLANA_KEY_FILE.reset()
    assert _wallets("terminal", {"command": f"cat {elsewhere}"}) == ["solana-cli"]


@pytest.mark.parametrize("command", [
    "solana-keygen pubkey ~/.config/solana/id.json",     # prints the PUBLIC key; the CLI reads the file itself
    "solana balance",
    "cat ~/.config/solana/cli/config.yml",               # settings, not a key
    "cat ~/.electrum/config",
    "ls ~/.config/Exodus",
    "cat ~/.config/Exodus/Preferences",                  # app settings, outside exodus.wallet
])
def test_ordinary_use_of_the_apps_is_left_alone(machine, command):
    assert _wallets("terminal", {"command": command}) == []


def test_found_wallets_lists_app_wallets_by_kind(machine):
    found = {(entry["wallet"], entry["id"], entry["browser"]) for entry in wallet_files.found_wallets()}
    assert {("Exodus", "exodus", "Desktop app"), ("Electrum", "electrum", "Desktop app"),
            ("Solana CLI", "solana-cli", "Command line")} <= found


def test_app_wallets_follow_the_wallet_ticks(machine):
    only_exodus = wallet_mode.WalletProtection(enabled=True, wallets=("exodus",))
    findings = detect_wallet_files("terminal", {"command": "tar czf home.tgz ~"})
    kept = [f.fields["wallet"] for f in findings if only_exodus.allows_finding({"identifier": f.identifier, "fields": f.fields})]
    assert kept == ["exodus"]


def test_every_app_wallet_can_be_ticked():
    for wallet in app_wallets.APP_WALLETS:
        assert wallet_files.wallet_id(wallet.name) in wallet_mode.SUPPORTED_WALLETS


def test_a_windows_command_naming_the_folder_by_its_variable_is_found(machine, monkeypatch):
    # PowerShell/cmd write %APPDATA%\\Exodus\\…; where APPDATA is unset the name stays
    # literal on both sides and still matches.
    monkeypatch.delenv("APPDATA", raising=False)
    assert _wallets("terminal", {"command": r"copy %APPDATA%\Exodus\exodus.wallet\seed.seco C:\out"}) == ["exodus"]
