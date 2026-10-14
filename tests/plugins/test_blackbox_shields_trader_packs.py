"""Trader Shield's wallets and browser roots as data (shields/trader/wallets/, browsers.json).

The two "coming soon" lists are pinned first, against the code they replace, so moving the
wallets into packs cannot quietly change what Settings and the page promise (D-12). Then
the data is held to today's code (code -> data, §06 step 3a): the eleven packs load, and
the ids, names, extension ids, places and browser globs they state equal the Python
tables in detection/wallet_files.py and detection/app_wallets.py under Linux, macOS and
Windows layouts with mixed-case input. A supported pack must have earned it: a blocked
``vault`` row in the attack table names it.
"""

import json
import re
from pathlib import Path

import pytest
from _blackbox_loader import load_blackbox


shields = load_blackbox("shields")
packs_loader = load_blackbox("shields.packs")
trader_mode = load_blackbox("shields.trader.mode")
wallet_files = load_blackbox("detection.wallet_files")
app_wallets = load_blackbox("detection.app_wallets")

TRADER = shields.get("trader")
PACKS = packs_loader.load_packs(TRADER)
ROOTS, ROOT_HEALTH = packs_loader.load_browser_roots(TRADER)
SUPPORTED = {pack.id: pack for pack in PACKS if pack.status == "supported"}

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"
#: The page's "Coming soon" chips (S6b re-points this to shields/trader/page/content.json).
PAGE = PLUGIN / "dashboard" / "static" / "trader-shield.html"


def test_settings_coming_soon_is_unchanged():
    fields = shields.settings_view()["trader"]["fields"]
    wallets = next(field for field in fields if field["kind"] == "multi-pick")
    planned = [option["name"] for option in wallets["options"] if option["status"] == "planned"]
    assert planned == ["Rabby", "Coinbase Wallet", "Trust Wallet", "OKX Wallet", "Keplr", "Solflare"]


def test_page_coming_next_is_unchanged():
    match = re.search(r"^\s*coming:\s*(\[.*?\]),\s*$", PAGE.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, "SHIELD.coming not found in trader-shield.html"
    assert json.loads(match.group(1)) == ["Rabby", "Coinbase Wallet", "Solflare", "Bitcoin Core",
                                          "More exchanges", "Safari wallets"]


# ------------------------------------------------------------------ what loads


def test_registry_loads_five_supported_six_planned_none_unavailable():
    by_status = {status: [pack.id for pack in PACKS if pack.status == status]
                 for status in ("supported", "planned", "unavailable")}
    assert by_status == {
        "supported": ["metamask", "phantom", "exodus", "electrum", "solana-cli"],
        "planned": ["rabby", "coinbase-wallet", "trust-wallet", "okx-wallet", "keplr", "solflare"],
        "unavailable": [],
    }
    assert [pack.order for pack in PACKS if pack.status == "planned"] == [110, 120, 130, 140, 150, 160]


@pytest.mark.parametrize("pack_id", ["solana-cli", "coinbase-wallet", "trust-wallet", "okx-wallet"])
def test_hyphenated_ids_load_by_name(pack_id):
    pack = next(pack for pack in PACKS if pack.id == pack_id)
    assert pack.status in ("supported", "planned") and pack.folder.name == pack_id


def test_browsers_json_states_the_31_roots():
    entries = json.loads((TRADER.folder / "browsers.json").read_text(encoding="utf-8"))
    engines = [entry["engine"] for entry in entries]
    assert len(entries) == 31 and engines.count("firefox") == 7 and engines.count("chromium") == 24


def test_registry_loads_31_browser_roots_none_dropped():
    assert (len(ROOTS), ROOT_HEALTH) == (31, ())


def test_mode_and_settings_read_the_packs():
    assert trader_mode.supported_wallets() == {"metamask": "MetaMask", "phantom": "Phantom", "exodus": "Exodus",
                                               "electrum": "Electrum", "solana-cli": "Solana CLI"}
    assert trader_mode.wallets(trader_mode.build()) == tuple(SUPPORTED)
    wallets = next(field for field in TRADER.settings_fields() if field.kind == "multi-pick")
    assert [(option.id, option.status) for option in wallets.options] == [
        (pack.id, pack.status) for pack in PACKS if pack.status != "unavailable"]


def test_logos_ship_with_their_terms():
    for pack_id in ("metamask", "phantom"):
        pack = SUPPORTED[pack_id]
        assert pack.logo is not None and (pack.folder / pack.logo.file).is_file()
        assert (pack.folder / pack.logo.terms).read_text(encoding="utf-8").strip()
        assert shields.pack_logo("trader", pack_id) == pack.folder / "logo.svg"
    assert shields.pack_logo("trader", "exodus") is None


# ---------------------------------------------------- the same as today's code


def test_browser_extension_packs_equal_wallet_files_wallets():
    today = {wallet_files.wallet_id(store.name): (store.name, store.chromium_ids, store.firefox_ids)
             for store in wallet_files.WALLETS}
    data = {pack.id: (pack.name, tuple(pack.data["stores"].get("chromium", ())),
                      tuple(pack.data["stores"].get("firefox", ())))
            for pack in SUPPORTED.values() if pack.kind == "browser-extension"}
    assert data == today


def test_app_folder_packs_equal_app_wallets():
    today = {wallet_files.wallet_id(wallet.name): (wallet.name, wallet.places, wallet.kind)
             for wallet in app_wallets.APP_WALLETS}
    data = {pack.id: (pack.name, tuple(pack.data["places"]), pack.data["label"])
            for pack in SUPPORTED.values() if pack.kind in ("desktop-app", "cli-key-file")}
    assert data == today
    assert SUPPORTED["solana-cli"].data["pointer"] == {
        "config": app_wallets.SOLANA_CONFIG, "key": "keypair_path", "max_bytes": 65536}


#: Three machines, each with mixed-case folder names (matching ignores case on both sides).
LAYOUTS = {
    "linux": {"HOME": "/home/TraDer", "XDG_CONFIG_HOME": "/home/TraDer/.Config",
              "APPDATA": "/home/TraDer/AppData/Roaming", "LOCALAPPDATA": "/home/TraDer/AppData/Local"},
    "linux-default-xdg": {"HOME": "/home/TraDer", "XDG_CONFIG_HOME": None,
                          "APPDATA": None, "LOCALAPPDATA": None},
    "macos": {"HOME": "/Users/TraDer", "XDG_CONFIG_HOME": None, "APPDATA": None, "LOCALAPPDATA": None},
    "windows": {"HOME": "C:/Users/TraDer", "XDG_CONFIG_HOME": None,
                "APPDATA": "C:/Users/TraDer/AppData/Roaming", "LOCALAPPDATA": "C:/Users/TraDer/AppData/Local"},
}


@pytest.fixture(params=sorted(LAYOUTS))
def layout(request, monkeypatch):
    """The environment of one machine layout; today's code reads it from os.environ."""
    for name, value in LAYOUTS[request.param].items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.setattr(app_wallets.SOLANA_KEY_FILE, "get", lambda: None)   # no config on this machine
    return LAYOUTS[request.param]


def _expand(template: str, env: dict) -> str:
    """A path template under *env*, with the defaults today's code uses for unset variables."""
    home = env["HOME"]
    roots = {"~": home, "$XDG_CONFIG_HOME": env["XDG_CONFIG_HOME"] or f"{home}/.config",
             "%APPDATA%": env["APPDATA"] or f"{home}/AppData/Roaming",
             "%LOCALAPPDATA%": env["LOCALAPPDATA"] or f"{home}/AppData/Local"}
    root, _, rest = template.partition("/")
    return f"{roots[root]}/{rest}"


def _mixed_case(path: str) -> str:
    """*path* with every other letter's case flipped — how an agent might type it."""
    return "".join(char.swapcase() if index % 2 else char for index, char in enumerate(path))


def test_places_match_today_on_every_layout(layout):
    for pack in SUPPORTED.values():
        if pack.kind not in ("desktop-app", "cli-key-file"):
            continue
        for template in pack.data["places"]:
            if "%" in template and not layout["APPDATA"]:
                continue   # today an unset %VAR% stays literal and is never looked for
            inside = _expand(template, layout).replace("*", "Testnet") + ("" if template.endswith(".json") else "/x")
            assert app_wallets.app_wallet_at(wallet_files.normalize_path(_mixed_case(inside))) == pack.name, inside


def test_browser_roots_match_today_on_every_layout(layout):
    today = {root.replace("\\", "/").lower() for root in wallet_files._browser_roots()}
    entries = json.loads((TRADER.folder / "browsers.json").read_text(encoding="utf-8"))
    data = {_mixed_case(_expand(entry["path"], layout)).lower() for entry in entries}
    assert data == today


# ------------------------------------------------------------ supported is earned


def test_every_supported_pack_has_a_blocked_vault_row():
    table = json.loads((PLUGIN / "dashboard" / "static" / "trader-shield-attacks.json").read_text(encoding="utf-8"))
    earned = {target for row in table["attacks"] if row["group"] == "vault" and row["outcome"] == "blocked"
              for target in row["targets"]}
    assert set(SUPPORTED) <= earned, sorted(set(SUPPORTED) - earned)
