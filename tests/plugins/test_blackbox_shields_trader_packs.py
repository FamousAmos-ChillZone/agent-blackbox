"""Trader Shield's wallets and browser roots as data (shields/trader/wallets/, browsers.json).

The two "coming soon" lists are pinned first, against the code they replace, so moving the
wallets into packs cannot quietly change what Settings and the page promise (D-12).
"""

import json
import re
from pathlib import Path

from _blackbox_loader import load_blackbox


shields = load_blackbox("shields")

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
