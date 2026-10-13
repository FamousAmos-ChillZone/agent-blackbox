"""The dashboard's wallet-protection panel (trader rules): what was found, how it is protected, what happened.

The panel must show the wallets that really exist on this machine (by folder name only),
say plainly whether Blackbox blocks or only watches, and list only wallet events.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.dashboard import protection
from plugins.blackbox.detection import wallet_files
from plugins.blackbox.kernel.config import BlackboxConfig

METAMASK_CHROME = wallet_files.WALLETS[0].chromium_ids[0]


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    wallet_files.EXISTING_STORES.reset()
    yield tmp_path
    wallet_files.EXISTING_STORES.reset()


def _vault(home, *parts):
    folder = home.joinpath(".config", "google-chrome", "Default", *parts)
    folder.mkdir(parents=True)
    (folder / "000003.log").write_text("placeholder", encoding="utf-8")


def test_a_metamask_vault_on_this_machine_is_listed_by_browser_profile_and_area(home):
    _vault(home, "Local Extension Settings", METAMASK_CHROME)
    _vault(home, "IndexedDB", f"chrome-extension_{METAMASK_CHROME}_0.indexeddb.leveldb")
    [found] = wallet_files.found_wallets()
    assert (found["wallet"], found["browser"], found["profile"]) == ("MetaMask", "Chrome", "default")   # paths are lower-cased
    assert sorted(found["areas"]) == ["backup copy", "vault"]


def test_a_machine_without_a_wallet_lists_none(home):
    assert wallet_files.found_wallets() == []


@pytest.mark.parametrize("mode, shown", [("block", "block"), ("audit", "audit")])
def test_the_panel_says_whether_it_blocks_or_only_watches(home, monkeypatch, mode, shown):
    monkeypatch.setattr(protection, "load_blackbox_config", lambda: BlackboxConfig(mode=mode))
    payload = protection.wallet_protection_payload()
    assert payload["mode"] == shown and payload["seed_checker"] is True and payload["terminal_reads"] == "blocked"


def test_only_wallet_events_are_listed_with_blocked_or_flagged(home, monkeypatch):
    monkeypatch.setattr(protection, "load_blackbox_config", lambda: BlackboxConfig(mode="block"))
    findings = home / "bb" / "findings.jsonl"
    findings.parent.mkdir(parents=True)
    rows = [
        {"ts": 1, "detail": {"decision": "block"},
         "finding": {"identifier": "fileaccess:terminal:crypto-wallet", "title": "MetaMask key store", "tool_name": "terminal"}},
        {"ts": 2, "detail": {}, "finding": {"identifier": "secret:wallet-private-key", "title": "Wallet private key"}},
        {"ts": 3, "detail": {}, "finding": {"identifier": "ioc:domain:evil.example", "title": "not a wallet event"}},
    ]
    findings.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    events = protection.wallet_protection_payload()["events"]
    assert sorted((e["identifier"], e["outcome"]) for e in events) == [
        ("fileaccess:terminal:crypto-wallet", "blocked"), ("secret:wallet-private-key", "flagged")]


# ------------------------------------------------------------ Web3 wallet protection is a mode


from plugins.blackbox.community.sighting import classify
from plugins.blackbox.kernel import settings
from plugins.blackbox.kernel.crypto_secrets import wallet_mode


def test_the_mode_is_off_by_default_and_governs_only_wallet_findings():
    mode = wallet_mode.from_entry({})
    assert mode.enabled is False and mode.wallets == tuple(wallet_mode.SUPPORTED_WALLETS)
    vault = {"identifier": "fileaccess:terminal:crypto-wallet", "fields": {"wallet": "metamask"}}
    assert not mode.allows_finding(vault) and not mode.allows_finding({"identifier": "secret:seed-phrase"})
    assert mode.allows_finding({"identifier": "dep:npm:evil@1.0.0"})   # not a wallet finding: untouched
    chosen = wallet_mode.from_entry({"wallet_protection": True, "protected_wallets": ["MetaMask", "not-a-wallet"]})
    assert chosen.wallets == ("metamask",) and chosen.allows_finding(vault)   # unsupported names are dropped


def test_engaging_protects_every_supported_wallet_unless_wallets_were_already_chosen():
    """Engage sends only the switch: a first engage protects MetaMask and Phantom; an
    earlier choice (e.g. MetaMask only) is kept, so engaging never widens it silently."""
    updates, errors = wallet_mode.validate({"wallet_protection": True})
    assert updates == {"wallet_protection": True} and errors == []
    assert wallet_mode.from_entry(updates).wallets == tuple(wallet_mode.SUPPORTED_WALLETS)
    earlier = {"wallet_protection": True, "protected_wallets": ["metamask"]}
    assert wallet_mode.from_entry(earlier).wallets == ("metamask",)


def test_settings_accept_the_mode_and_refuse_an_unknown_wallet():
    assert wallet_mode.validate({"wallet_protection": True, "protected_wallets": ["metamask"]}) == (
        {"wallet_protection": True, "protected_wallets": ["metamask"]}, [])
    _, errors = wallet_mode.validate({"protected_wallets": ["not-a-wallet"]})
    assert errors and wallet_mode.validate({"wallet_protection": "yes"})[1]
    assert "wallet_protection" in settings.read_settings()


def test_the_panel_is_off_until_the_mode_is_on(home, monkeypatch):
    monkeypatch.setattr(protection, "load_blackbox_config", lambda: BlackboxConfig(mode="block"))
    monkeypatch.setattr(wallet_mode, "current", lambda: wallet_mode.WalletProtection(enabled=False))
    assert protection.wallet_protection_payload()["enabled"] is False
    monkeypatch.setattr(wallet_mode, "current", lambda: wallet_mode.WalletProtection(enabled=True))
    _vault(home, "Local Extension Settings", METAMASK_CHROME)
    wallet_files.EXISTING_STORES.reset()   # the folder scan is cached for minutes
    payload = protection.wallet_protection_payload()
    assert payload["enabled"] is True and payload["wallets"][0]["protected"] is True


@pytest.mark.parametrize("finding, goal", [
    ({"category": "fileaccess", "fields": {"file_category": "crypto-wallet"}}, "wallet-drain"),
    ({"category": "secret", "identifier": "secret:seed-phrase"}, "wallet-drain"),
    ({"category": "secret", "identifier": "secret:wallet-private-key"}, "wallet-drain"),
])
def test_a_wallet_event_names_its_goal_instead_of_unknown(finding, goal):
    classified = classify(finding)
    assert (classified.threat_goal, classified.resource_at_risk) == (goal, "wallet-keys")


def test_the_trader_shield_page_is_served_with_its_get_started_button():
    """The dashboard's "Learn more" opens /trader-shield; its Engage button uses the same settings keys."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    protection.register_protection_routes(app)
    page = TestClient(app).get("/trader-shield")
    assert page.status_code == 200 and "Engage Trader Shield" in page.text
    assert "var body = { wallet_protection: true };" in page.text and "protected_wallets" not in page.text
    assert "https://" not in page.text.split("<script>")[0].split("</style>")[0]   # no external fonts or styles: works offline


def test_the_dashboard_announces_trader_shield_only_while_it_is_off():
    html = (protection.TRADER_SHIELD_PAGE.parent / "index.html").read_text(encoding="utf-8")
    assert 'id="ts-banner" hidden' in html and 'href="/trader-shield"' in html
    assert "banner.hidden = !!(d && d.enabled) || !tsBannerDue()" in html and "TS_BANNER_DAYS = 7" in html


def test_the_panel_opens_settings_at_the_trader_shield_section():
    html = (protection.TRADER_SHIELD_PAGE.parent / "index.html").read_text(encoding="utf-8")
    assert 'id="wp-edit"' in html and 'id="set-trader-shield"' in html
    wiring = html[html.index('var wpEdit = $("wp-edit")'):]
    assert wiring.index("openSettings()") < wiring.index('$("set-trader-shield")')


def test_every_panel_event_opens_the_full_local_report_window():
    html = (protection.TRADER_SHIELD_PAGE.parent / "index.html").read_text(encoding="utf-8")
    assert 'class="wp-ev" data-wev-open="' in html and 'data-wev-open="">View all' in html
    assert 'id="wallet-events" hidden' in html and ".wev-overlay[hidden] { display: none; }" in html
    assert 'getJSON("/api/wallet-protection/events")' in html
    assert "Private to this machine." in html


def test_protected_files_lists_what_trader_shield_guards_read_only():
    html = (protection.TRADER_SHIELD_PAGE.parent / "index.html").read_text(encoding="utf-8")
    rows = html[html.index("function shieldPathRows()"):html.index("function renderWalletUI()")]
    assert "if (!setState || !setState.wallet_protection) return" in rows   # only while engaged
    assert "path-del" not in rows   # read-only: no remove button
    assert "host.innerHTML = own + shieldPathRows();" in html


def test_a_new_wallet_finding_refreshes_trader_shield_on_the_main_poll():
    """Real time: the 4 s findings poll, not the panel's 30 s timer, brings wallet events in."""
    html = (protection.TRADER_SHIELD_PAGE.parent / "index.html").read_text(encoding="utf-8")
    notify = html[html.index("function processThreatNotifications(data)"):html.index("function setThreatAlertsEnabled(")]
    assert notify.index("onWalletEvent()") < notify.index("if (!threatAlertsEnabled || !fresh.length) return;")
    assert "var POLL_MS = 4000;" in html


def test_wallet_threats_show_their_wallet_logo_everywhere_they_appear():
    """At a glance: the panel, the events window, the threats table, the alert and the finding
    detail all draw the wallet's logo for a wallet event."""
    html = (protection.TRADER_SHIELD_PAGE.parent / "index.html").read_text(encoding="utf-8")
    assert "'<td>' + walletLogoHTML(f) + typeTag(" in html                      # threats table
    assert "icon.innerHTML = walletLogoHTML(newest, \"big\") ||" in html          # threat alert
    assert '$("tm-ico").innerHTML = walletLogoHTML(f, "big") ||' in html          # finding detail
    assert html.count("walletLogoHTML(e") >= 3                                   # panel row, window list + detail
    assert "walletLogoByName(g.wallet)" in html and "walletGroups(d.wallets)" in html   # found: one row per wallet


def test_the_panel_calls_a_store_protected_exactly_when_the_gate_would_count_it(home, monkeypatch):
    """The panel used its own copy of the rule and labelled a Firefox store "not protected"
    while the gate (FIX-0100) protected it. Both now read WalletProtection.protects()."""
    stores = [(wallet_files.normalize_path("~/.mozilla/firefox/a.default/storage/default/moz-extension+++x^usercontextid=4294967295"),
               wallet_files.FIREFOX_EXTENSION),
              (wallet_files.normalize_path(f"~/.config/google-chrome/Default/local extension settings/{METAMASK_CHROME}"), "MetaMask")]
    monkeypatch.setattr(wallet_files.EXISTING_STORES, "get", lambda: stores)
    for chosen, expected in ((["metamask"], {"a Firefox extension": True, "MetaMask": True}),
                             ([], {"a Firefox extension": False, "MetaMask": False})):
        monkeypatch.setattr(protection.crypto_secrets.wallet_mode, "current",
                            lambda chosen=chosen: wallet_mode.WalletProtection(enabled=True, wallets=tuple(chosen)))
        shown = {w["wallet"]: w["protected"] for w in protection.wallet_protection_payload()["wallets"]}
        assert shown == expected


def test_a_firefox_profile_name_is_shown_as_it_is_not_defanged(home, monkeypatch):
    """Seen on a macOS lab run: the panel showed "lab[.]default" — local folder names went
    through the community-text sanitizer, which defangs anything shaped like a domain."""
    store = wallet_files.normalize_path(
        "~/Library/Application Support/Firefox/Profiles/ab12.default-release/storage/default/moz-extension+++x^usercontextid=4294967295")
    monkeypatch.setattr(wallet_files.EXISTING_STORES, "get", lambda: [(store, wallet_files.FIREFOX_EXTENSION)])
    [shown] = protection.wallet_protection_payload()["wallets"]
    assert shown["profile"] == "ab12.default-release" and "[.]" not in str(shown)


def test_the_panel_states_todays_rules(home, monkeypatch):
    # Terminal reads follow the protected-path rule (FIX-0103); the exchange list and the
    # own-address COUNT are shown — never the addresses themselves.
    own = wallet_mode.WalletProtection(enabled=True, addresses=("0x" + "ab" * 20,))
    monkeypatch.setattr(wallet_mode, "current", lambda: own)
    payload = protection.wallet_protection_payload()
    assert payload["terminal_reads"] == "blocked" and payload["own_addresses"] == 1
    assert "Binance" in payload["exchanges"] and "ab" * 20 not in str(payload)


def test_keychain_and_approval_findings_are_trader_shield_events():
    for identifier in ("fileaccess:terminal:macos-keychain", "secret:token-approval-drainer", "secret:exchange-api-key"):
        assert wallet_mode.belongs_to_mode(identifier), identifier
    assert not wallet_mode.belongs_to_mode("fileaccess:terminal:user-protected")


def test_each_protection_state_has_its_own_mark():
    # Green check = secured (blocked), amber = watched only (audit mode), grey = not protected,
    # red = needs attention; the panel carries a legend for them, and green is its own token.
    page = (protection.STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert 'var on = block ? ["✓", "ok"] : ["~", "watch"];' in page
    assert "--secure:" in page and ".wp-ic.ok { color: var(--secure)" in page
    assert all(word in page for word in ("secured — blocked", "watched — flagged only", "not protected", "needs attention"))


def test_the_event_list_scrolls_inside_its_column():
    page = (protection.STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert ".wp-evlist { max-height:" in page and "overflow-y: auto" in page.split(".wp-evlist {", 1)[1].split("}", 1)[0]
    assert '<div class="wp-evlist" tabindex="0"' in page
