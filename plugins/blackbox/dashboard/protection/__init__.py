"""The dashboard's wallet-protection panel: what Blackbox found to protect, and how (trader rules).

``GET /api/wallet-protection`` answers, for this machine:

* ``mode`` — ``block`` (wallet threats are stopped) or ``audit`` (recorded only),
  and ``block_severity`` (what severity blocks);
* ``wallets`` — the browser wallets whose key stores exist here
  (:func:`..detection.found_wallets`: folder names only, nothing inside is read);
* ``seed_checker`` — whether seed-phrase detection is on (the pinned BIP-39 list loaded);
* ``protected_paths`` — the operator's protected file patterns, and ``terminal_reads``
  — whether reads of those through the terminal are blocked yet (not yet: KI-363);
* ``events`` — the latest wallet-related findings (vault access, seed phrases,
  labelled private keys), each blocked or flagged, newest first.

``GET /api/wallet-protection/events`` is the full local report behind the panel's
"Wallet events" window (:mod:`.events`: every event with its session timeline).

Usage::

    register_protection_routes(app)   # from dashboard.server.create_app
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from ... import audit, detection
from ...kernel import crypto_secrets
from ...kernel.config import load_blackbox_config
from ..safe_payloads import safe_identifier, safe_text
from .events import is_wallet_identifier, local_text, wallet_event_report

MAX_EVENTS = 20


def _events() -> List[Dict[str, Any]]:
    """The latest wallet findings, newest first: when, what, which tool, blocked or flagged."""
    out: List[Dict[str, Any]] = []
    for row in audit.read_findings(limit=500):   # flattened rows, newest first
        identifier = str(row.get("identifier") or "")
        if not is_wallet_identifier(identifier):
            continue
        out.append({"ts": row.get("ts"), "identifier": safe_identifier(identifier),
                    "title": safe_text(row.get("title"), 160), "severity": safe_text(row.get("severity"), 16),
                    "tool": safe_text(row.get("tool_name"), 40),
                    "outcome": "blocked" if row.get("decision") == "block" else "flagged"})
        if len(out) >= MAX_EVENTS:
            break
    return out


def wallet_protection_payload() -> Dict[str, Any]:
    """What the panel shows (see the module doc). Fail-open: a part that cannot be read is empty."""
    cfg = load_blackbox_config()
    mode = crypto_secrets.wallet_mode.current()
    try:
        wallets = detection.found_wallets()
    except Exception:   # a filesystem error means "none found", never a broken page
        wallets = []
    return {
        "enabled": mode.enabled,                 # the panel shows only while Web3 wallet protection is on
        "wallet_mode": mode.as_json(),
        "mode": "block" if cfg.block_enabled else "audit",
        "block_severity": safe_text(cfg.block_severity, 16),
        # Folder names found on THIS machine: cleaned, never defanged (a Firefox profile is "x.default-release").
        "wallets": [{**{key: (local_text(value, 64) if isinstance(value, str) else [local_text(a, 32) for a in value])
                        for key, value in wallet.items()},
                     "protected": mode.protects(str(wallet.get("id") or ""))}   # the gate's own rule
                    for wallet in wallets],
        "seed_checker": bool(crypto_secrets.wordlist_ready()),
        "private_keys": True,
        "protected_paths": [safe_text(p, 120) for p in (cfg.protected_paths or ())][:20],
        "terminal_reads": "logged",   # KI-363: terminal reads of protected paths are not blocked yet
        "events": _events(),
    }


#: The Trader Shield explainer page (the dashboard's "Learn more"), the tested attack table it
#: shows (one source for the page and its test), and the logos of the wallets it can protect.
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
TRADER_SHIELD_PAGE = STATIC_DIR / "trader-shield.html"
ATTACK_TABLE = STATIC_DIR / "trader-shield-attacks.json"
WALLET_LOGOS = STATIC_DIR / "wallets"
NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate"}


def register_protection_routes(app: Any) -> None:
    """Add ``GET /api/wallet-protection``, its ``/events`` report and the ``/trader-shield`` page to *app*."""
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

    @app.get("/api/wallet-protection")
    def wallet_protection() -> Any:
        return wallet_protection_payload()

    @app.get("/api/wallet-protection/events")
    def wallet_protection_events() -> Any:
        return wallet_event_report()

    @app.get("/trader-shield/attacks.json")
    def trader_shield_attacks() -> Any:
        return FileResponse(str(ATTACK_TABLE), media_type="application/json", headers=NO_CACHE)

    @app.get("/wallets/{wallet}.svg")
    def wallet_logo(wallet: str) -> Any:
        # Allowlisted by the supported-wallet table, so the name never becomes a free path.
        if wallet not in crypto_secrets.wallet_mode.SUPPORTED_WALLETS:
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(WALLET_LOGOS / f"{wallet}.svg"), media_type="image/svg+xml",
                            headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/trader-shield", response_class=HTMLResponse)
    def trader_shield_page() -> Any:
        if not TRADER_SHIELD_PAGE.exists():
            return HTMLResponse("<h1>Trader Shield</h1><p>page missing</p>", status_code=404)
        return FileResponse(str(TRADER_SHIELD_PAGE), headers=NO_CACHE)
