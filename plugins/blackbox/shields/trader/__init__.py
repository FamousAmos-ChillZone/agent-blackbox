"""Trader Shield — opt-in protection for people who hold crypto: wallet key stores, seed
phrases, private keys, exchange keys, token approvals and the macOS keychain.

This module assembles :data:`TRADER`, the shield's record (Strategy, by composition: a
:class:`~..contract.Shield` of plain functions). Today it carries the setting (:mod:`.mode`),
the gate (``claims`` / ``allows``, the rules the guard has always applied) and its data —
the wallet packs in ``wallets/`` and the browser folders in ``browsers.json``, validated
by the kind table in :mod:`.detectors` (nothing on the hot path reads them yet); its own
detectors, card and events report are placeholders that answer empty until S4c, S5 and
S6a fill them, and ``finding_kinds`` / ``capabilities`` arrive with S4c.

Usage::

    from plugins.blackbox import shields
    trader = shields.get("trader")
    trader.allows({"identifier": "secret:seed-phrase"}, trader.mode())   # False while off
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ...detection import Finding
from ...kernel import crypto_secrets
from ..contract import SettingField, SettingOption, Shield, ShieldEvent, ShieldMode, ShieldStatus
from ..packs import load_packs
from . import detectors, mode

HERE = Path(__file__).resolve().parent


def _current_mode() -> ShieldMode:
    # Looked up on every call, not bound once: a test stands a mode in by patching mode.current.
    return mode.current()


def _listed_addresses() -> tuple[str, ...]:
    """The operator's own addresses, for the kernel's always-on own-key redaction."""
    return mode.addresses(mode.current())


def claims(finding: Mapping[str, Any]) -> bool:
    """Whether *finding* is a Trader Shield finding (the mode gate applies to it)."""
    return mode.belongs_to_mode(str(finding.get("identifier") or ""))


def settings_fields() -> list[SettingField]:
    """How Settings draws Trader's group: the switch, and the wallet packs in display order
    (supported, then coming soon; a pack that failed to load is left out until S6a shows it)."""
    options = tuple(SettingOption(id=pack.id, name=pack.name, status=pack.status,
                                  logo=f"/wallets/{pack.id}.svg" if pack.status == "supported" else "")
                    for pack in mode.wallet_packs() if pack.status != "unavailable")
    return [SettingField(key="enabled", kind="toggle", label="Trader Shield"),
            SettingField(key=mode.WALLETS, kind="multi-pick", label="Wallets to protect", options=options)]


def _no_findings(tool_name: str, args: Any, active: ShieldMode) -> list[Finding]:
    return []   # placeholder: Trader's own detectors arrive in S4c


def _status(active: ShieldMode) -> ShieldStatus:
    return ShieldStatus(shield_id="trader", mode=active, blocking=False)   # placeholder: the card arrives in S6a


def _no_events() -> list[ShieldEvent]:
    return []   # placeholder: the events report moves here in S5


TRADER = Shield(
    id="trader", name="Trader Shield", beta=True,
    tagline="Keeps your AI agent away from your crypto wallets, seed phrases and keys.",
    mode=_current_mode, validate=mode.validate, detect=_no_findings,
    claims=claims, allows=mode.allows_finding, status=_status, events=_no_events,
    settings_fields=settings_fields, finding_kinds=(), capabilities=(),
    packs=HERE / "wallets", page=HERE / "page" / "trader.html", attacks=HERE / "attacks.json",
    detectors=detectors.DETECTORS, browser_roots=HERE / "browsers.json",
)

# The mode chooses among the packs, read once here at import (never on the hot path).
# The registry reads them again for its own view (logos, health): two import-time reads.
mode.use_packs(load_packs(TRADER))

# The kernel's own-key redaction needs the listed addresses but may not import a shield:
# the shield hands its reader in (dependency injection, like the settings validators).
crypto_secrets.read_listed_addresses_from(_listed_addresses)
