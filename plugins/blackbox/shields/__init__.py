"""Shields — named, opt-in protection packs; this is the registry and the only public entry.

**Registry over Strategies.** Each registered :class:`~.contract.Shield` is a record of
plain callables (composition, no base class); the functions here fan a call out to
every shield and apply the rules no shield may opt out of:

* ``snapshot()`` reads every shield's mode ONCE; the hooks take one snapshot per call
  and hand it to ``check`` and ``allows``. Nothing here reads config on its own
  behalf — a mode is read only by the shield's own ``mode()``, only in ``snapshot()``
  and the dashboard views.
* ``check()`` runs every ENABLED shield's ``detect`` and marks each finding
  ``source="secret"`` (local only: the community gate refuses that source), and a
  shield whose ``detect`` raises contributes nothing (fail-open, WARNING).
* ``allows()`` is the gate: a finding no shield claims is always allowed; a claimed
  one only while that shield is enabled and its ``allows`` agrees. A shield whose
  ``claims`` or ``allows`` raises is read as "claims and refuses" — opt-in
  protection fails toward OFF.

Packs and browser roots are loaded at import (never on the hot path) and loading
never raises: a broken pack is ``unavailable`` with its reason, the rest load.

Usage::

    active = shields.snapshot()
    findings = detection.detect_all(...) + shields.check(tool, args, active)
    kept = [f for f in findings if shields.allows(f.to_dict(), active)]
"""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from ..detection import Finding
from ..kernel.settings import SettingsValidator
from .contract import (
    Shield,
    ShieldEvent,
    ShieldMode,
    ShieldsSnapshot,
    ShieldStatus,
)
from .packs import ShieldData, load_shield_data

logger = logging.getLogger(__name__)

__all__ = [
    "Shield",
    "ShieldEvent",
    "ShieldMode",
    "ShieldStatus",
    "ShieldsSnapshot",
    "all_shields",
    "allows",
    "check",
    "events",
    "get",
    "pack_logo",
    "settings_validators",
    "settings_view",
    "snapshot",
    "statuses",
]

#: Every registered shield, in registration order. Registering one is one line here.
_SHIELDS: tuple[Shield, ...] = ()

#: The finding source every shield finding carries: never shared (community.NEVER_SHARED_SOURCES).
LOCAL_ONLY_SOURCE = "secret"


def _load_all(shields: Iterable[Shield]) -> dict[str, ShieldData]:
    """Each shield's packs and roots; a shield whose loading fails has none, with the reason."""
    loaded: dict[str, ShieldData] = {}
    for shield in shields:
        try:
            loaded[shield.id] = load_shield_data(shield)
        except Exception as exc:   # loading never takes the registry (and with it the guard) down
            logger.warning("blackbox: shield %s data could not be loaded: %s", shield.id, exc)
            loaded[shield.id] = ShieldData(health=(f"shield data unavailable — {type(exc).__name__}",))
    return loaded


_DATA: dict[str, ShieldData] = _load_all(_SHIELDS)


def all_shields() -> tuple[Shield, ...]:
    """Every registered shield, in registration order."""
    return _SHIELDS


def get(shield_id: str) -> Optional[Shield]:
    """The shield registered as *shield_id*, or None."""
    return next((shield for shield in _SHIELDS if shield.id == shield_id), None)


def _mode_of(shield: Shield) -> ShieldMode:
    try:
        return shield.mode()
    except Exception as exc:   # a mode that cannot be read is off (fails toward OFF)
        logger.warning("blackbox: shield %s mode could not be read: %s", shield.id, exc)
        return ShieldMode(enabled=False)


def snapshot() -> ShieldsSnapshot:
    """Every shield paired with its mode, each read once — take one per hook call."""
    return ShieldsSnapshot(entries=tuple((shield, _mode_of(shield)) for shield in _SHIELDS))


def check(tool_name: str, args: Any, active: ShieldsSnapshot) -> list[Finding]:
    """Every enabled shield's own findings for this call, each marked local-only."""
    findings: list[Finding] = []
    for shield, mode in active.entries:
        if not mode.enabled:
            continue
        try:
            raised = shield.detect(tool_name, args, mode)
        except Exception as exc:   # a broken detector contributes nothing (fail-open)
            logger.warning("blackbox: shield %s detect failed: %s", shield.id, exc)
            continue
        for finding in raised:
            if finding.source != LOCAL_ONLY_SOURCE:
                logger.warning("blackbox: shield %s finding %s had source %r; made local-only",
                               shield.id, finding.identifier, finding.source)
            findings.append(dataclasses.replace(finding, source=LOCAL_ONLY_SOURCE))
    return findings


def allows(finding: Mapping[str, Any], active: ShieldsSnapshot) -> bool:
    """False when a shield claims *finding* and is off or refuses it; True otherwise."""
    for shield, mode in active.entries:
        try:
            if shield.claims(finding) and not (mode.enabled and shield.allows(finding, mode)):
                return False
        except Exception as exc:   # claims-and-refuses: opt-in protection fails toward OFF
            logger.warning("blackbox: shield %s gate failed: %s", shield.id, exc)
            return False
    return True


def settings_validators() -> tuple[SettingsValidator, ...]:
    """One settings validator per shield, for ``kernel.settings.write_settings(validators=...)``."""
    return tuple(shield.validate for shield in _SHIELDS)


def settings_view() -> dict[str, Any]:
    """``{shield id: {mode, fields}}`` for the Settings page (the one view that shows personal options)."""
    return {shield.id: {"mode": _mode_of(shield).as_json(include_personal=True),
                        "fields": [item.as_json() for item in shield.settings_fields()]}
            for shield in _SHIELDS}


def statuses() -> list[ShieldStatus]:
    """Every shield's card, built from one snapshot."""
    return [shield.status(mode) for shield, mode in snapshot().entries]


def events(shield_id: str) -> list[ShieldEvent]:
    """The local events report of *shield_id* (empty for an unknown id)."""
    shield = get(shield_id)
    return shield.events() if shield is not None else []


def pack_logo(shield_id: str, pack_id: str) -> Optional[Path]:
    """The logo file of a usable pack, resolved through the registry only; None when it has none."""
    data = _DATA.get(shield_id)
    pack = next((item for item in data.packs if item.id == pack_id), None) if data else None
    if pack is None or pack.status == "unavailable" or pack.logo is None:
        return None
    return pack.folder / pack.logo.file
