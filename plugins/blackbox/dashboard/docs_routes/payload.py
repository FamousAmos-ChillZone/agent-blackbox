"""What the dashboard's Docs page shows that comes from the product itself.

The Docs page explains Blackbox in prose it ships with (``docs.html``), and reads everything that
changes with the product from ``GET /api/docs`` — built here, live, from the shields registry:
each shield, its packs (with each wallet's stores, browsers and sources), the browser folders it
knows and its tested attack table. Nothing here is a hand-kept copy of product data, so the docs
cannot drift from what the product does. The one hand-written record is ``field_tests.json``: the
real-machine test runs, which are past events, not product state.

Shields are read generically (the dashboard never names a shield's parts — see
tests/plugins/test_blackbox_shields_boundaries.py).

Usage::

    payload = build_payload()        # DocsPayload, JSON-ready
    payload["shields"][0]["packs"]   # every pack of the first shield
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional, TypedDict

from ... import shields
from ...kernel.constants import __version__

logger = logging.getLogger(__name__)

FIELD_TESTS_FILE = Path(__file__).with_name("field_tests.json")
#: The attack-table row fields the page may show: never a row's test command (those live with the
#: tests, never in plugin files — the Hermes catalog gate scans what ships).
ATTACK_FIELDS = ("id", "group", "title", "how", "outcome", "targets", "evidence")


class AvailabilityDoc(TypedDict, total=False):
    """One store a wallet ships in: ``store``, ``browsers``, ``state`` (protected / not-covered /
    not-offered / not-found) and, when known, ``url``, ``source`` and ``note``."""

    store: str
    browsers: list[str]
    state: str
    url: str
    source: str
    note: str


class PackDoc(TypedDict):
    """One pack of a shield (a wallet, for Trader Shield) as the Docs page lists it."""

    id: str
    name: str
    kind: str
    status: str
    verified: str
    source: str
    stores: dict[str, list[str]]
    places: list[str]
    label: str
    availability: list[AvailabilityDoc]
    logo: Optional[str]


class BrowserDoc(TypedDict):
    """One browser folder the shield knows: which browser, on which system, installed how."""

    browser: str
    engine: str
    os: str
    install: str


class ShieldDoc(TypedDict):
    """One shield: who it is, what it can do, what it guards, where it looks and what was tested."""

    id: str
    name: str
    tagline: str
    beta: bool
    page: str
    capabilities: list[dict[str, str]]
    packs: list[PackDoc]
    browsers: list[BrowserDoc]
    attacks: dict[str, Any]


class DocsPayload(TypedDict):
    """``GET /api/docs``: the product version, every shield and the real-machine test runs."""

    version: str
    shields: list[ShieldDoc]
    field_tests: list[dict[str, Any]]


def _pack_doc(shield_id: str, pack: Any) -> PackDoc:
    data = pack.data
    has_logo = shields.pack_logo(shield_id, pack.id) is not None
    return PackDoc(
        id=pack.id, name=pack.name, kind=pack.kind, status=pack.status, verified=pack.verified,
        source=pack.source, stores={engine: list(ids) for engine, ids in (data.get("stores") or {}).items()},
        places=list(data.get("places") or []), label=str(data.get("label") or ""),
        availability=[AvailabilityDoc(**entry) for entry in data.get("availability") or []],
        logo=f"/shields/{shield_id}/packs/{pack.id}/logo.svg" if has_logo else None)


def _attacks_doc(shield_id: str) -> dict[str, Any]:
    from ..shields_routes import attacks_payload   # the page's table, browser-folder rows included

    try:
        table = attacks_payload(shield_id)
    except (OSError, ValueError) as exc:
        logger.warning("blackbox docs: the %s attack table could not be read: %s", shield_id, exc)
        table = None
    if not table:
        return {"groups": [], "rows": [], "evidence_levels": {}, "tested_with": ""}
    return {"groups": table.get("groups", []), "evidence_levels": table.get("evidence_levels", {}),
            "tested_with": table.get("tested_with", ""),
            "rows": [{field: row[field] for field in ATTACK_FIELDS if field in row} for row in table.get("attacks", [])]}


def _shield_doc(shield: Any) -> ShieldDoc:
    return ShieldDoc(
        id=shield.id, name=shield.name, tagline=shield.tagline, beta=shield.beta, page=f"/shields/{shield.id}",
        capabilities=[{"id": cap.id, "name": cap.name, "note": cap.note} for cap in shield.capabilities],
        packs=[_pack_doc(shield.id, pack) for pack in shields.loaded_packs(shield.id)],
        browsers=[BrowserDoc(browser=root.browser, engine=root.engine, os=root.os, install=root.install)
                  for root in shields.browser_roots(shield.id)],
        attacks=_attacks_doc(shield.id))


def _field_tests() -> list[dict[str, Any]]:
    try:
        runs = json.loads(FIELD_TESTS_FILE.read_text(encoding="utf-8")).get("runs", [])
    except (OSError, ValueError) as exc:
        logger.warning("blackbox docs: field tests could not be read: %s", exc)
        return []
    return runs if isinstance(runs, list) else []


def build_payload() -> DocsPayload:
    """The Docs page's live data (see :class:`DocsPayload`)."""
    return DocsPayload(version=__version__, shields=[_shield_doc(shield) for shield in shields.all_shields()],
                       field_tests=_field_tests())
