"""The dashboard's side of shields: the settings each shield adds, and ``GET /api/shields``.

The kernel's settings stay shield-free (it never imports a shield); the dashboard composes
each shield's Settings view onto what the kernel answers (F-017), on GET and POST alike, so
the page re-renders from one shape. A sub-package because ``dashboard/`` is at its file
limit; the rest of the shield routes of §3.6 join it here.

``GET /api/shields`` answers every registered shield's card (``shields.statuses()``),
sanitised ONCE here, at the serving boundary (F-002: a shield clamps its own text but never
imports the dashboard), and served through the server's stale-while-revalidate cache for
:data:`STATUS_TTL_SECONDS`, so N shields cost one read per 2 s however many tabs poll (F-021).

``GET /api/shields/{id}/events`` answers that shield's full local events report
(``[ShieldEvent.as_json()]``, newest first; 404 for an id no shield is registered as),
sanitised once here too. Its text is the operator's OWN logs (redacted when logged), so it
is cleaned and clamped but not defanged — ``backup.tgz`` stays ``backup.tgz`` — and the
``identifier`` goes through ``safe_identifier``, the token the page hands back.

Usage::

    return shields_routes.with_shields(settings.read_settings())   # GET /api/settings
    return shields_routes.with_shields(settings.write_settings(payload, validators=...))   # POST
    shields_routes.register(app, _swr)   # from dashboard.server.create_app
    shields_routes.events_payload("trader")   # -> [ShieldEvent.as_json()], or None for an unknown id
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

from ... import shields
from .. import protection
from ...kernel.display_safety import strip_controls
from ..safe_payloads import safe_identifier, safe_text

logger = logging.getLogger(__name__)

#: How long one answer of ``GET /api/shields`` is reused (the page polls every 4 s).
STATUS_TTL_SECONDS = 2.0
#: The longest text a card carries (a section's help sentence is the longest today).
MAX_CARD_TEXT = 1000
#: The longest text an event carries (its story: the asked request, escaped, plus the prose).
MAX_EVENT_TEXT = 8000
#: A card's ``logo``: a path on this dashboard (``/wallets/metamask.svg``), served as is or not at all.
LOCAL_URL = re.compile(r"/[A-Za-z0-9_-]+(?:[./][A-Za-z0-9_-]+)*")
#: ``create_app``'s cache: ``swr(key, producer, default, ttl)`` answers the cached value.
Cache = Callable[..., Any]


def with_shields(result: dict[str, Any]) -> dict[str, Any]:
    """*result* with ``shields`` (``{id: {mode, fields}}``) added to its settings view.

    A ``write_settings`` result carries the view under ``settings``; a ``read_settings``
    result is the view. Fail-open: when a shield's view cannot be built, the settings are
    answered without ``shields`` and the page leaves the shield groups as they were.
    """
    view = result.get("settings") if isinstance(result.get("settings"), dict) else result
    try:
        view["shields"] = shields.settings_view()
    except Exception as exc:   # one broken shield must never take the settings page down
        logger.warning("blackbox dashboard: shield settings view failed (%s)", type(exc).__name__)
    return result


def _card_text(value: str) -> str:
    return safe_text(value, MAX_CARD_TEXT)


def _local_text(value: str) -> str:
    """The operator's own logged text: controls stripped and clamped, never defanged."""
    return strip_controls(value)[:MAX_EVENT_TEXT]


def sanitised(value: Any, text: Callable[[str], str] = _card_text) -> Any:
    """*value* (plain JSON) with every string passed through *text* (by default
    ``safe_payloads.safe_text`` — the dashboard's one sanitiser), except a ``logo``, which is
    a local path kept only when it is one (defanging would break it), and an ``identifier``,
    which goes through ``safe_identifier``; keys are the record's own field names."""
    if isinstance(value, str):
        return text(value)
    if isinstance(value, dict):
        return {key: _local_url(item) if key == "logo" else safe_identifier(item) if key == "identifier"
                else sanitised(item, text) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitised(item, text) for item in value]
    return value


def statuses_payload() -> list[Any]:
    """Every shield's card as served: ``[ShieldStatus.as_json()]``, sanitised once."""
    return [sanitised(status.as_json()) for status in shields.statuses()]


def events_payload(shield_id: str) -> list[Any] | None:
    """*shield_id*'s events report as served, sanitised once; None when no shield has that id."""
    shield = shields.get(shield_id)
    if shield is None:
        return None
    return [sanitised(event.as_json(), _local_text) for event in shield.events()]


def register(app: Any, swr: Cache) -> None:
    """Add ``GET /api/shields`` (cached through *swr*) and ``GET /api/shields/{id}/events``
    to *app*, and (until S7 removes it) the old wallet-protection panel's routes."""
    from fastapi.responses import JSONResponse

    protection.register_protection_routes(app)   # transitional: the old panel, until S7

    @app.get("/api/shields")
    def shield_statuses() -> Any:
        return swr("shields", statuses_payload, [], STATUS_TTL_SECONDS)

    @app.get("/api/shields/{shield_id}/events")
    def shield_events(shield_id: str) -> Any:
        payload = events_payload(shield_id)
        if payload is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return payload


def _local_url(value: Any) -> str:
    """*value* when it is a plain path on this dashboard, else "" (no scheme, host or ``..``)."""
    return value if isinstance(value, str) and LOCAL_URL.fullmatch(value) else ""
