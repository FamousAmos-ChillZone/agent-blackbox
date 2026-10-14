"""The dashboard's side of shields: the settings each shield adds, and ``GET /api/shields``.

The kernel's settings stay shield-free (it never imports a shield); the dashboard composes
each shield's Settings view onto what the kernel answers (F-017), on GET and POST alike, so
the page re-renders from one shape. A sub-package because ``dashboard/`` is at its file
limit; the rest of the shield routes of §3.6 join it in S6a.

``GET /api/shields`` answers every registered shield's card (``shields.statuses()``),
sanitised ONCE here, at the serving boundary (F-002: a shield clamps its own text but never
imports the dashboard), and served through the server's stale-while-revalidate cache for
:data:`STATUS_TTL_SECONDS`, so N shields cost one read per 2 s however many tabs poll (F-021).

Usage::

    return shields_routes.with_shields(settings.read_settings())   # GET /api/settings
    return shields_routes.with_shields(settings.write_settings(payload, validators=...))   # POST
    shields_routes.register(app, _swr)   # from dashboard.server.create_app
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

from ... import shields
from .. import protection
from ..safe_payloads import safe_text

logger = logging.getLogger(__name__)

#: How long one answer of ``GET /api/shields`` is reused (the page polls every 4 s).
STATUS_TTL_SECONDS = 2.0
#: The longest text a card carries (a section's help sentence is the longest today).
MAX_CARD_TEXT = 1000
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


def sanitised(value: Any) -> Any:
    """*value* (plain JSON) with every string passed through ``safe_payloads.safe_text`` —
    the dashboard's one sanitiser — except a ``logo``, which is a local path kept only when
    it is one (defanging would break it); keys are the record's own field names."""
    if isinstance(value, str):
        return safe_text(value, MAX_CARD_TEXT)
    if isinstance(value, dict):
        return {key: _local_url(item) if key == "logo" else sanitised(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitised(item) for item in value]
    return value


def statuses_payload() -> list[Any]:
    """Every shield's card as served: ``[ShieldStatus.as_json()]``, sanitised once."""
    return [sanitised(status.as_json()) for status in shields.statuses()]


def register(app: Any, swr: Cache) -> None:
    """Add ``GET /api/shields`` to *app*, cached through *swr*, and (until S7 removes it) the
    old wallet-protection panel's routes."""
    protection.register_protection_routes(app)   # transitional: the old panel, until S7

    @app.get("/api/shields")
    def shield_statuses() -> Any:
        return swr("shields", statuses_payload, [], STATUS_TTL_SECONDS)


def _local_url(value: Any) -> str:
    """*value* when it is a plain path on this dashboard, else "" (no scheme, host or ``..``)."""
    return value if isinstance(value, str) and LOCAL_URL.fullmatch(value) else ""
