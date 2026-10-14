"""The dashboard's side of shields: what the settings routes add for every registered shield.

The kernel's settings stay shield-free (it never imports a shield); the dashboard composes
each shield's Settings view onto what the kernel answers (F-017), on GET and POST alike, so
the page re-renders from one shape. A sub-package because ``dashboard/`` is at its file
limit; the shield routes of §3.6 join it in S6a.

Usage::

    return shields_routes.with_shields(settings.read_settings())   # GET /api/settings
    return shields_routes.with_shields(settings.write_settings(payload, validators=...))   # POST
"""

from __future__ import annotations

import logging
from typing import Any

from ... import shields

logger = logging.getLogger(__name__)


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
