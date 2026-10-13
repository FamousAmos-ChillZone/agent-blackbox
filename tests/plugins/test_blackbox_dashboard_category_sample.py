"""The category panel loads its own sample (KI-337, 2026-10-10).

With live graph lookups the unfiltered graph page is one window in a fixed
category order (small tiers, then 252k dependencies, then IOCs), so the IOC and
dependency panels found nothing loaded and said "No threats are currently stored
in this category" under a count of 311,005. The panel must fetch its category
page itself when it holds fewer threats than it shows, and never claim an empty
category while that fetch is pending or has failed.

Structural guard: the panel's code lives inside the dashboard's private page
script and its categories are drawn on a canvas, so the real-browser pass cannot
reach it directly; the bench browser check is recorded in FIX-0089.
"""

from __future__ import annotations

import re
from pathlib import Path

INDEX = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "dashboard" / "static" / "index.html"


def _function_body(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    following = re.search(r"\n\t  function |\n  function ", source[start + 1:])
    return source[start:start + 1 + following.start()] if following else source[start:]


def test_the_category_panel_fetches_its_own_category_page_when_short():
    body = _function_body(INDEX.read_text(encoding="utf-8"), "openCategoryModal")

    assert "loadGraphFocusPage(" in body
    assert "items.length < wanted" in body


def test_the_category_panel_never_calls_a_pending_or_failed_fetch_empty():
    source = INDEX.read_text(encoding="utf-8")
    body = _function_body(source, "categoryThreatListHTML")

    assert 'sampleState === "loading"' in body
    assert 'sampleState === "unavailable"' in body
    assert "categoryThreatListHTML(items, sampleState)" in source
