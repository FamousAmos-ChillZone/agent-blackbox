"""Make ``tests/plugins`` importable for shared helpers (e.g. ``_blackbox_loader``)."""

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import pytest


@pytest.fixture(autouse=True)
def _fresh_community_membership(monkeypatch):
    """Blackbox keeps per-process subscribe/join state (community/membership.py);
    each test starts from a fresh one so retry windows never leak between tests.
    Only touches the module when a test has already imported it."""
    for name in ("plugins.blackbox.community.membership", "hermes_plugins.blackbox.community.membership"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "MEMBERSHIP", module.CommunityMembership())
    yield
