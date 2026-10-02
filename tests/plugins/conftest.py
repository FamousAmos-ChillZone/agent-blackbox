"""Make ``tests/plugins`` importable for shared helpers (e.g. ``_blackbox_loader``)."""

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import pytest

from plugins.blackbox.community import consent as _consent_module

_REAL_IN_FORCE = _consent_module.in_force


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


@pytest.fixture(autouse=True)
def _sharing_consent_in_force(monkeypatch):
    """R13: sharing is opt-in and refused without a consent record. The suite's
    share-path tests predate the gate and test OTHER things, so consent is in
    force by default; the gate's own tests ask for ``real_consent``."""
    for name in ("plugins.blackbox.community.consent", "hermes_plugins.blackbox.community.consent"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "in_force", lambda: True)
    yield


@pytest.fixture
def real_consent(monkeypatch):
    """The real consent gate (undoes the autouse stub for one test)."""
    from plugins.blackbox.community import consent
    monkeypatch.setattr(consent, "in_force", _REAL_IN_FORCE)
    return consent
