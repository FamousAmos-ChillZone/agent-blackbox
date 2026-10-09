"""kernel.identity.reporter_address — THE resolver of this node's identity.

KI-003 / LES-003: identity-keyed writes fail closed — no resolvable address
means ``None``, never a shared placeholder that would merge distinct nodes
onto one report subject. Until 2026-10-01 this resolver had no direct test
(LES-020: a fail-open path needs a real test or a refactor can delete it).
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import identity

ADDRESS = "0xabc0000000000000000000000000000000000001"


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.setattr(identity, "_reporter_cache", {})


class _Client:
    """Answers agent_identity/status with the given payloads (or raises)."""

    def __init__(self, identity_payload=None, status_payload=None, identity_raises=False):
        self.identity_payload = identity_payload
        self.status_payload = status_payload
        self.identity_raises = identity_raises
        self.identity_calls = 0

    def agent_identity(self):
        self.identity_calls += 1
        if self.identity_raises:
            raise RuntimeError("node down")
        return self.identity_payload

    def status(self):
        return self.status_payload


def test_resolves_from_agent_identity():
    assert identity.reporter_address(_Client({"agentAddress": f"  {ADDRESS} "})) == ADDRESS


def test_falls_back_to_status_when_identity_fails():
    client = _Client(identity_raises=True, status_payload={"defaultAgentAddress": ADDRESS})
    assert identity.reporter_address(client) == ADDRESS


def test_returns_none_never_a_placeholder_when_unresolvable():
    client = _Client(identity_payload={"agentAddress": "   "}, status_payload={})
    assert identity.reporter_address(client) is None


def test_caches_a_resolved_address_only():
    unresolved = _Client(identity_payload={})
    assert identity.reporter_address(unresolved) is None
    resolved = _Client({"agentAddress": ADDRESS})
    assert identity.reporter_address(resolved) == ADDRESS
    assert identity.reporter_address(resolved) == ADDRESS
    assert resolved.identity_calls == 1
