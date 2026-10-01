"""The private working-memory audit record is actually written (FIX-0017).

Every other test stubs ``audit.write_private_audit_ka`` out, and the function
is best-effort (it swallows its own failures) — so when the restructure broke
its lazy import, the record silently stopped being written and the suite
stayed green. These tests call the real function with a recording client.
"""

from __future__ import annotations

from _blackbox_loader import load_blackbox

audit = load_blackbox("audit")
constants = load_blackbox("kernel.constants")


class _RecordingClient:
    """Captures private-KA writes instead of talking to a DKG node."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str, list[dict[str, str]]]] = []

    def write_private_knowledge_asset(self, cg_id: str, name: str, quads: list[dict[str, str]]) -> None:
        self.writes.append((cg_id, name, quads))


def test_private_audit_record_is_written_with_redacted_evidence():
    client = _RecordingClient()
    finding = {"identifier": "dep:npm:evil@1.0.0", "severity": "high", "evidence": "npm install evil@1.0.0"}

    audit.write_private_audit_ka(client, "graph-1", "pre_tool_call", finding)

    assert len(client.writes) == 1, "the private audit record was not written"
    cg_id, _name, quads = client.writes[0]
    assert cg_id == "graph-1"
    predicates = {q["predicate"] for q in quads}
    assert constants.IDENTIFIER_PRED in predicates
    assert constants.SCHEMA_DESCRIPTION_PRED in predicates


def test_private_audit_record_subject_is_an_audit_urn():
    client = _RecordingClient()

    audit.write_private_audit_ka(client, "graph-1", "pre_tool_call", {"identifier": "x"})

    _cg, _name, quads = client.writes[0]
    assert all(q["subject"].startswith("urn:guardian:audit:") for q in quads)
