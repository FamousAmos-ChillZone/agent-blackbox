"""R0b — every community report and dispute this node shares is signed.

The signature (kernel.signing) is what a reader will verify before counting a
report (R0c); here we pin that the writer side produces it, that it covers the
stored fields, that the timestamp is day-rounded (decision 25), and that a node
that cannot sign does not share at all (fail closed, LES-014).
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.community import report_builder, report_command, report_signer, sharing
from plugins.blackbox.kernel import constants, signing
from plugins.blackbox.kernel.config import BlackboxConfig

GRAPH = "0xabc/agent-blackbox-community-test"
NETWORK = "test-network-id"
REPORTER = "0xAbC0000000000000000000000000000000000001"


def _signer() -> report_signer.ReportSigner:
    return report_signer.ReportSigner(private_key=Ed25519PrivateKey.generate(), environment=NETWORK, graph=GRAPH)


def _envelope(quads):
    texts = [q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED]
    assert len(texts) == 1
    return signing.from_text(json.loads(texts[0]))


def _verify(envelope, statement_type=report_signer.REPORT_STATEMENT):
    return signing.verify(envelope, statement_type=statement_type, environment=NETWORK, graph=GRAPH)


def test_signed_report_verifies_and_covers_its_fields():
    signer = _signer()
    quads = report_builder.build_report_quads(
        identifier="dep:npm:evil@1.0.0", category="dependency", severity="Critical",
        reporter_address=REPORTER, signer=signer,
        ecosystem="npm", package_name="evil", package_version="1.0.0", kind="malware", reason="install-hook",
        ts=datetime(2026, 10, 1, 17, 42, tzinfo=timezone.utc),
    )
    envelope = _envelope(quads)
    assert _verify(envelope) == signing.public_key_hex(signer.private_key)
    assert envelope.payload == {
        "subject": quads[0]["subject"], "identifier": "dep:npm:evil@1.0.0", "category": "dependency",
        "severity": "critical", "reporter": REPORTER.lower(), "framework": "hermes", "day": "2026-10-01",
        "package_name": "evil", "package_version": "1.0.0", "ecosystem": "npm", "kind": "malware", "reason": "install-hook",
    }


def test_report_timestamp_is_rounded_to_the_day():
    quads = report_builder.build_report_quads(
        identifier="ioc:domain:x.example", category="ioc", severity="high", reporter_address=REPORTER, ioc_type="domain", ioc_context="fetched-by-tool",
        ts=datetime(2026, 10, 1, 17, 42, 9, tzinfo=timezone.utc),
    )
    stamp = [q["object"] for q in quads if q["predicate"] == constants.SCHEMA_DATE_MODIFIED_PRED][0]
    assert "2026-10-01T00:00:00" in stamp and "17:42" not in stamp


def test_unsigned_build_has_no_signature_quad():
    quads = report_builder.build_report_quads(identifier="ioc:domain:x.example", category="ioc",
                                              severity="high", reporter_address=REPORTER, ioc_type="domain", ioc_context="fetched-by-tool")
    assert not [q for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED]


def test_dispute_is_signed_as_a_dispute():
    quads = report_builder.build_false_positive_quads(identifier="ioc:domain:x.example",
                                                      reporter_address=REPORTER, signer=_signer())
    envelope = _envelope(quads)
    assert _verify(envelope, report_signer.DISPUTE_STATEMENT) is not None
    assert _verify(envelope, report_signer.REPORT_STATEMENT) is None   # a dispute can't pass as a report


class _Status:
    def __init__(self, status):
        self._status = status

    def status(self):
        if isinstance(self._status, Exception):
            raise self._status
        return self._status


@pytest.mark.parametrize("status", [{}, {"networkId": ""}, RuntimeError("node down")])
def test_no_signer_without_a_network_id(status, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    assert report_signer.resolve_report_signer(_Status(status), GRAPH) is None


def test_no_signer_with_an_unusable_key(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    (tmp_path / "reporter_key.pem").write_text("broken", encoding="utf-8")
    assert report_signer.resolve_report_signer(_Status({"networkId": NETWORK}), GRAPH) is None


def test_signer_binds_network_and_graph(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    signer = report_signer.resolve_report_signer(_Status({"networkId": NETWORK}), GRAPH)
    assert (signer.environment, signer.graph) == (NETWORK, GRAPH)


def test_automatic_share_refuses_when_it_cannot_sign(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    shared, ledger = [], []

    class _NoNetwork(_Status):
        def share_knowledge_asset(self, *args, **kwargs):
            shared.append(args)

    monkeypatch.setattr(sharing, "_ledger_share", lambda finding, subject, name, ok, error="": ledger.append((ok, error)))
    finding = {"identifier": "ioc:domain:x.example", "category": "ioc", "severity": "high", "fields": {}}
    sharing._share_sighting(_NoNetwork({}), BlackboxConfig(report=True, community_graph_id=GRAPH), finding, REPORTER)
    assert shared == []
    assert ledger and ledger[0][0] is False and "cannot sign" in ledger[0][1]


def test_cli_report_refuses_when_it_cannot_sign(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: BlackboxConfig(report=True, community_graph_id=GRAPH))
    monkeypatch.setattr(report_command, "DkgClient", lambda **kw: _Status({}))
    monkeypatch.setattr(report_command.identity, "reporter_address", lambda client: REPORTER)
    args = argparse.Namespace(false_positive=None, status=False)
    assert report_command.cmd_report(args) == 1
    assert "Nothing was submitted" in capsys.readouterr().out
