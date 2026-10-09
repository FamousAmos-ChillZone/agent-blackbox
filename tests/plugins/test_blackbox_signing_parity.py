"""Cross-runtime signing parity (Refine R0b, KI-182 port).

The hermes plugin (`kernel/signing/envelope.py`) and the OpenClaw bridge
(`integrations/openclaw/src/signing.ts`) must sign the SAME bytes in the SAME
envelope format, or a reader in one runtime drops every report the other made.
The key is generated AT RUNTIME (no key material in the repo, LES-022). The
TypeScript half is `integrations/openclaw/test/signing-parity.mjs`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from plugins.blackbox.community import report_signer
from plugins.blackbox.community.verification import ReportVerifier
from plugins.blackbox.kernel import constants, signing
from plugins.blackbox.kernel.signing import envelope as envelope_module

REPO = Path(__file__).resolve().parents[2]
TSX = REPO / "node_modules" / ".bin" / "tsx"
SCRIPT = REPO / "integrations" / "openclaw" / "test" / "signing-parity.mjs"
GRAPH = "0x189e3fb1f109a579fb061afd4494a1019b19e0a5/community-parity"
NETWORK = "parity-net"
REPORTER = "0x" + "ab" * 20

_CASES = [
    {"statementType": "blackbox.report", "environment": NETWORK, "graph": GRAPH,
     "payload": {"identifier": "ioc:domain:evil.example", "reporter": REPORTER, "day": "2026-10-03"}},
    {"statementType": "blackbox.retract", "environment": NETWORK, "graph": GRAPH,
     "payload": {"identifier": "dep:npm:evil@1", "reporter": REPORTER, "note": "café — non-ascii escapes like Python"}},
    {"statementType": "blackbox.report", "environment": NETWORK, "graph": GRAPH, "payload": {}},
]
_REPORT = {
    "environment": NETWORK, "graph": GRAPH, "day": "2026-10-03",
    "input": {"identifier": "ioc:domain:evil.example", "category": "ioc", "severity": "high", "reporter": REPORTER,
              "framework": "openclaw", "evidence": {"ioc_type": "domain", "ioc_context": "fetched-by-tool"}},
}


def _row(quads: list[dict]) -> dict:
    """A reader row for the one subject in *quads*, as the SPARQL in reader.py would bind it."""
    strip = lambda term: term[1:-1] if term.startswith('"') and term.endswith('"') else term.split('"^^')[0].lstrip('"')
    row = {"r": quads[0]["subject"]}
    names = {constants.IDENTIFIER_PRED: "identifier", constants.REPORTER_PRED: "reporter", constants.SEVERITY_PRED: "severity",
             constants.IOC_TYPE_PRED: "iocType", constants.IOC_CONTEXT_PRED: "iocContext", constants.SIGNED_STATEMENT_PRED: "signedStatement"}
    for quad in quads:
        if quad["predicate"] in names:
            row[names[quad["predicate"]]] = strip(quad["object"]).replace('\\"', '"').replace("\\\\", "\\")
    return row


@pytest.mark.skipif(not TSX.exists() or shutil.which("node") is None, reason="tsx/node not installed")
def test_typescript_signs_the_same_bytes_and_python_verifies_them(tmp_path):
    key = Ed25519PrivateKey.generate()
    pem = tmp_path / "parity_key.pem"
    pem.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps({"cases": _CASES, "report": _REPORT}), encoding="utf-8")
    result = subprocess.run([str(TSX), str(SCRIPT), str(pem), str(cases)], capture_output=True, text=True,
                            timeout=120, cwd=str(REPO), check=True)
    from_ts = json.loads(result.stdout)
    signer_hex = signing.public_key_hex(key)

    for case, produced in zip(_CASES, from_ts["cases"]):
        parsed = signing.from_text(produced["envelope"])
        assert parsed is not None, produced["envelope"]
        # the exact bytes both runtimes sign
        assert produced["messageHex"] == envelope_module._signed_message(parsed).hex()
        # Python's own signing of the same statement serializes identically (modulo the signature value)
        ours = signing.sign(key, statement_type=case["statementType"], environment=case["environment"],
                            graph=case["graph"], payload=case["payload"])
        assert json.loads(ours.to_text())["payload"] == json.loads(produced["envelope"])["payload"]
        assert signing.verify(parsed, statement_type=case["statementType"], environment=case["environment"],
                              graph=case["graph"]) == signer_hex
        assert signing.verify(parsed, statement_type=case["statementType"], environment="other-net",
                              graph=case["graph"]) is None   # domain separation holds across runtimes

    # a TS-built, TS-signed report is COUNTED by the Python reader, under the signer's key
    verified = ReportVerifier(NETWORK, GRAPH, today="2026-10-03").verify(_row(from_ts["reportQuads"]))
    assert verified is not None
    assert verified.author == signer_hex and verified.reporter == REPORTER
    assert verified.identifier == "ioc:domain:evil.example"
    assert dict(verified.fields) == {"iocType": "domain", "iocContext": "fetched-by-tool"}
    assert report_signer.REPORT_STATEMENT == "blackbox.report"
