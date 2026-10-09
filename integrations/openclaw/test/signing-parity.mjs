/**
 * Cross-runtime SIGNING parity — the TypeScript half (Refine R0b, KI-182).
 *
 * argv[2]: a PKCS#8 PEM file holding an Ed25519 key the Python test generated at
 * runtime (no key material lives in the repo — LES-022); argv[3]: a JSON array of
 * cases `{statementType, environment, graph, payload}`. Prints, per case, the
 * serialized envelope and the hex of the exact bytes that were signed, so
 * `tests/plugins/test_blackbox_signing_parity.py` can verify each envelope with
 * `kernel.signing.verify` and compare the signed bytes with `_signed_message`.
 * Also builds one full signed report so Python's `ReportVerifier` can count it.
 */
import { readFileSync } from "node:fs";
import { createPrivateKey } from "node:crypto";

import { ReportSigner, signEnvelope, signedMessage } from "../src/signing.ts";
import { buildReportQuads } from "../src/quads.ts";

const key = createPrivateKey(readFileSync(process.argv[2]));
const { cases, report } = JSON.parse(readFileSync(process.argv[3], "utf8"));
const out = cases.map((c) => ({
  envelope: signEnvelope(key, { statementType: c.statementType, environment: c.environment, graph: c.graph }, c.payload),
  messageHex: signedMessage({ statementType: c.statementType, environment: c.environment, graph: c.graph }, c.payload).toString("hex"),
}));
const signer = new ReportSigner(key, report.environment, report.graph);
const quads = buildReportQuads({ ...report.input, signer, ts: Date.parse(report.day + "T12:00:00Z") });
process.stdout.write(JSON.stringify({ cases: out, reportQuads: quads }));
