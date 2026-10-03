/**
 * The bridge's REPORT path, SDK-free (imports only quads/reportSchema/reportEvidence/signing —
 * `parity.mjs` needs the OpenClaw SDK, which a plain checkout lacks). Asserts:
 *   1. buildReportQuads reproduces the Python fixture's report quads byte-for-byte (R1 shape);
 *   2. the schema REFUSES what Python refuses (bad context, vulnerability kind, named local skill, bad reporter);
 *   3. evidenceFor assigns the context from the hook, never from the text;
 *   4. a signed report carries a verifiable envelope over its fields.
 * Run: npx tsx integrations/openclaw/test/report.mjs      (exits non-zero on any failure)
 */
import { readFileSync } from "node:fs";
import { generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildReportQuads, BLACKBOX_SIGNED_STATEMENT_PRED, isAgentAddress } from "../src/quads.ts";
import { ReportValidationError, validateReport } from "../src/reportSchema.ts";
import { evidenceFor } from "../src/reportEvidence.ts";
import { ReportSigner, publicKeyHex, signedMessage } from "../src/signing.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(join(here, "..", "..", "..", "tests", "parity", "identifier_fixtures.json"), "utf8"));
const DATE_MODIFIED = "http://schema.org/dateModified";
const sortQuads = (quads) => [...quads].filter((q) => q.predicate !== DATE_MODIFIED)
  .sort((a, b) => (a.predicate < b.predicate ? -1 : a.predicate > b.predicate ? 1 : a.object < b.object ? -1 : a.object > b.object ? 1 : 0));
let failures = 0;
const check = (name, ok, detail = "") => { console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `\n    ${detail}`}`); if (!ok) failures++; };

// 1. fixture parity (unsigned)
for (const c of fixture.reportQuads) {
  const { identifier, category, severity, reporter_address, framework, ...evidence } = c.in;
  const got = JSON.stringify(sortQuads(buildReportQuads({ identifier, category, severity, reporter: reporter_address, framework, evidence })));
  const want = JSON.stringify(sortQuads(c.quadsNoDate));
  check(`reportQuads parity: ${identifier}`, got === want, `got ${got}\n    want ${want}`);
}

// 2. refusals mirror Python
const refuses = (name, input) => { try { validateReport(input); check(name, false, "was accepted"); } catch (e) { check(name, e instanceof ReportValidationError, String(e)); } };
const addr = "0x" + "a".repeat(40);
refuses("injection without a context stays local", { identifier: "injection:abc123", category: "injection", severity: "high", framework: "openclaw", evidence: {} });
refuses("a vulnerability dependency never leaves", { identifier: "dep:npm:x@1", category: "dependency", severity: "high", framework: "openclaw", evidence: { ecosystem: "npm", package_name: "x", package_version: "1", kind: "vulnerability", reason: "advisory:GHSA-1" } });
refuses("a local skill is never named", { identifier: "skill:foo@1", category: "skill", severity: "high", framework: "openclaw", evidence: { skill_name: "foo", skill_version: "1", danger_shape: "shell-exec", artifact_hash: "0".repeat(64) } });
refuses("ioc value must be canonical", { identifier: "ioc:domain:Evil.Example", category: "ioc", severity: "high", framework: "openclaw", evidence: { ioc_type: "domain", ioc_context: "fetched-by-tool" } });
let threw = false; try { buildReportQuads({ identifier: "ioc:domain:evil.example", category: "ioc", severity: "high", reporter: "node", framework: "openclaw", evidence: { ioc_type: "domain", ioc_context: "fetched-by-tool" } }); } catch { threw = true; }
check("a fallback reporter identity is refused (LES-003)", threw && !isAgentAddress("anonymous"));

// 3. context comes from the hook
const inj = { identifier: "injection:abc", category: "injection", severity: "high", title: "", toolName: null, matched: "", evidence: "", confirmed: false, source: "public", fields: { pattern: "ignore previous", owaspCategory: "LLM01" } };
check("tool output of a web tool → in-fetched-page", evidenceFor(inj, "post_tool_call", "web_fetch").context === "in-fetched-page");
check("tool output elsewhere → in-tool-output", evidenceFor(inj, "post_tool_call", "read_file").context === "in-tool-output");
check("user text → in-user-prompt", evidenceFor(inj, "message_received").context === "in-user-prompt");
check("tool-call arguments → no injection context (stays local)", evidenceFor(inj, "before_tool_call", "terminal").context === undefined);
check("the pattern text never becomes evidence", !("pattern" in evidenceFor(inj, "post_tool_call", "web_fetch")));
const ioc = { ...inj, identifier: "ioc:domain:evil.example", category: "ioc", fields: { iocType: "domain" } };
check("an IOC in a fetch tool's output → fetched-by-tool", evidenceFor(ioc, "post_tool_call", "browser_open").ioc_context === "fetched-by-tool");

// 4. signed envelope verifies with the public key, over exactly the signed message
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = new ReportSigner(privateKey, "net-1", "0xowner/community");
const quads = buildReportQuads({ identifier: "ioc:domain:evil.example", category: "ioc", severity: "high", reporter: addr, framework: "openclaw", evidence: { ioc_type: "domain", ioc_context: "fetched-by-tool" }, signer, ts: Date.UTC(2026, 9, 3, 12, 0, 0) });
const envelopeTerm = quads.find((q) => q.predicate === BLACKBOX_SIGNED_STATEMENT_PRED)?.object ?? "";
const envelope = JSON.parse(JSON.parse(envelopeTerm.replace(/\\"/g, '"').replace(/^"|"$/g, "").replace(/\\\\/g, "\\")) === undefined ? "{}" : envelopeTerm.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\"));
check("envelope names the signer by raw public key hex", envelope.sigs?.[0]?.signer === publicKeyHex(privateKey));
check("envelope payload day is the UTC day", envelope.payload?.day === "2026-10-03");
const { sigs, ...domainDoc } = envelope;
const msg = signedMessage({ statementType: domainDoc.type, environment: domainDoc.env, graph: domainDoc.graph, chain: domainDoc.chain, rootEpoch: domainDoc.epoch, sequence: domainDoc.seq, schemaVersion: domainDoc.schema }, domainDoc.payload);
check("signature verifies over the canonical bytes", cryptoVerify(null, msg, publicKey, Buffer.from(sigs[0].sig, "hex")));
check("the day literal has no milliseconds", quads.some((q) => q.predicate === DATE_MODIFIED && q.object.includes("T00:00:00Z")));

console.log(failures ? `\n${failures} FAILED` : "\nall ok");
process.exit(failures ? 1 : 0);
