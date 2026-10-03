/**
 * Identifier + quad builders for the Blackbox threat graph.
 *
 * This file is a FAITHFUL port of the canonical Python `plugins/blackbox/kernel/threat_ids.py`
 * (identifiers) and `kernel/rdf_terms.py` (terms) — formerly one `quads.py`
 * (the tested, shipped ground truth). A hermes node and an OpenClaw node that see
 * the same threat MUST compute the same subject URI, otherwise the cross-framework
 * threat-graph flywheel breaks (first-writer-wins on SWM root entities depends on
 * byte-identical identifiers). The contract is pinned by
 * `tests/parity/identifier_fixtures.json` and asserted by `test/parity.mjs`.
 *
 * Zero runtime deps: Node built-ins for sha256 and Java MUTF-8 byte accounting.
 */
import { validateReport } from "./reportSchema.js";
import { REPORT_STATEMENT, type ReportSigner } from "./signing.js";
import { createHash } from "node:crypto";

export type BlackboxSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Severity ladder, lowest → highest. Mirrors constants.SEVERITY_ORDER. */
export const SEVERITY_ORDER: readonly BlackboxSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

export const SEVERITY_RANK: Record<BlackboxSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// --- Ontology IRIs (shared vocabulary; identical to kernel/constants.py) ----------
// The legacy IRI path and `urn:guardian:` schemes below remain byte-stable so
// the already-published corpus stays queryable.
export const BLACKBOX_ONTOLOGY = "http://umanitek.ai/ontology/guardian/";
export const BLACKBOX_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}Threat`;
export const BLACKBOX_DEP_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}VulnerabilityAdvisory`;
export const BLACKBOX_INJECTION_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}PromptInjectionThreat`;
export const BLACKBOX_ESCALATION_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}EscalationThreat`;
export const BLACKBOX_FILE_ACCESS_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}FileAccessThreat`;
export const BLACKBOX_SUSPICIOUS_SKILL_THREAT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}SuspiciousSkillThreat`;
export const BLACKBOX_REPORT_TYPE_IRI = `${BLACKBOX_ONTOLOGY}ThreatReport`;
export const BLACKBOX_IDENTIFIER_PRED = `${BLACKBOX_ONTOLOGY}identifier`;
export const BLACKBOX_CURATED_PRED = `${BLACKBOX_ONTOLOGY}curated`;
export const BLACKBOX_SEVERITY_PRED = `${BLACKBOX_ONTOLOGY}severity`;
export const BLACKBOX_PATTERN_PRED = `${BLACKBOX_ONTOLOGY}pattern`;
export const BLACKBOX_TOOL_NAME_PRED = `${BLACKBOX_ONTOLOGY}toolName`;
export const BLACKBOX_ARG_SHAPE_PRED = `${BLACKBOX_ONTOLOGY}argShape`;
export const BLACKBOX_OWASP_CATEGORY_PRED = `${BLACKBOX_ONTOLOGY}owaspCategory`;
export const BLACKBOX_REPORTS_THREAT_PRED = `${BLACKBOX_ONTOLOGY}reportsThreat`;
export const BLACKBOX_REPORTER_PRED = `${BLACKBOX_ONTOLOGY}reporter`;
export const BLACKBOX_FRAMEWORK_PRED = `${BLACKBOX_ONTOLOGY}framework`;
export const BLACKBOX_PACKAGE_NAME_PRED = `${BLACKBOX_ONTOLOGY}packageName`;
export const BLACKBOX_PACKAGE_VERSION_PRED = `${BLACKBOX_ONTOLOGY}packageVersion`;
export const BLACKBOX_PACKAGE_ECOSYSTEM_PRED = `${BLACKBOX_ONTOLOGY}packageEcosystem`;
// threat kind: distinguishes active malware from a mere vulnerability. Only
// `malware` blocks (at/above block_severity); `vulnerability` always flags but
// never auto-blocks, so a legit-but-vulnerable package isn't stopped.
export const BLACKBOX_KIND_PRED = `${BLACKBOX_ONTOLOGY}kind`;
export const KIND_MALWARE = "malware";
export const KIND_VULNERABILITY = "vulnerability";
// file-access predicates (g:toolName reused; category is new) ---------------
export const BLACKBOX_CATEGORY_PRED = `${BLACKBOX_ONTOLOGY}category`;
// suspicious-skill predicates -----------------------------------------------
export const BLACKBOX_SKILL_NAME_PRED = `${BLACKBOX_ONTOLOGY}skillName`;
export const BLACKBOX_SKILL_VERSION_PRED = `${BLACKBOX_ONTOLOGY}skillVersion`;
export const BLACKBOX_DANGER_SHAPE_PRED = `${BLACKBOX_ONTOLOGY}dangerShape`;
export const BLACKBOX_INJECTION_CONTEXT_PRED = `${BLACKBOX_ONTOLOGY}injectionContext`;
export const BLACKBOX_SKILL_ARTIFACT_HASH_PRED = `${BLACKBOX_ONTOLOGY}skillArtifactHash`;
export const BLACKBOX_SKILL_REGISTRY_PRED = `${BLACKBOX_ONTOLOGY}skillRegistry`;
export const BLACKBOX_IOC_TYPE_PRED = `${BLACKBOX_ONTOLOGY}iocType`;
export const BLACKBOX_IOC_CONTEXT_PRED = `${BLACKBOX_ONTOLOGY}iocContext`;
export const BLACKBOX_REPORT_REASON_PRED = `${BLACKBOX_ONTOLOGY}reportReason`;
export const BLACKBOX_SIGNED_STATEMENT_PRED = `${BLACKBOX_ONTOLOGY}signedStatement`;
// Append-only VM correction vocabulary. Corrections suppress an exact RDF
// subject without mutating the original published knowledge asset.
export const DEFENDER_CORRECTION_TYPE_IRI = "urn:defender:CorrectionSignal";
export const DEFENDER_CORRECTION_TARGET_PRED = "urn:defender:p:targetSubject";
export const DEFENDER_CORRECTION_ACTION_PRED = "urn:defender:p:action";
export const DEFENDER_CORRECTION_SUPPRESS = "suppress";
export const IOC_TYPES = ["domain", "url", "ip", "hash", "wallet", "contract"] as const;

const RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const SCHEMA_NAME = "http://schema.org/name";
const SCHEMA_DESCRIPTION = "http://schema.org/description";
const SCHEMA_DATE_MODIFIED = "http://schema.org/dateModified";
const SCHEMA_IDENTIFIER = "http://schema.org/identifier";
const XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";

export interface Quad {
  subject: string;
  predicate: string;
  object: string;
}

// DKG validates writable RDF literal terms with a 60,000 Java Modified UTF-8
// safe limit across Oxigraph/Blazegraph-compatible paths. Keep OpenClaw's final
// quoted term under the stricter Blackbox cap.
export const DKG_RDF_LITERAL_SAFE_MUTF8_BYTES = 60000;
export const MAX_LITERAL_BYTES = 50000;
const TRUNCATION_MARKER = " ...[truncated]";

// ---------------------------------------------------------------------------
// Hashing / slugs / URIs
// ---------------------------------------------------------------------------

/**
 * SHA-256 hex digest of the RAW UTF-8 bytes of `value`, truncated to `length`.
 *
 * Port of Python `stable_hash`: it hashes the string's raw bytes, NOT a JSON
 * stringification. Do not add quotes / JSON.stringify here — that would diverge
 * from the Python identifiers.
 */
export function stableHash(value: string, length = 24): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, length);
}

/** lowercase, non `[a-z0-9._-]` → `-`, trim leading/trailing dashes, ≤96 chars. */
export function slug(value: string): string {
  const lowered = String(value).toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
  const trimmed = lowered.replace(/^-+|-+$/g, "").slice(0, 96);
  return trimmed || "unknown";
}

export function normalizeSeverity(value: unknown, fallback: BlackboxSeverity = "info"): BlackboxSeverity {
  const raw = String(value ?? "").trim().toLowerCase();
  if (raw === "moderate") return "medium";
  return raw in SEVERITY_RANK ? (raw as BlackboxSeverity) : fallback;
}

/** Stable curated-threat subject URI for a threat `identifier`. */
export function threatUri(identifier: string): string {
  return `urn:guardian:threat:${slug(identifier)}`;
}

/**
 * Per-submitter namespaced report subject URI:
 *   `urn:guardian:report:{addrLower}:{sha256(identifier)[:16]}`
 * where the hash is over the RAW identifier bytes (Python parity).
 */
export const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
/** Mirror of Python `is_agent_address`: the only reporter shape a statement may carry (KI-196). */
export function isAgentAddress(value: unknown): boolean {
  return EVM_ADDRESS_RE.test(String(value ?? "").trim());
}

export function reportUri(identifier: string, agentAddress: string): string {
  if (!isAgentAddress(agentAddress)) throw new Error("a report subject needs a resolved reporter address"); // LES-003 (R0)
  const addr = agentAddress.trim().toLowerCase();
  return `urn:guardian:report:${addr}:${stableHash(identifier, 16)}`;
}

// ---------------------------------------------------------------------------
// Identifier builders
// ---------------------------------------------------------------------------

/** `dep:{ecosystem}:{name}@{version}` — ecosystem + name lowercased/trimmed. */
/** Mirror of Python `canonical_package_name`: lower-case everywhere; PyPI (PEP 503) also
 *  collapses runs of `-_.` to one `-` — other ecosystems are separator-sensitive. */
export function canonicalPackageName(ecosystem: string, name: string): string {
  const canon = name.trim().toLowerCase();
  return ecosystem.trim().toLowerCase() === "pypi" ? canon.replace(/[-_.]+/g, "-") : canon;
}

export function dependencyIdentifier(ecosystem: string, name: string, version: string): string {
  const eco = ecosystem.trim().toLowerCase();
  return `dep:${eco}:${canonicalPackageName(eco, name)}@${version.trim()}`;
}

/** `skill:artifact:{sha256}:{shape}` — a local/unknown skill named by its code hash, never its name (KI-159). */
export function skillArtifactIdentifier(artifactHash: string, dangerShape: string): string {
  return `skill:artifact:${artifactHash.trim().toLowerCase()}:${dangerShape.trim().toLowerCase()}`;
}

/** `injection:{sha256(pattern)[:24]}` — hashes the RAW pattern bytes. */
export function injectionIdentifier(pattern: string): string {
  return `injection:${stableHash(pattern, 24)}`;
}

/**
 * `escalation:{tool}:{argShape}` — human-readable, single colon, shape NOT hashed.
 * The shape is kept literal so the id is legible, e.g.
 * `escalation:shell:remote-script-pipe`.
 */
export function escalationIdentifier(toolName: string, argShape: string): string {
  return `escalation:${toolName.trim().toLowerCase()}:${argShape.trim()}`;
}

/**
 * `fileaccess:{tool}:{category}` — e.g. `fileaccess:read_file:ssh-private-key`.
 * Both parts kept literal (lowercased+trimmed) so the id is legible and two
 * nodes touching the same sensitive-path category converge on one threat KA.
 */
export function fileaccessIdentifierFor(toolName: string, category: string): string {
  return `fileaccess:${toolName.trim().toLowerCase()}:${category.trim().toLowerCase()}`;
}

/** `skill:{name}@{version}` — the known-bad (graph-matched) skill id. */
export function skillVersionIdentifierFor(name: string, version: string): string {
  return `skill:${name.trim().toLowerCase()}@${version.trim()}`;
}

/** `skill:{name}:{dangerShape}` — a heuristic dangerous-code/permission id. */
export function skillShapeIdentifierFor(name: string, dangerShape: string): string {
  return `skill:${name.trim().toLowerCase()}:${dangerShape.trim()}`;
}

/** Canonicalize an IOC value exactly like Python `normalize_ioc_value`. */
/** Mirror of Python `threat_ids._canonical_ip` (KI-193): IPv4 `a.b.c.d[:port]` → `a.b.c.d`;
 *  IPv6 (two or more colons) → RFC 5952 compressed lower-case form, accepting `[addr]:port`
 *  and a `%zone` suffix; an unparseable value is returned verbatim so the grammar refuses it. */
export function canonicalIp(raw: string): string {
  if ((raw.match(/:/g) || []).length < 2) return raw.split(":", 1)[0];
  let candidate = raw;
  if (candidate.startsWith("[")) candidate = candidate.slice(1).split("]", 1)[0];
  candidate = candidate.split("%", 1)[0].toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(candidate) || candidate.includes(":::")) return raw;
  const halves = candidate.split("::");
  if (halves.length > 2) return raw;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const groups = [...head, ...tail];
  // embedded IPv4 tail (::ffff:1.2.3.4) → two hex groups, as Python's ipaddress does
  const last = groups[groups.length - 1];
  if (last && last.includes(".")) {
    const octets = last.split(".").map((o) => Number(o));
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return raw;
    groups.splice(groups.length - 1, 1, ((octets[0] << 8) | octets[1]).toString(16), ((octets[2] << 8) | octets[3]).toString(16));
    if (halves.length === 2 && halves[1]) tail.splice(tail.length - 1, 1, groups[groups.length - 2], groups[groups.length - 1]);
  }
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return raw;
  const missing = 8 - groups.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return raw;
  const headGroups = halves.length === 2 ? head : groups;
  const full = halves.length === 2 ? [...headGroups, ...Array(missing).fill("0"), ...tail.map((g) => g)] : groups;
  const words = full.map((g) => parseInt(g, 16));
  // RFC 5952: shorten the longest run of zero words (length ≥ 2), leftmost on ties
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < words.length; ) {
    if (words[i] !== 0) { i++; continue; }
    let j = i;
    while (j < words.length && words[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = words.map((w) => w.toString(16));
  if (bestLen < 2) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

export function normalizeIocValue(iocType: string, value: string): string {
  const type = (iocType || "").trim().toLowerCase();
  let raw = String(value || "").trim();
  if (!raw) return "";
  if (type === "domain") return raw.replace(/\.+$/, "").toLowerCase();
  if (type === "url") {
    const parts = raw.split("://", 2);
    if (parts.length === 2) {
      const slash = parts[1].indexOf("/");
      const host = (slash >= 0 ? parts[1].slice(0, slash) : parts[1]).toLowerCase();
      const rest = slash >= 0 ? parts[1].slice(slash) : "";
      raw = `${parts[0].toLowerCase()}://${host}${rest}`;
    }
    return raw.replace(/\/+$/, "");
  }
  if (type === "ip") return canonicalIp(raw);
  if (type === "hash") return raw.toLowerCase();
  if (type === "wallet" || type === "contract") {
    return /^0x[a-fA-F0-9]{40}$/.test(raw) ? raw.toLowerCase() : raw;
  }
  return raw;
}

/** `ioc:{type}:{normalized-value}` — shared by Hermes and OpenClaw. */
const HOST_SHAPE = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.){1,16}[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?";
const IPV4_SHAPE = "(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)";
const IOC_VALUE_SHAPES: Record<string, RegExp> = {
  domain: new RegExp(`^${HOST_SHAPE}$`),
  url: new RegExp(`^https?://(?:${HOST_SHAPE}|${IPV4_SHAPE})(?::\\d{1,5})?(?:[/?#][^\\s<>"'\`\\\\^{}|\\[\\]]*)?$`),
  ip: new RegExp(`^${IPV4_SHAPE}$`),
  hash: /^[a-f0-9]{32,128}$/,
  wallet: /^[A-Za-z0-9]{20,128}$/,
  contract: /^[A-Za-z0-9]{20,128}$/,
};
export const MAX_IOC_VALUE_CHARS = 2048;

/** Mirror of Python `ioc_value_is_well_formed`: whether a CANONICAL value has the shape its type
 *  allows (§07 grammar). IPv6 is accepted only in its one canonical spelling (KI-193). */
export function iocValueIsWellFormed(iocType: string, value: string): boolean {
  const kind = (iocType || "").trim().toLowerCase();
  const shape = IOC_VALUE_SHAPES[kind];
  if (!shape || !value || value.length > MAX_IOC_VALUE_CHARS) return false;
  if (kind === "ip" && value.includes(":")) return canonicalIp(value) === value && /^[0-9a-f:]+$/.test(value);
  if (kind === "domain" && value.length > 253) return false;
  return shape.test(value);
}

export function iocIdentifier(iocType: string, value: string): string {
  const type = (iocType || "").trim().toLowerCase();
  return `ioc:${type}:${normalizeIocValue(type, value)}`;
}

/**
 * The threat identifier string. Faithful to Python's identifier builders.
 *   dependency    -> `dep:{ecosystem}:{name}@{version}`   (eco+name lowercased+trimmed)
 *   injection     -> `injection:{sha256(pattern_raw)[:24]}`
 *   escalation    -> `escalation:{toolName}:{argShape}`    (tool lowercased, shape literal)
 *   fileaccess    -> `fileaccess:{toolName}:{category}`    (both lowercased+trimmed)
 *   skill_version -> `skill:{name}@{version}`              (name lowercased, version literal)
 *   skill_shape   -> `skill:{name}:{dangerShape}`          (name lowercased, shape literal)
 */
export function threatIdentifierFor(
  args:
    | { type: "dependency"; ecosystem: string; name: string; version: string }
    | { type: "injection"; pattern: string }
    | { type: "escalation"; toolName: string; argShape: string }
    | { type: "fileaccess"; toolName: string; category: string }
    | { type: "skill_version"; name: string; version: string }
    | { type: "skill_shape"; name: string; dangerShape: string },
): string {
  if (args.type === "dependency") {
    return dependencyIdentifier(args.ecosystem, args.name, args.version);
  }
  if (args.type === "injection") {
    return injectionIdentifier(args.pattern);
  }
  if (args.type === "fileaccess") {
    return fileaccessIdentifierFor(args.toolName, args.category);
  }
  if (args.type === "skill_version") {
    return skillVersionIdentifierFor(args.name, args.version);
  }
  if (args.type === "skill_shape") {
    return skillShapeIdentifierFor(args.name, args.dangerShape);
  }
  return escalationIdentifier(args.toolName, args.argShape);
}

// ---------------------------------------------------------------------------
// N-Triples term escaping
// ---------------------------------------------------------------------------

function q(subject: string, predicate: string, object: string): Quad {
  return { subject, predicate, object };
}

/** Render an IRI term (bare, per the daemon's quad object convention). */
export function iri(value: string): string {
  return value;
}

/**
 * Render a plain-string literal term with N-Triples escaping.
 * Matches Python `literal`: escapes backslash, doublequote, \n, \r, \t (all five).
 */
export function literal(value: string): string {
  return literalTermForValue(capLiteralValue(String(value)));
}

export function javaModifiedUtf8ByteLength(value: string): number {
  let bytes = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0) bytes += 2;
    else if (code <= 0x7f) bytes += 1;
    else if (code <= 0x07ff) bytes += 2;
    else bytes += 3;
  }
  return bytes;
}

function escapeLiteralText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

function literalTermForValue(value: string): string {
  return `"${escapeLiteralText(value)}"`;
}

function literalValueTermMutf8Bytes(value: string): number {
  return javaModifiedUtf8ByteLength(literalTermForValue(value));
}

function capLiteralValue(value: string): string {
  if (literalValueTermMutf8Bytes(value) <= MAX_LITERAL_BYTES) return value;
  const chars = Array.from(value);
  let lo = 0;
  let hi = chars.length;
  let best = TRUNCATION_MARKER;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    const candidate = `${chars.slice(0, mid).join("")}${TRUNCATION_MARKER}`;
    if (literalValueTermMutf8Bytes(candidate) <= MAX_LITERAL_BYTES) {
      best = candidate;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

/** Render an `xsd:dateTime` typed literal (UTC ISO-8601 with `Z`). */
export function datetimeLiteral(ts?: number): string {
  const iso = new Date(ts ?? Date.now()).toISOString(); // always UTC, ends in Z
  return `${literal(iso)}^^${XSD_DATETIME}`;
}

export interface ReportInput {
  identifier: string;
  category: "injection" | "escalation" | "dependency" | "fileaccess" | "skill" | "ioc";
  severity: BlackboxSeverity;
  /** Reporter agent address (0x + 40 hex) — refused otherwise (LES-003). Lower-cased for the URI. */
  reporter: string;
  framework: "hermes" | "openclaw";
  /** Epoch ms; rounded to the UTC day (decision 25). */
  ts?: number;
  /** R1 evidence, Python keyword names (`context`, `tool_name`, `package_name`, `ioc_type`, …). */
  evidence?: Record<string, string | undefined | null>;
  /** With a signer the report carries its signed envelope (R0b); without one it is unsigned and no reader counts it. */
  signer?: ReportSigner;
}

/** The evidence a report may carry per category — ONE table mirroring Python `_EVIDENCE_FIELDS`
 *  (keyword, predicate) in emission order. */
const EVIDENCE_FIELDS: Record<string, ReadonlyArray<readonly [string, string]>> = {
  injection: [["context", BLACKBOX_INJECTION_CONTEXT_PRED], ["owasp_category", BLACKBOX_OWASP_CATEGORY_PRED]],
  escalation: [["tool_name", BLACKBOX_TOOL_NAME_PRED], ["arg_shape", BLACKBOX_ARG_SHAPE_PRED]],
  dependency: [
    ["package_name", BLACKBOX_PACKAGE_NAME_PRED], ["package_version", BLACKBOX_PACKAGE_VERSION_PRED],
    ["ecosystem", BLACKBOX_PACKAGE_ECOSYSTEM_PRED], ["advisory_id", SCHEMA_IDENTIFIER],
    ["kind", BLACKBOX_KIND_PRED], ["reason", BLACKBOX_REPORT_REASON_PRED],
  ],
  fileaccess: [["tool_name", BLACKBOX_TOOL_NAME_PRED], ["file_category", BLACKBOX_CATEGORY_PRED]],
  skill: [
    ["artifact_hash", BLACKBOX_SKILL_ARTIFACT_HASH_PRED], ["registry", BLACKBOX_SKILL_REGISTRY_PRED],
    ["skill_name", BLACKBOX_SKILL_NAME_PRED], ["skill_version", BLACKBOX_SKILL_VERSION_PRED], ["danger_shape", BLACKBOX_DANGER_SHAPE_PRED],
  ],
  ioc: [["ioc_type", BLACKBOX_IOC_TYPE_PRED], ["ioc_context", BLACKBOX_IOC_CONTEXT_PRED]],
};

/** Midnight UTC of the report's day, as Python's `datetime_literal(_day(ts))` renders it: `YYYY-MM-DDT00:00:00Z`. */
export function dayLiteral(ts?: number): { day: string; literal: string } {
  const day = new Date(ts ?? Date.now()).toISOString().slice(0, 10);
  return { day, literal: `${literal(`${day}T00:00:00Z`)}^^${XSD_DATETIME}` };
}

/**
 * Build the community report for one finding — faithful port of Python
 * `build_report_quads` (Refine R1 + R0b). Only from a VALIDATED record: a bad
 * report throws `ReportValidationError` and is never built. Reports NEVER carry
 * observed prompt/command text; the timestamp is the day only; with a signer
 * the report carries a signed envelope over its fields.
 *
 * IRIs (the rdf:type object and reportsThreat object) are emitted BARE — Python
 * `iri()` returns the value with no angle brackets.
 */
export function buildReportQuads(input: ReportInput): Quad[] {
  const record = validateReport({ identifier: input.identifier, category: input.category, severity: input.severity,
                                  framework: input.framework, evidence: input.evidence ?? {} });
  const subj = reportUri(record.identifier, input.reporter);
  const threat = threatUri(record.identifier);
  const reporter = input.reporter.trim().toLowerCase();
  const { day, literal: dayLit } = dayLiteral(input.ts);
  const values = Object.fromEntries(record.evidence);
  const fields = (EVIDENCE_FIELDS[record.category] ?? []).filter(([name]) => name in values).map(([name, pred]) => [name, pred, values[name]] as const);
  const out: Quad[] = [
    q(subj, RDF_TYPE, iri(BLACKBOX_REPORT_TYPE_IRI)),
    q(subj, BLACKBOX_REPORTS_THREAT_PRED, iri(threat)),
    q(subj, BLACKBOX_IDENTIFIER_PRED, literal(record.identifier)),
    q(subj, BLACKBOX_REPORTER_PRED, literal(reporter)),
    q(subj, BLACKBOX_FRAMEWORK_PRED, literal(record.framework)),
    q(subj, BLACKBOX_SEVERITY_PRED, literal(record.severity)),
    q(subj, SCHEMA_DATE_MODIFIED, dayLit),
  ];
  for (const [, pred, value] of fields) out.push(q(subj, pred, literal(value)));
  if (input.signer) {
    const payload: Record<string, string> = { subject: subj, identifier: record.identifier, category: record.category,
      severity: record.severity, reporter, framework: record.framework, day };
    for (const [name, , value] of fields) payload[name] = value;
    out.push(q(subj, BLACKBOX_SIGNED_STATEMENT_PRED, literal(input.signer.sign(REPORT_STATEMENT, payload))));
  }
  return out;
}

export { RDF_TYPE, SCHEMA_NAME, SCHEMA_DESCRIPTION, SCHEMA_DATE_MODIFIED, SCHEMA_IDENTIFIER, XSD_DATETIME };
