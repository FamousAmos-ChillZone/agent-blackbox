/**
 * The report schema — TypeScript mirror of `plugins/blackbox/community/report_schema.py`
 * (Refine R1, plan §04): a closed shape per category, closed vocabularies, and
 * `ingest refuses, never repairs`. A report that fails here is never built and
 * never leaves the machine. Pattern: Factory (`validateReport`) + a Strategy
 * table of per-category validators, as in Python.
 *
 * Usage:
 *   const record = validateReport({ identifier, category: "ioc", severity: "high",
 *                                   framework: "openclaw", evidence: { ioc_type: "domain", ioc_context: "fetched-by-tool" } });
 *   // record.evidence: [name, value][] sorted — what the builder emits and the signer signs
 */
import { ESCALATION_SHAPES, SENSITIVE_PATH_CATEGORIES, SHELL_TOOLS, SKILL_DANGER_SHAPES } from "./detection.js";
import { canonicalPackageName, dependencyIdentifier, escalationIdentifier, fileaccessIdentifierFor, iocIdentifier,
         iocValueIsWellFormed, skillArtifactIdentifier, skillVersionIdentifierFor } from "./quads.js";

export const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"] as const;
export const REPORT_FRAMEWORKS = ["hermes", "openclaw"] as const;
export const INJECTION_CONTEXTS = ["in-fetched-page", "in-tool-output", "in-user-prompt", "in-skill"] as const;
export const IOC_CONTEXTS = ["fetched-by-tool", "in-prompt", "in-tool-output", "in-dependency", "in-skill"] as const;
export const DEPENDENCY_REASONS = ["typosquat", "install-hook", "exfil", "internal-mirror-collision"] as const;
export const WHOLE_PACKAGE_REASONS = ["typosquat", "internal-mirror-collision"] as const;
export const ADVISORY_REASON_PREFIX = "advisory:";
export const SKILL_REGISTRIES = ["mcp-registry", "clawhub", "npm", "pypi", "oci", "mcpb"] as const;
export const DEPENDENCY_ECOSYSTEMS = ["npm", "pypi", "cargo", "rubygems"] as const;
export const IOC_TYPES = ["domain", "url", "ip", "hash", "wallet", "contract"] as const;
export const OWASP_LLM_CATEGORIES = Array.from({ length: 10 }, (_, i) => `LLM${String(i + 1).padStart(2, "0")}`);
export const KIND_MALWARE = "malware";
export const MAX_IDENTIFIER_CHARS = 512;
export const MAX_VALUE_CHARS = 128;
const SAFE_TOKEN = /^[A-Za-z0-9._@:/+~-]+$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const INJECTION_ID = /^injection:[a-z0-9][a-z0-9._-]{0,63}$/;
// Unicode Cc + Cf (control and format characters) — Python `display_safety.strip_controls`.
const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;

export class ReportValidationError extends Error {}

export interface ReportRecord {
  identifier: string;
  category: string;
  severity: string;
  framework: string;
  /** (builder keyword, value) pairs, sorted — only keys the category allows, every value checked. */
  evidence: Array<[string, string]>;
}

type Evidence = Record<string, string>;
type Validated = [string | null, Evidence];

function fail(message: string): never {
  throw new ReportValidationError(message);
}

function token(name: string, value: string | undefined, required = true): string {
  const text = String(value ?? "").trim();
  if (!text) {
    if (required) fail(`${name} is required`);
    return "";
  }
  if (text.length > MAX_VALUE_CHARS || !SAFE_TOKEN.test(text)) fail(`${name} must be a short token without spaces or control characters`);
  return text;
}

function oneOf(name: string, value: string | undefined, allowed: Iterable<string>): string {
  const text = String(value ?? "").trim().toLowerCase();
  const set = new Set([...allowed].map((a) => a.toLowerCase()));
  if (!set.has(text)) fail(`${name} must be one of: ${[...set].sort().join(", ")}`);
  return text;
}

function injection(ev: Evidence): Validated {
  const out: Evidence = { context: oneOf("context", ev.context, INJECTION_CONTEXTS) };
  if (ev.owasp_category) out.owasp_category = oneOf("owasp_category", ev.owasp_category, OWASP_LLM_CATEGORIES).toUpperCase();
  return [null, out];
}

function escalation(ev: Evidence): Validated {
  const tool = oneOf("tool_name", ev.tool_name, SHELL_TOOLS);
  const shape = oneOf("arg_shape", ev.arg_shape, ESCALATION_SHAPES);
  return [escalationIdentifier(tool, shape), { tool_name: tool, arg_shape: shape }];
}

function dependencyReason(ev: Evidence): [string, string] {
  const reason = String(ev.reason ?? "").trim();
  const advisory = token("advisory_id", ev.advisory_id, false);
  if (reason.toLowerCase().startsWith(ADVISORY_REASON_PREFIX)) {
    const cited = token("advisory id in reason", reason.slice(ADVISORY_REASON_PREFIX.length));
    if (advisory && advisory !== cited) fail("the reason's advisory and advisory_id differ");
    return [ADVISORY_REASON_PREFIX + cited, cited];
  }
  return [oneOf("reason", reason, [...DEPENDENCY_REASONS, `${ADVISORY_REASON_PREFIX}<id>`]), advisory];
}

function dependency(ev: Evidence): Validated {
  const eco = oneOf("ecosystem", ev.ecosystem, DEPENDENCY_ECOSYSTEMS);
  const name = canonicalPackageName(eco, token("package_name", ev.package_name));
  if (String(ev.kind ?? "").toLowerCase() !== KIND_MALWARE) fail("a dependency report must be kind=malware (vulnerabilities stay local — decision 22)");
  const [reason, advisory] = dependencyReason(ev);
  let version = String(ev.package_version ?? "").trim();
  if (version === "*") {
    if (!(WHOLE_PACKAGE_REASONS as readonly string[]).includes(reason)) fail(`a whole-package (*) report needs reason ${WHOLE_PACKAGE_REASONS.join(" or ")}`);
  } else {
    version = token("package_version", version);
  }
  const out: Evidence = { ecosystem: eco, package_name: name, package_version: version, kind: KIND_MALWARE, reason };
  if (advisory) out.advisory_id = advisory;
  return [dependencyIdentifier(eco, name, version), out];
}

function fileaccess(ev: Evidence): Validated {
  const tool = token("tool_name", ev.tool_name).toLowerCase();
  const category = oneOf("file_category", ev.file_category, SENSITIVE_PATH_CATEGORIES);
  return [fileaccessIdentifierFor(tool, category), { tool_name: tool, file_category: category }];
}

function skill(ev: Evidence): Validated {
  if (ev.artifact_hash || ev.danger_shape) {
    if (ev.skill_name || ev.skill_version || ev.registry) fail("a local skill is reported by artifact hash + danger shape, never by name or version (KI-159)");
    const digest = String(ev.artifact_hash ?? "").trim().toLowerCase();
    if (!SHA256_HEX.test(digest)) fail("artifact_hash must be the sha256 hex of the skill's code");
    const shape = oneOf("danger_shape", ev.danger_shape, SKILL_DANGER_SHAPES);
    return [skillArtifactIdentifier(digest, shape), { artifact_hash: digest, danger_shape: shape }];
  }
  const registry = oneOf("registry", ev.registry, SKILL_REGISTRIES);
  const name = token("skill_name", ev.skill_name);
  const version = token("skill_version", ev.skill_version);
  return [skillVersionIdentifierFor(name, version), { registry, skill_name: name, skill_version: version }];
}

function ioc(ev: Evidence): Validated {
  return [null, { ioc_type: oneOf("ioc_type", ev.ioc_type, IOC_TYPES), ioc_context: oneOf("ioc_context", ev.ioc_context, IOC_CONTEXTS) }];
}

const VALIDATORS: Record<string, (ev: Evidence) => Validated> = { injection, escalation, dependency, fileaccess, skill, ioc };

function isCleanToken(identifier: string): boolean {
  return Boolean(identifier) && identifier.length <= MAX_IDENTIFIER_CHARS && !identifier.includes(" ") && !CONTROL_OR_FORMAT.test(identifier);
}

function checkIdentifier(category: string, identifier: string, derived: string | null, evidence: Evidence): void {
  if (!isCleanToken(identifier)) fail("identifier must be a short single token without control or format characters");
  if (derived !== null && identifier !== derived) fail(`identifier does not match its fields (expected ${derived})`);
  if (category === "injection" && !INJECTION_ID.test(identifier)) fail("an injection identifier is a slug (injection:<pattern hash or corpus id>), never free text");
  if (category === "ioc") {
    const prefix = `ioc:${evidence.ioc_type}:`;
    const value = identifier.startsWith(prefix) ? identifier.slice(prefix.length) : "";
    if (!value || iocIdentifier(evidence.ioc_type, value) !== identifier) fail("an ioc identifier must be the canonical ioc:<type>:<value>");
    if (!iocValueIsWellFormed(evidence.ioc_type, value)) fail(`the ${evidence.ioc_type} value does not have the shape that type allows`);
  }
}

export interface ReportInput {
  identifier: string;
  category: string;
  severity: string;
  framework: string;
  evidence: Record<string, string | undefined | null>;
}

/** The validated record for one report, or `ReportValidationError`. */
export function validateReport(input: ReportInput): ReportRecord {
  const validator = VALIDATORS[input.category];
  if (!validator) fail(`category must be one of: ${Object.keys(VALIDATORS).sort().join(", ")}`);
  const severity = String(input.severity ?? "").trim().toLowerCase();
  if (!(SEVERITY_ORDER as readonly string[]).includes(severity)) fail(`severity must be one of: ${SEVERITY_ORDER.join(", ")}`);
  const framework = oneOf("framework", input.framework, REPORT_FRAMEWORKS);
  const given: Evidence = {};
  for (const [k, v] of Object.entries(input.evidence)) if (v !== undefined && v !== null && v !== "") given[k] = String(v);
  const [derived, out] = validator(given);
  const unknown = Object.keys(given).filter((k) => !(k in out)).sort();
  if (unknown.length) fail(`fields not allowed in a ${input.category} report: ${unknown.join(", ")}`);
  const identifier = String(input.identifier ?? "").trim();
  checkIdentifier(input.category, identifier, derived, out);
  return { identifier, category: input.category, severity, framework,
           evidence: Object.entries(out).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)) };
}
