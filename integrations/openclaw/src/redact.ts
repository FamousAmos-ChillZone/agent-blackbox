/**
 * Secret redaction — the OpenClaw runtime's copy of ONE rule set.
 *
 * The canonical rule table lives in the hermes plugin, `kernel/redaction.py`
 * (`SECRET_VALUE_RULES`, the redaction-only shapes, the bearer rule and the
 * secret-assignment rule). This file carries the same rules in the same order
 * with the same markers, and `tests/plugins/test_blackbox_redaction_parity.py`
 * runs generated inputs through BOTH runtimes and fails on any byte of
 * difference (LES-021: one redactor per runtime, a cross-runtime parity test).
 * Change a rule here only together with the Python table.
 *
 * Reports NEVER carry raw content; evidence snippets are always run through
 * this first. Pure, zero deps. Redact BEFORE truncating — a secret cut in half
 * no longer matches (KI-178).
 */

/** Known secret shapes → typed markers. Mirrors `redaction.SECRET_VALUE_RULES`. */
const SECRET_VALUE_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  // The WHOLE private-key block — through its END line, or to the end of the
  // text when the block was cut off — so the key material goes, not just the
  // header line (KI-178).
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g],
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/g],
  ["anthropic-api-key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ["openai-api-key", /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g],
  ["github-token", /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}/g],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{10,}/g],
  ["google-api-key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ["stripe-key", /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}/g],
  ["gcp-service-account-key", /"type"\s*:\s*"service_account"/g],
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g],
];

/** Redaction-only shapes (too broad to be detection signals). Mirrors `_REDACTION_ONLY_RULES`. */
const REDACTION_ONLY_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ["api-key", /\bsk-[A-Za-z0-9_-]{16,}/g],
  ["github-token", /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}/g],
];

const BEARER_RE = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;

// A secret-named key followed by `:` or `=` and a value: `DB_PASSWORD=...`,
// `"api_key": "..."`. The key name stays (it explains the log line); the
// value goes. A value already replaced by a typed marker is kept.
const SECRET_ASSIGNMENT_RE =
  /(\b[A-Za-z0-9_-]*(?:api[_-]?key|token|secret|password|passwd|credential|private[_-]?key|client[_-]?secret|access[_-]?key)[A-Za-z0-9_-]*["']?)(\s*[:=]\s*["']?)([^\s"'[\],;]{8,})/gi;

/** Object KEYS whose whole value is dropped. Mirrors `audit/redaction._SECRET_KEY_RE`. */
const SECRET_KEY_RE =
  /(api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)/i;

function marker(secretType: string): string {
  return `[REDACTED_${secretType.toUpperCase().replace(/-/g, "_")}]`;
}

/**
 * Replace every recognizable secret value in `text` with a marker — the pure
 * rule pass, byte-for-byte the Python `redact_secret_values`. No truncation.
 */
export function redactSecretValues(text: string): string {
  let out = String(text);
  for (const [secretType, pattern] of SECRET_VALUE_RULES) out = out.replace(pattern, marker(secretType));
  for (const [secretType, pattern] of REDACTION_ONLY_RULES) out = out.replace(pattern, marker(secretType));
  out = out.replace(BEARER_RE, "Bearer [REDACTED]");
  return out.replace(SECRET_ASSIGNMENT_RE, "$1$2[REDACTED]");
}

/** Redact, THEN clamp to `maxLength` (never the other way round). */
export function sanitizeText(value: string, maxLength = 2000): string {
  const redacted = redactSecretValues(value);
  return redacted.length > maxLength ? `${redacted.slice(0, maxLength)}...[truncated]` : redacted;
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 5) return "[truncated-depth]";
  if (value == null) return value;
  if (typeof value === "string") return sanitizeText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY_RE.test(key)) {
        out[key] = "[REDACTED]";
      } else if (/^(content|body|fileContent|input|prompt)$/i.test(key) && typeof child === "string") {
        out[key] = sanitizeText(child, 1200);
      } else {
        out[key] = redact(child, depth + 1);
      }
    }
    return out;
  }
  return String(value);
}
