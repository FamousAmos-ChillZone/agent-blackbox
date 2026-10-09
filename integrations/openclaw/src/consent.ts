/**
 * Sharing consent — TypeScript mirror of `plugins/blackbox/community/consent.py` (Refine R13).
 *
 * Nothing leaves a machine without a consent record bound to the CONTENT of the
 * reporter terms: `${blackboxHome}/sharing_consent.json` holds the sha256 of
 * REPORTER_TERMS.md the operator accepted; a changed text, a withdrawal, or a
 * missing terms file all mean "no consent". This module only READS the record
 * (`blackbox report --consent` writes it); fail closed on every error.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const RECORD_FILE = "sharing_consent.json";
const here = dirname(fileURLToPath(import.meta.url));

/** Where the shipped terms live, by layout: env override, the bundled `_openclaw/` copy
 *  inside the plugin (`../../docs`), or the repository (`plugins/blackbox/docs`). */
export function termsPathCandidates(): string[] {
  const out: string[] = [];
  if (process.env.BLACKBOX_REPORTER_TERMS) out.push(process.env.BLACKBOX_REPORTER_TERMS);
  out.push(join(here, "..", "..", "docs", "REPORTER_TERMS.md"));
  out.push(join(here, "..", "..", "..", "plugins", "blackbox", "docs", "REPORTER_TERMS.md"));
  return out;
}

export function termsText(): string {
  for (const path of termsPathCandidates()) {
    try {
      if (existsSync(path)) return readFileSync(path, "utf8");
    } catch {
      /* try the next candidate */
    }
  }
  return "";
}

export function termsHash(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** True only with a record bound to the CURRENT terms and not withdrawn. */
export function sharingConsentInForce(blackboxHome: string): boolean {
  const text = termsText();
  if (!text) return false;
  try {
    const raw = JSON.parse(readFileSync(join(blackboxHome, RECORD_FILE), "utf8")) as Record<string, unknown>;
    return !raw.withdrawn_at && raw.terms_hash === termsHash(text);
  } catch {
    return false;
  }
}
