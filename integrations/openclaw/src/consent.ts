/**
 * Sharing gate — TypeScript mirror of `plugins/blackbox/community/consent.py`.
 *
 * Community sharing is ON BY DEFAULT with an easy opt-out (2026-10-12; it was
 * opt-in). `${blackboxHome}/sharing_consent.json` matters only when it records
 * an opt-out (`withdrawn_at`); no record means the default, sharing allowed.
 * This module only READS the record (`blackbox report --withdraw-consent` and the
 * dashboard toggle write it). An unreadable or malformed record reads as no
 * record, exactly as in Python.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

const RECORD_FILE = "sharing_consent.json";

/** True unless the operator opted out (a record with `withdrawn_at`). */
export function sharingConsentInForce(blackboxHome: string): boolean {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readFileSync(join(blackboxHome, RECORD_FILE), "utf8")) as Record<string, unknown>;
  } catch {
    return true;   // no record (or unreadable): the default, sharing allowed
  }
  return !(raw && typeof raw === "object" && raw.withdrawn_at);
}
