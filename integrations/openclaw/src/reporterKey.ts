/**
 * The reporter key — TypeScript mirror of `plugins/blackbox/kernel/reporter_key.py`.
 *
 * One Ed25519 key per Blackbox home, `${blackboxHome}/reporter_key.pem` (PKCS#8,
 * unencrypted, owner-only 0600), created on first use. Both runtimes read the
 * SAME file, so a machine that runs Hermes and OpenClaw reports under one
 * identity — point both at one `blackboxHome`. Creation is atomic (temp file
 * with 0600 from the first byte, then rename).
 */
import { generateKeyPairSync, createPrivateKey, type KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const REPORTER_KEY_FILE = "reporter_key.pem";

export function reporterKeyPath(blackboxHome: string): string {
  return join(blackboxHome, REPORTER_KEY_FILE);
}

/** Load the home's reporter key, creating it when absent. Throws on an unreadable file. */
export function loadOrCreateReporterKey(blackboxHome: string): KeyObject {
  const path = reporterKeyPath(blackboxHome);
  if (existsSync(path)) return createPrivateKey(readFileSync(path));
  mkdirSync(blackboxHome, { recursive: true });
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const tmp = `${path}.tmp.${process.pid}.${Date.now()}`;
  writeFileSync(tmp, pem, { mode: 0o600, flag: "wx" });
  try {
    renameSync(tmp, path);
  } catch (err) {
    // Another process created it first: use theirs (one identity per home).
    if (existsSync(path)) return createPrivateKey(readFileSync(path));
    throw err;
  }
  return privateKey;
}
