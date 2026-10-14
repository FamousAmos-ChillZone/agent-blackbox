/**
 * Solana secret-key REDACTION — the OpenClaw runtime's copy.
 *
 * Mirrors `plugins/blackbox/kernel/crypto_secrets/solana_key.py`
 * (`redact_solana_keys`): a 64-byte value written as one base58 string
 * (Phantom's "Export private key"), a JSON array of 64 numbers (the Solana
 * CLI's `id.json`), 128 hex characters or base64 is a secret key only when its second half is the
 * Ed25519 public key of its first half — a transaction signature of the same
 * shape fails that check. Verified keys become `[REDACTED_SOLANA_KEY]`.
 * Uses Node's built-in Ed25519; no dependency.
 * `tests/plugins/test_blackbox_redaction_parity.py` checks both runtimes
 * byte-for-byte. Change this file only together with the Python one.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";

import { base58Decode } from "./base58.js";

export const SOLANA_KEY_MARKER = "[REDACTED_SOLANA_KEY]";
const BASE58_KEY = /(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{86,89}(?![1-9A-HJ-NP-Za-km-z])/g;
const JSON_KEY = /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/g;
// Scripts also write the key as 128 hex characters or as base64.
const HEX_KEY = /(?<![0-9A-Fa-f])[0-9A-Fa-f]{128}(?![0-9A-Fa-f])/g;
const BASE64_KEY = /(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{86}(?:==)?(?![A-Za-z0-9+/_=-])/g;
// A key CUT OFF at the end of the text: redaction (never detection) removes it too (LES-021).
const CUT_BASE58 = /(?<![0-9A-Za-z])(?=[0-9A-Za-z]{0,107}[g-km-zG-HJ-NP-Z])[1-9A-HJ-NP-Za-km-z]{45,89}$(?![\s\S])/;
const CUT_JSON = /\[\s*(?:\d{1,3}\s*,\s*){31,63}\d{0,3}\s*$(?![\s\S])/;
const CUT_HEX = /(?<![0-9A-Za-z])(?:0x)?[0-9A-Fa-f]{65,127}$(?![\s\S])/;
// Most distinct candidates verified per text; the rest are redacted unverified (fail closed).
const MAX_CANDIDATES = 256;
const SEED_BYTES = 32;
// PKCS#8 DER header for a raw 32-byte Ed25519 seed (RFC 8410).
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function jsonBytes(text: string): Buffer | null {
  const values = (text.match(/\d+/g) ?? []).map(Number);
  return values.every((v) => v < 256) ? Buffer.from(values) : null;
}

function hexBytes(text: string): Buffer | null {
  return Buffer.from(text, "hex");
}

function base64Bytes(text: string): Buffer | null {
  return Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

const DECODERS: ReadonlyArray<readonly [RegExp, (s: string) => Buffer | null]> = [
  [BASE58_KEY, base58Decode], [JSON_KEY, jsonBytes], [HEX_KEY, hexBytes], [BASE64_KEY, base64Bytes],
];

function publicKey(seed: Buffer): Buffer {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  return Buffer.from(jwk.x, "base64url");
}

export function isSolanaSecretKey(material: Buffer | null): boolean {
  if (!material || material.length !== 2 * SEED_BYTES) return false;
  return publicKey(material.subarray(0, SEED_BYTES)).equals(material.subarray(SEED_BYTES));
}

/** Verified key spans and the candidate spans left unverified (over the budget), as in `scan_solana_keys`. */
function scanSolanaKeys(text: string): { keys: Array<[number, number]>; unchecked: Array<[number, number]> } {
  const candidates: Array<[number, number, string, number]> = [];
  DECODERS.forEach(([pattern], index) => {
    for (const m of text.matchAll(pattern)) candidates.push([m.index ?? 0, (m.index ?? 0) + m[0].length, m[0], index]);
  });
  candidates.sort((a, b) => b[0] - a[0]); // later first, stable like Python's sort
  const verdicts = new Map<string, boolean>();
  const keys = new Map<string, [number, number]>();
  const unchecked = new Map<string, [number, number]>();
  for (const [start, end, value, index] of candidates) {
    const id = `${index}:${value}`;
    if (!verdicts.has(id)) {
      if (verdicts.size >= MAX_CANDIDATES) {
        unchecked.set(`${start}:${end}`, [start, end]);
        continue;
      }
      verdicts.set(id, isSolanaSecretKey(DECODERS[index][1](value)));
    }
    if (verdicts.get(id)) keys.set(`${start}:${end}`, [start, end]);
  }
  for (const id of keys.keys()) unchecked.delete(id);
  const order = (a: [number, number], b: [number, number]) => a[0] - b[0] || a[1] - b[1];
  return { keys: [...keys.values()].sort(order), unchecked: [...unchecked.values()].sort(order) };
}

/** Spans of every VERIFIED Solana secret key in `text`, in order. */
export function findSolanaSecretKeys(text: string): Array<[number, number]> {
  return text ? scanSolanaKeys(text).keys : [];
}

function merged(spans: Array<[number, number]>): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  for (const [start, end] of [...spans].sort((a, b) => a[0] - b[0] || a[1] - b[1])) {
    const last = out[out.length - 1];
    if (last && start < last[1]) last[1] = Math.max(end, last[1]);
    else out.push([start, end]);
  }
  return out;
}

/** `text` with every verified key, every unchecked candidate and a key cut off at the end replaced by the marker. */
export function redactSolanaKeys(text: string): string {
  if (!text) return text;
  const scan = scanSolanaKeys(text);
  let out = text;
  for (const [start, end] of merged([...scan.keys, ...scan.unchecked]).reverse()) {
    out = out.slice(0, start) + SOLANA_KEY_MARKER + out.slice(end);
  }
  for (const cut of [CUT_BASE58, CUT_JSON, CUT_HEX]) out = out.replace(cut, SOLANA_KEY_MARKER);
  return out;
}
