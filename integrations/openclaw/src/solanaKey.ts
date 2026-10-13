/**
 * Solana secret-key REDACTION — the OpenClaw runtime's copy.
 *
 * Mirrors `plugins/blackbox/kernel/crypto_secrets/solana_key.py`
 * (`redact_solana_keys`): a 64-byte value written as one base58 string
 * (Phantom's "Export private key") or as a JSON array of 64 numbers (the
 * Solana CLI's `id.json`) is a secret key only when its second half is the
 * Ed25519 public key of its first half — a transaction signature of the same
 * shape fails that check. Verified keys become `[REDACTED_SOLANA_KEY]`.
 * Uses Node's built-in Ed25519; no dependency.
 * `tests/plugins/test_blackbox_redaction_parity.py` checks both runtimes
 * byte-for-byte. Change this file only together with the Python one.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";

export const SOLANA_KEY_MARKER = "[REDACTED_SOLANA_KEY]";
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_KEY = /(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{86,89}(?![1-9A-HJ-NP-Za-km-z])/g;
const JSON_KEY = /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/g;
// A key CUT OFF at the end of the text: redaction (never detection) removes it too (LES-021).
const CUT_BASE58 = /(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{45,89}$(?![\s\S])/;
const CUT_JSON = /\[\s*(?:\d{1,3}\s*,\s*){31,63}\d{0,3}\s*$(?![\s\S])/;
const MAX_CANDIDATES = 64;
const SEED_BYTES = 32;
// PKCS#8 DER header for a raw 32-byte Ed25519 seed (RFC 8410).
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function base58Decode(text: string): Buffer {
  let value = 0n;
  for (const char of text) value = value * 58n + BigInt(ALPHABET.indexOf(char));
  const hex = value === 0n ? "" : value.toString(16);
  const body = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
  const zeros = text.length - text.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(zeros), body]);
}

function jsonBytes(text: string): Buffer | null {
  const values = (text.match(/\d+/g) ?? []).map(Number);
  return values.every((v) => v < 256) ? Buffer.from(values) : null;
}

function publicKey(seed: Buffer): Buffer {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  return Buffer.from(jwk.x, "base64url");
}

function isSolanaSecretKey(material: Buffer | null): boolean {
  if (!material || material.length !== 2 * SEED_BYTES) return false;
  return publicKey(material.subarray(0, SEED_BYTES)).equals(material.subarray(SEED_BYTES));
}

/** Spans of every VERIFIED Solana secret key in `text`, in order. */
export function findSolanaSecretKeys(text: string): Array<[number, number]> {
  if (!text) return [];
  const candidates: Array<[RegExpMatchArray, (s: string) => Buffer | null]> = [
    ...[...text.matchAll(BASE58_KEY)].map((m): [RegExpMatchArray, (s: string) => Buffer | null] => [m, base58Decode]),
    ...[...text.matchAll(JSON_KEY)].map((m): [RegExpMatchArray, (s: string) => Buffer | null] => [m, jsonBytes]),
  ];
  const spans: Array<[number, number]> = [];
  for (const [match, decode] of candidates.slice(0, MAX_CANDIDATES)) {
    const start = match.index ?? 0;
    if (isSolanaSecretKey(decode(match[0]))) spans.push([start, start + match[0].length]);
  }
  return spans.sort((a, b) => a[0] - b[0]);
}

/** `text` with every verified Solana secret key — and a key-shaped run cut off at the end — replaced by the marker. */
export function redactSolanaKeys(text: string): string {
  let out = text;
  for (const [start, end] of findSolanaSecretKeys(text).reverse()) out = out.slice(0, start) + SOLANA_KEY_MARKER + out.slice(end);
  return out.replace(CUT_BASE58, SOLANA_KEY_MARKER).replace(CUT_JSON, SOLANA_KEY_MARKER);
}
