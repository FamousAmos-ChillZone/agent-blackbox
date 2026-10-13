/**
 * Bitcoin private-key REDACTION — the OpenClaw runtime's copy.
 *
 * Mirrors `plugins/blackbox/kernel/crypto_secrets/bitcoin_key.py`
 * (`redact_bitcoin_keys`): a WIF key (version 0x80 / 0xEF, 32-byte key, optional
 * 0x01 flag) or a BIP-32 extended private key (xprv, yprv, zprv, tprv, uprv,
 * vprv, Yprv, Zprv — 78 bytes, 0x00 before the key) is a key only when its
 * Base58Check checksum holds. Verified keys — and a key-shaped run cut off at
 * the end of the text — become typed markers.
 * `tests/plugins/test_blackbox_redaction_parity.py` checks both runtimes
 * byte-for-byte. Change this file only together with the Python one.
 */
import { createHash } from "node:crypto";

import { base58Decode } from "./base58.js";

export const WIF_MARKER = "[REDACTED_BITCOIN_PRIVATE_KEY]";
export const EXTENDED_MARKER = "[REDACTED_EXTENDED_PRIVATE_KEY]";
const B58 = "1-9A-HJ-NP-Za-km-z";
const WIF = new RegExp(`(?<![${B58}])[59KLc][${B58}]{50,51}(?![${B58}])`, "g");
const EXTENDED = new RegExp(`(?<![${B58}])[xyztuvYZ]prv[${B58}]{107}(?![${B58}])`, "g");
const CUT_WIF = new RegExp(`(?<![0-9A-Za-z])(?=[0-9A-Za-z]{0,107}[g-km-zG-HJ-NP-Z])[59KLc][${B58}]{29,51}$(?![\\s\\S])`);
const CUT_EXTENDED = new RegExp(`(?<![0-9A-Za-z])[xyztuvYZ]prv[${B58}]{0,107}$(?![\\s\\S])`);
const WIF_VERSIONS = new Set([0x80, 0xef]);
const EXTENDED_VERSIONS = new Set(["0488ade4", "049d7878", "04b2430c", "04358394", "044a4e28", "045f18bc", "0295b005", "02aa7a99"]);
const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function checkDecode(text: string): Buffer | null {
  const raw = base58Decode(text);
  if (raw.length < 5) return null;
  const body = raw.subarray(0, raw.length - 4);
  return sha256(sha256(body)).subarray(0, 4).equals(raw.subarray(raw.length - 4)) ? body : null;
}

function inRange(key: Buffer): boolean {
  const value = BigInt("0x" + (key.toString("hex") || "0"));
  return value > 0n && value < CURVE_ORDER;
}

function isWif(text: string): boolean {
  const body = checkDecode(text);
  if (!body || !WIF_VERSIONS.has(body[0])) return false;
  const compressed = body.length === 34 && body[33] === 0x01;
  return (body.length === 33 || compressed) && inRange(body.subarray(1, 33));
}

function isExtended(text: string): boolean {
  const body = checkDecode(text);
  return !!body && body.length === 78 && EXTENDED_VERSIONS.has(body.subarray(0, 4).toString("hex"))
    && body[45] === 0x00 && inRange(body.subarray(46, 78));
}

/** `text` with every verified WIF / extended private key (and one cut off at the end) replaced. */
export function redactBitcoinKeys(text: string): string {
  const found: Array<[number, number, string]> = [];
  for (const m of text.matchAll(WIF)) if (isWif(m[0])) found.push([m.index ?? 0, (m.index ?? 0) + m[0].length, WIF_MARKER]);
  for (const m of text.matchAll(EXTENDED)) if (isExtended(m[0])) found.push([m.index ?? 0, (m.index ?? 0) + m[0].length, EXTENDED_MARKER]);
  found.sort((a, b) => a[0] - b[0]);
  let out = text;
  for (const [start, end, marker] of found.reverse()) out = out.slice(0, start) + marker + out.slice(end);
  return out.replace(CUT_EXTENDED, EXTENDED_MARKER).replace(CUT_WIF, WIF_MARKER);
}
