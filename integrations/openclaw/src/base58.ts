/**
 * Base58 (the Bitcoin alphabet) — the OpenClaw runtime's copy of
 * `plugins/blackbox/kernel/crypto_secrets/base58.py`. Solana keys, Bitcoin WIF
 * keys and BIP-32 extended keys are written in it.
 */
export const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Base58 to bytes (leading '1's are zero bytes). */
export function base58Decode(text: string): Buffer {
  let value = 0n;
  for (const char of text) value = value * 58n + BigInt(BASE58_ALPHABET.indexOf(char));
  const hex = value === 0n ? "" : value.toString(16);
  const body = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
  const zeros = text.length - text.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(zeros), body]);
}
