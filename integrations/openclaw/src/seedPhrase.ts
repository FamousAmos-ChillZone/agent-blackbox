/**
 * BIP-39 seed-phrase REDACTION — the OpenClaw runtime's copy.
 *
 * Mirrors `plugins/blackbox/kernel/crypto_secrets/seed_phrase.py`
 * (`redact_seed_phrases`): every run of 12+ consecutive words from the BIP-39
 * English list, separated only by spaces, commas, line breaks or list
 * numbering, becomes `[REDACTED_SEED_PHRASE]` — checksum or not, since a
 * mistyped phrase is still a secret. The wordlist ships next to this file and
 * is pinned by the same SHA-256 as the Python copy; a mismatch turns the pass
 * off loudly (console.warn) instead of silently.
 * `tests/plugins/test_blackbox_redaction_parity.py` checks both runtimes
 * byte-for-byte. Change this file only together with the Python one.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export const SEED_PHRASE_MARKER = "[REDACTED_SEED_PHRASE]";
const WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
const MIN_WORDS = 12;
const WORD_RE = /[A-Za-z]+/g;
// Same ASCII class as the Python `_GAP`.
const GAP_RE = /^[ \t\n\r\f\v,;.:)(\-"'`0-9+%_/]{1,8}$/;

let wordlist: ReadonlySet<string> | null | undefined;

function loadWordlist(): ReadonlySet<string> | null {
  if (wordlist !== undefined) return wordlist;
  try {
    const data = readFileSync(new URL("./bip39-english.txt", import.meta.url));
    if (createHash("sha256").update(data).digest("hex") !== WORDLIST_SHA256) {
      console.warn("blackbox: BIP-39 wordlist does not match its pinned SHA-256; seed-phrase redaction is OFF");
      wordlist = null;
    } else {
      wordlist = new Set(data.toString("ascii").split(/\s+/).filter(Boolean));
    }
  } catch (error) {
    console.warn(`blackbox: BIP-39 wordlist unreadable (${String(error)}); seed-phrase redaction is OFF`);
    wordlist = null;
  }
  return wordlist;
}

/** Character spans `[start, end)` of every run of 12+ consecutive list words. */
function seedPhraseSpans(text: string, words: ReadonlySet<string>): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  let runStart = -1;
  let runEnd = -1;
  let count = 0;
  const close = (): void => {
    if (count >= MIN_WORDS) spans.push([runStart, runEnd]);
    count = 0;
  };
  for (const match of text.matchAll(WORD_RE)) {
    const start = match.index ?? 0;
    const end = start + match[0].length;
    const listed = words.has(match[0].toLowerCase());
    const joined = count > 0 && GAP_RE.test(text.slice(runEnd, start));
    if (!listed || (count > 0 && !joined)) close();
    if (listed) {
      if (count === 0) runStart = start;
      runEnd = end;
      count += 1;
    }
  }
  close();
  return spans;
}

/** `text` with every seed-phrase run replaced by {@link SEED_PHRASE_MARKER}. */
export function redactSeedPhrases(text: string): string {
  const words = loadWordlist();
  if (!text || !words) return text;
  let out = text;
  for (const [start, end] of seedPhraseSpans(text, words).reverse()) {
    out = out.slice(0, start) + SEED_PHRASE_MARKER + out.slice(end);
  }
  return out;
}
