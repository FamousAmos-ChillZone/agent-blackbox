/**
 * BIP-39 seed-phrase REDACTION — the OpenClaw runtime's copy.
 *
 * Mirrors `plugins/blackbox/kernel/crypto_secrets/seed_phrase.py`
 * (`redact_seed_phrases`): every run of 12+ consecutive words from the BIP-39
 * English list (or their unique four-letter forms), joined by anything that is
 * not a letter, in the text's normalised reading (textView.ts: percent escapes,
 * invisible characters, fullwidth letters, HTML entities, CamelCase), or inside
 * a base64 run that decodes to such text, becomes `[REDACTED_SEED_PHRASE]` —
 * checksum or not, since a mistyped phrase is still a secret. The wordlist ships next to this file and
 * is pinned by the same SHA-256 as the Python copy; a mismatch turns the pass
 * off loudly (console.warn) instead of silently.
 * `tests/plugins/test_blackbox_redaction_parity.py` checks both runtimes
 * byte-for-byte. Change this file only together with the Python one.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { readings } from "./textView.js";

export const SEED_PHRASE_MARKER = "[REDACTED_SEED_PHRASE]";
const WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
const MIN_WORDS = 12;
const WORD_RE = /[A-Za-z]+/g;
// A base64 run long enough to hold a 12-word phrase; at most MAX_ENCODED decoded per text.
const BASE64_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{64,4096}={0,2}(?![A-Za-z0-9+/=_-])/g;
const MAX_ENCODED = 16;

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

/** `{first four letters: word}` for list words longer than four letters (BIP-39 makes them unique). */
let prefixes: ReadonlySet<string> | undefined;
function loadPrefixes(words: ReadonlySet<string>): ReadonlySet<string> {
  if (!prefixes) prefixes = new Set([...words].filter((word) => word.length > 4).map((word) => word.slice(0, 4)));
  return prefixes;
}

/** Runs `[start, end)` (in `text`) of 12+ consecutive list words: any non-letter joins two words. */
function runSpans(text: string, words: ReadonlySet<string>): Array<[number, number]> {
  const shortForms = loadPrefixes(words);
  const spans: Array<[number, number]> = [];
  let runStart = -1;
  let runEnd = -1;
  let count = 0;
  for (const match of text.matchAll(WORD_RE)) {
    const token = match[0].toLowerCase();
    const listed = words.has(token) || (token.length === 4 && shortForms.has(token));
    if (!listed) {
      if (count >= MIN_WORDS) spans.push([runStart, runEnd]);
      count = 0;
      continue;
    }
    const start = match.index ?? 0;
    if (count === 0) runStart = start;
    runEnd = start + match[0].length;
    count += 1;
  }
  if (count >= MIN_WORDS) spans.push([runStart, runEnd]);
  return spans;
}

/** Original spans of the runs in `text`'s normalised readings. */
function seedPhraseSpans(text: string, words: ReadonlySet<string>): Array<[number, number]> {
  return readings(text).flatMap((view) => runSpans(view.text, words).map(([start, end]) => view.originalSpan(start, end)));
}

/** `blob` base64-decoded when that gives printable ASCII text, else null. */
function decodedText(blob: string): string | null {
  const core = blob.replace(/=+$/, "");
  if (core.length % 4 === 1) return null; // not base64 (Python's decoder refuses it too)
  const raw = Buffer.from(core.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  for (const byte of raw) if (!((byte >= 32 && byte < 127) || byte === 9 || byte === 10 || byte === 13)) return null;
  return raw.toString("ascii");
}

/** `text` with every seed-phrase run (plain or base64-encoded) replaced by {@link SEED_PHRASE_MARKER}. */
export function redactSeedPhrases(text: string): string {
  const words = loadWordlist();
  if (!text || !words) return text;
  const spans = seedPhraseSpans(text, words);
  for (const match of [...text.matchAll(BASE64_RE)].slice(0, MAX_ENCODED)) {
    const decoded = decodedText(match[0]);
    if (decoded && seedPhraseSpans(decoded, words).length) spans.push([match.index ?? 0, (match.index ?? 0) + match[0].length]);
  }
  const merged: Array<[number, number]> = [];
  for (const [start, end] of spans.sort((a, b) => a[0] - b[0] || a[1] - b[1])) {
    const last = merged[merged.length - 1];
    if (last && start < last[1]) last[1] = Math.max(end, last[1]);
    else merged.push([start, end]);
  }
  let out = text;
  for (const [start, end] of merged.reverse()) out = out.slice(0, start) + SEED_PHRASE_MARKER + out.slice(end);
  return out;
}
