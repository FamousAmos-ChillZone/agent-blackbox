/**
 * A normalised reading of a text that remembers where every character came from —
 * the OpenClaw runtime's copy of `plugins/blackbox/kernel/crypto_secrets/text_view.py`.
 *
 * One linear pass undoes the spellings that hide a seed phrase from a word matcher:
 * percent escapes (any number of `25` layers) become their character, invisible format
 * characters are dropped, fullwidth ASCII becomes ASCII, an HTML entity becomes a space
 * and a lower→Upper boundary (CamelCase) gets a space. `originalSpan` maps a span of the
 * reading back to the text it came from. Change only together with the Python copy
 * (`tests/plugins/test_blackbox_redaction_parity.py` checks both byte-for-byte).
 */
const EDITS =
  /%(?:25)*([0-9A-Fa-f]{2})|([\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff])|([\uff01-\uff5e])|(&(?:[A-Za-z]{2,8}|#[0-9]{1,6}|#[xX][0-9A-Fa-f]{1,6});)|(?<=[a-z])(?=[A-Z])/g;
const FULLWIDTH_OFFSET = 0xfee0;

/** [viewStart, viewLength, originalStart, originalLength] */
type Segment = [number, number, number, number];

export interface TextView {
  text: string;
  originalSpan(start: number, end: number): [number, number];
}

const INVISIBLE = /[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]/;

function replacement(match: RegExpMatchArray, invisible: string): string {
  const [, percent, hidden, fullwidth] = match;
  if (percent !== undefined) return String.fromCharCode(parseInt(percent, 16));
  if (fullwidth !== undefined) return String.fromCharCode(fullwidth.charCodeAt(0) - FULLWIDTH_OFFSET);
  if (hidden !== undefined) return invisible;
  return " "; // an entity, or the CamelCase boundary
}

/** One reading, or two when the text holds an invisible character (inside a word: drop it; between words: a space). */
export function readings(text: string): TextView[] {
  return INVISIBLE.test(text) ? [normalised(text), normalised(text, " ")] : [normalised(text)];
}

export function normalised(text: string, invisible = ""): TextView {
  const pieces: string[] = [];
  const segments: Segment[] = [];
  let view = 0;
  let original = 0;
  for (const match of text.matchAll(EDITS)) {
    const start = match.index ?? 0;
    if (start > original) {
      const length = start - original;
      pieces.push(text.slice(original, start));
      segments.push([view, length, original, length]);
      view += length;
    }
    const piece = replacement(match, invisible);
    if (piece) {
      pieces.push(piece);
      segments.push([view, 1, start, match[0].length]);
      view += 1;
    }
    original = start + match[0].length;
  }
  if (original < text.length || segments.length === 0) {
    const length = text.length - original;
    pieces.push(text.slice(original));
    segments.push([view, length, original, length]);
  }
  const segmentAt = (offset: number): Segment => {
    let low = 0;
    let high = segments.length - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if (segments[middle][0] <= offset) low = middle;
      else high = middle - 1;
    }
    return segments[low];
  };
  return {
    text: pieces.join(""),
    originalSpan(start: number, end: number): [number, number] {
      const [viewStart, viewLength, originalStart, originalLength] = segmentAt(start);
      const begin = viewLength === originalLength ? originalStart + (start - viewStart) : originalStart;
      const [lastStart, lastLength, lastOriginal, lastOriginalLength] = segmentAt(end - 1);
      const finish = lastLength === lastOriginalLength ? lastOriginal + (end - 1 - lastStart) + 1 : lastOriginal + lastOriginalLength;
      return [begin, finish];
    },
  };
}
