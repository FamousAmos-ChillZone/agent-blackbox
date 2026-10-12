"""BIP-39 seed phrases (a wallet's Secret Recovery Phrase) found in text.

A seed phrase IS the wallet: anyone holding the 12–24 words owns every
account behind it. MetaMask calls it the Secret Recovery Phrase (12 words);
most wallets accept 12, 15, 18, 21 or 24.

How a phrase is recognised (BIP-39, github.com/bitcoin/bips bip-0039):

* every word is on the 2048-word English list, which ships next to this file
  and is pinned by its SHA-256 (:data:`WORDLIST_SHA256`) — a changed or
  truncated list disables detection loudly instead of silently;
* the words stand together: only spaces, commas, line breaks and list
  numbering ("1.", "2)") between them. Ordinary English breaks such a run
  within a few words ("the", "of", "is" are not on the list);
* the last word carries a checksum: of the n×11 bits the words encode, the
  final n/3 bits must equal the first bits of SHA-256 of the rest. A random
  run passes with probability 1/16 (12 words) down to 1/256 (24 words), so
  the checksum confirms a phrase rather than finding one.

What callers get, per run of 12+ list words (:class:`SeedPhraseRun`): where
it is, how many words, whether a checksum-valid phrase of a standard length is
inside it, whether a cue word is near ("seed", "recovery", "phrase", …) and
whether it is one of the published test phrases (uniform entropy, e.g.
"abandon … about"). Policy (block / flag) is the caller's.

Usage::

    for run in find_seed_phrase_runs(text):
        run.valid_words      # 12/15/18/21/24 when a checksum-valid phrase is inside, else 0
    redact_seed_phrases(text)  # every run of 12+ list words → [REDACTED_SEED_PHRASE]
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

WORDLIST_FILE = Path(__file__).with_name("bip39_english.txt")
#: SHA-256 of the official list (bitcoin/bips bip-0039/english.txt), checked at load.
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
#: Fewest words a phrase can have.
MIN_WORDS = 12
#: Phrase lengths BIP-39 defines, longest first (the longest valid one wins).
PHRASE_LENGTHS = (24, 21, 18, 15, 12)
MARKER = "[REDACTED_SEED_PHRASE]"

_WORD = re.compile(r"[A-Za-z]+")
#: What may stand between two words of one phrase: spaces, commas, line
#: breaks, list numbering — at most a few characters.
#: ASCII only, spelled out — the OpenClaw bridge's copy (redact.ts) uses the
#: same class, and Python's and JavaScript's \s / \d differ outside ASCII.
_GAP = re.compile(r"[ \t\n\r\f\v,;.:)(\-\"'`0-9]{1,8}")
_CUE = re.compile(r"\b(?:seed|mnemonic|recovery|phrase|secret|backup|srp|words?|wallet)\b", re.IGNORECASE)
_CUE_WINDOW = 80


@dataclass(frozen=True)
class SeedPhraseRun:
    """A run of 12+ consecutive wordlist words in a text.

    ``start``/``end`` — character offsets of the run; ``word_count`` — its
    length; ``valid_words`` — the length of the longest checksum-valid
    standard phrase inside it (0 when none); ``has_cue`` — a cue word within
    80 characters or numbered words; ``test_phrase`` — the valid phrase is a
    published example (uniform entropy), not a real wallet.
    """

    start: int
    end: int
    word_count: int
    valid_words: int
    has_cue: bool
    test_phrase: bool


@lru_cache(maxsize=1)
def _wordlist() -> Optional[Dict[str, int]]:
    """``{word: index}`` from the pinned list, or ``None`` when the file is
    missing or not the pinned list (logged once at WARNING)."""
    try:
        data = WORDLIST_FILE.read_bytes()
    except OSError as exc:
        logger.warning("blackbox: BIP-39 wordlist unreadable (%s); seed-phrase detection is OFF", exc)
        return None
    if hashlib.sha256(data).hexdigest() != WORDLIST_SHA256:
        logger.warning("blackbox: BIP-39 wordlist does not match its pinned SHA-256; seed-phrase detection is OFF")
        return None
    words = data.decode("ascii").split()
    return {word: index for index, word in enumerate(words)}


def checksum_entropy(indices: List[int]) -> Optional[bytes]:
    """The entropy behind word *indices* when their BIP-39 checksum holds,
    else ``None``. ``len(indices)`` must be a standard phrase length."""
    total_bits = len(indices) * 11
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits
    value = 0
    for index in indices:
        value = (value << 11) | index
    entropy = (value >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    return entropy if (value & ((1 << checksum_bits) - 1)) == expected else None


def _runs(text: str, words: Dict[str, int]) -> List[List[Tuple[int, int, int]]]:
    """Runs of consecutive list words as ``[(start, end, index), ...]``."""
    runs: List[List[Tuple[int, int, int]]] = []
    current: List[Tuple[int, int, int]] = []
    for match in _WORD.finditer(text):
        index = words.get(match.group(0).lower())
        joined = current and _GAP.fullmatch(text[current[-1][1]:match.start()])
        if index is None or (current and not joined):
            if len(current) >= MIN_WORDS:
                runs.append(current)
            current = []
        if index is not None:
            current.append((match.start(), match.end(), index))
    if len(current) >= MIN_WORDS:
        runs.append(current)
    return runs


def _longest_valid(run: List[Tuple[int, int, int]]) -> Tuple[int, List[int], Optional[bytes]]:
    """``(length, offsets, entropy)`` for the longest standard length at which
    *run* holds a checksum-valid phrase: EVERY offset that is valid at that
    length (a label word such as "seed" joins the run, and the window that
    includes it passes the checksum by chance 1 time in 16), and the first
    one's entropy. ``(0, [], None)`` when there is none."""
    indices = [index for _start, _end, index in run]
    for length in PHRASE_LENGTHS:
        found = [(offset, checksum_entropy(indices[offset:offset + length]))
                 for offset in range(0, len(indices) - length + 1)]
        valid = [(offset, entropy) for offset, entropy in found if entropy is not None]
        if valid:
            return length, [offset for offset, _entropy in valid], valid[0][1]
    return 0, [], None


def _has_cue(text: str, span_start: int, span_end: int) -> bool:
    """A cue word near the phrase, or numbered words. Looked for OUTSIDE the
    phrase itself: "seed", "phrase", "wallet" are list words, so a label like
    "seed:" joins the run, and a phrase may contain them by chance."""
    nearby = text[max(0, span_start - _CUE_WINDOW):span_start] + " " + text[span_end:span_end + _CUE_WINDOW]
    numbered = bool(re.search(r"\b\d{1,2}[.)]\s*[A-Za-z]", text[max(0, span_start - 4):span_end]))
    return bool(_CUE.search(nearby)) or numbered


def find_seed_phrase_runs(text: str) -> List[SeedPhraseRun]:
    """Every run of 12+ consecutive wordlist words in *text* (see module doc)."""
    words = _wordlist()
    if not text or words is None:
        return []
    out: List[SeedPhraseRun] = []
    for run in _runs(text, words):
        valid_words, offsets, entropy = _longest_valid(run)
        windows = [run[offset:offset + valid_words] for offset in offsets] or [run]
        out.append(SeedPhraseRun(
            start=run[0][0], end=run[-1][1], word_count=len(run), valid_words=valid_words,
            has_cue=any(_has_cue(text, window[0][0], window[-1][1]) for window in windows),
            test_phrase=entropy is not None and len(set(entropy)) == 1,
        ))
    return out


def redact_seed_phrases(text: str) -> str:
    """*text* with every run of 12+ consecutive wordlist words replaced by
    :data:`MARKER` — checksum or not: a mistyped phrase is still a secret."""
    runs = find_seed_phrase_runs(text)
    for run in reversed(runs):
        text = text[:run.start] + MARKER + text[run.end:]
    return text
