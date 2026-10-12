"""Crypto secrets — wallet secrets recognised in text by their own structure.

Generic secret rules (``kernel/redaction.py``) match fixed shapes such as a key
prefix. Wallet secrets need more: a seed phrase is ordinary words until a
checksum proves it is a phrase. This sub-package holds those recognisers, used
by redaction (never store or send one) and by detection (flag or block an agent
handling one).

Public surface:

* :func:`find_seed_phrase_runs` / :class:`SeedPhraseRun` — BIP-39 seed phrases
  (MetaMask's Secret Recovery Phrase), checksum-verified;
* :func:`redact_seed_phrases` and :data:`SEED_PHRASE_MARKER`.
"""

from .seed_phrase import MARKER as SEED_PHRASE_MARKER
from .seed_phrase import SeedPhraseRun, find_seed_phrase_runs, redact_seed_phrases, wordlist_ready

__all__ = ["SEED_PHRASE_MARKER", "SeedPhraseRun", "find_seed_phrase_runs", "redact_seed_phrases", "wordlist_ready"]
