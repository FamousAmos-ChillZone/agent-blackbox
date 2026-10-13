"""Crypto secrets — wallet secrets recognised in text by their own structure.

Generic secret rules (``kernel/redaction.py``) match fixed shapes such as a key
prefix. Wallet secrets need more: a seed phrase is ordinary words until a
checksum proves it is a phrase. This sub-package holds those recognisers, used
by redaction (never store or send one) and by detection (flag or block an agent
handling one).

Public surface:

* :func:`find_seed_phrase_runs` / :class:`SeedPhraseRun` — BIP-39 seed phrases
  (MetaMask's Secret Recovery Phrase), checksum-verified;
* :func:`redact_seed_phrases` and :data:`SEED_PHRASE_MARKER`;
* :func:`find_solana_secret_keys` / :func:`redact_solana_keys` and
  :data:`SOLANA_KEY_MARKER` — Solana secret keys (Phantom's exported key, the
  Solana CLI ``id.json``), verified by their Ed25519 self-check.
"""

from .seed_phrase import MARKER as SEED_PHRASE_MARKER
from . import wallet_mode
from .seed_phrase import SeedPhraseRun, find_seed_phrase_runs, redact_seed_phrases, wordlist_ready
from .solana_key import MARKER as SOLANA_KEY_MARKER
from .solana_key import find_solana_secret_keys, redact_solana_keys

__all__ = ["SEED_PHRASE_MARKER", "SOLANA_KEY_MARKER", "SeedPhraseRun", "find_seed_phrase_runs", "find_solana_secret_keys",
           "redact_seed_phrases", "redact_solana_keys", "wallet_mode", "wordlist_ready"]
