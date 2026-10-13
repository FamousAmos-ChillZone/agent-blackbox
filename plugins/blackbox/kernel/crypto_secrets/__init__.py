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
  Solana CLI ``id.json``), verified by their Ed25519 self-check;
* :func:`find_bitcoin_private_keys` / :func:`redact_bitcoin_keys` — Bitcoin WIF keys and
  BIP-32 extended private keys (xprv, yprv, zprv, tprv…), verified by their checksum;
* :func:`scan_solana_keys` — the Solana check with the candidates it had no budget for;
* :func:`misdirected_exchange_keys` — an exchange's API key header sent to a
  site that is not that exchange;
* :func:`scan_own_keys` / :class:`OwnKeyScan` / :func:`own_keys_in` / :func:`address_of`
  — raw Ethereum private keys that open one of the operator's listed addresses;
* :func:`protocol_contract` — well-known exchange routers (never a drainer, never flagged).
"""

from .seed_phrase import MARKER as SEED_PHRASE_MARKER
from . import wallet_mode
from .seed_phrase import SeedPhraseRun, find_seed_phrase_runs, redact_seed_phrases, wordlist_ready
from .solana_key import MARKER as SOLANA_KEY_MARKER
from .solana_key import find_solana_secret_keys, redact_solana_keys, scan_solana_keys
from .bitcoin_key import find_bitcoin_private_keys, redact_bitcoin_keys
from .evm_key import OwnKeyScan, address_of, own_keys_in, scan_own_keys
from . import exchange_keys
from .exchange_keys import misdirected_exchange_keys
from .known_contracts import protocol_contract

__all__ = [
           "SEED_PHRASE_MARKER",
           "SOLANA_KEY_MARKER",
           "OwnKeyScan",
           "SeedPhraseRun",
           "address_of",
           "exchange_keys",
           "find_bitcoin_private_keys",
           "find_seed_phrase_runs",
           "find_solana_secret_keys",
           "misdirected_exchange_keys",
           "own_keys_in",
           "protocol_contract",
           "redact_bitcoin_keys",
           "redact_seed_phrases",
           "redact_solana_keys",
           "scan_own_keys",
           "scan_solana_keys",
           "wallet_mode",
           "wordlist_ready",
]
