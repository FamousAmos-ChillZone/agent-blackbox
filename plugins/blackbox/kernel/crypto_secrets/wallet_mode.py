"""Web3 wallet protection: an opt-in mode, and the wallets the operator chose to protect.

Founder direction (Amos, 2026-10-12): wallet protection is a mode the operator turns
on in Settings, choosing which wallets to guard. Off (the default), the wallet rules —
key-store access, seed phrases, labelled private keys — neither flag nor block, and
the dashboard hides the wallet panel. Redaction is NOT part of the mode: seed phrases
and private keys are always scrubbed from Blackbox's own logs (privacy, never a switch).

Config keys under ``plugins.entries.blackbox``::

    wallet_protection: true          # the mode (default false)
    protected_wallets: [metamask]    # which wallets (default: every supported one)
    wallet_addresses: ["0x…"]        # the operator's OWN public addresses (optional, opt-in):
                                     # a raw 64-hex key that opens one of them is recognised

Pattern: Value Object (:class:`WalletProtection`) + a validate-then-persist step the
settings writer calls (:func:`validate`).

Usage::

    mode = current()
    mode.enabled, mode.wallets           # False, ("metamask", "phantom", "exodus", ...)
    mode.allows_finding(finding_dict)    # False while the mode is off
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

#: Wallets Blackbox can protect today: id -> display name.
SUPPORTED_WALLETS: dict[str, str] = {"metamask": "MetaMask", "phantom": "Phantom",
                                     "exodus": "Exodus", "electrum": "Electrum", "solana-cli": "Solana CLI"}
#: Wallets on the way (key-store IDs verified, rules not written yet) — shown as "coming soon".
PLANNED_WALLETS: tuple[str, ...] = ("Rabby", "Coinbase Wallet", "Trust Wallet", "OKX Wallet", "Keplr", "Solflare")
#: Findings that belong to the mode: seed phrases, labelled private keys, Solana and Bitcoin keys (any wallet)…
WALLET_SECRET_IDENTIFIERS = frozenset({"secret:seed-phrase", "secret:wallet-private-key", "secret:solana-private-key",
                                       "secret:bitcoin-private-key",
                                       "secret:exchange-api-key",    # …an exchange key sent to a site not its own
                                       "secret:token-approval-drainer", "secret:token-approval-unlimited",    # …token approvals
                                       "secret:token-approval-unchecked-spender"})
#: …and key-store access, which names its wallet in ``fields["wallet"]``.
WALLET_FILE_SUFFIX = ":crypto-wallet"
#: …and the macOS keychain (saved passwords, the browsers' Safe Storage keys), any wallet.
KEYCHAIN_FILE_SUFFIX = ":macos-keychain"
#: ``fields["wallet"]`` of a Firefox extension key store: Firefox names each install's
#: storage by a random UUID, so the folder cannot be tied to one wallet. It belongs to
#: EVERY chosen wallet — counted whenever the mode is on with any wallet chosen.
ANY_EXTENSION_WALLET = "any-extension"


#: Most addresses an operator may list (each costs a key derivation only when a 64-hex
#: value appears in a call, ~2 ms; the list is matched as a set).
MAX_WALLET_ADDRESSES = 50
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def belongs_to_mode(identifier: str) -> bool:
    """Whether a finding identifier is a Trader Shield finding — THE list the mode gate
    and the dashboard's wallet events both use."""
    return (identifier in WALLET_SECRET_IDENTIFIERS or identifier.endswith(WALLET_FILE_SUFFIX)
            or identifier.endswith(KEYCHAIN_FILE_SUFFIX))


@dataclass(frozen=True)
class WalletProtection:
    """``enabled`` — the mode is on; ``wallets`` — supported wallet ids to guard;
    ``addresses`` — the operator's own public addresses, lower-case (kept on this
    machine only; never put in a finding, a log line or a report)."""

    enabled: bool = False
    wallets: tuple[str, ...] = tuple(SUPPORTED_WALLETS)
    addresses: tuple[str, ...] = ()

    def protects(self, wallet_id: str) -> bool:
        """Whether the wallet *wallet_id* is guarded under this mode — THE rule the gate
        and the dashboard both use. ``ANY_EXTENSION_WALLET`` (a store no folder name ties
        to one wallet) is guarded whenever any wallet is chosen."""
        wallet_id = str(wallet_id or "").lower()
        if wallet_id == ANY_EXTENSION_WALLET:
            return self.enabled and bool(self.wallets)
        return self.enabled and wallet_id in self.wallets

    def allows_finding(self, finding: Mapping[str, Any]) -> bool:
        """Whether a finding may flag or block under this mode. Findings that are
        not wallet findings are always allowed (this mode governs wallets only)."""
        identifier = str(finding.get("identifier") or "")
        if identifier in WALLET_SECRET_IDENTIFIERS:
            return self.enabled
        if identifier.endswith(KEYCHAIN_FILE_SUFFIX):
            return self.enabled
        if identifier.endswith(WALLET_FILE_SUFFIX):
            fields = finding.get("fields")
            return self.protects(str((fields.get("wallet") if isinstance(fields, Mapping) else None) or ""))
        return True

    def as_json(self) -> dict[str, Any]:
        """What the dashboard and the settings page show."""
        return {"enabled": self.enabled, "wallets": list(self.wallets), "addresses": list(self.addresses),
                "supported": [{"id": key, "name": name} for key, name in SUPPORTED_WALLETS.items()],
                "planned": list(PLANNED_WALLETS)}


def _wallet_list(raw: Any) -> tuple[str, ...]:
    """Supported wallet ids from *raw* (a list), lower-cased, deduplicated, in order."""
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        wallet = str(item or "").strip().lower()
        if wallet in SUPPORTED_WALLETS and wallet not in out:
            out.append(wallet)
    return tuple(out)


def _address_list(raw: Any) -> tuple[str, ...]:
    """Valid addresses from *raw* (a list), lower-cased, deduplicated, at most the cap."""
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        address = str(item or "").strip().lower()
        if _ADDRESS.match(address) and address not in out:
            out.append(address)
    return tuple(out[:MAX_WALLET_ADDRESSES])


def from_entry(entry: Mapping[str, Any]) -> WalletProtection:
    """The mode as the ``blackbox`` config entry states it (defaults when absent)."""
    enabled = entry.get("wallet_protection") is True
    wallets = _wallet_list(entry["protected_wallets"]) if "protected_wallets" in entry else tuple(SUPPORTED_WALLETS)
    return WalletProtection(enabled=enabled, wallets=wallets, addresses=_address_list(entry.get("wallet_addresses")))


def current() -> WalletProtection:
    """The mode in force now, read from the Hermes config like every other setting."""
    from ..config import _blackbox_entry   # the one reader of plugins.entries.blackbox

    return from_entry(_blackbox_entry())


def validate(payload: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """``(config updates, errors)`` for the mode's keys in a settings *payload*.
    Unknown wallets are refused, never stored; ``protected_wallets`` holds at most
    every supported wallet once, ``wallet_addresses`` at most :data:`MAX_WALLET_ADDRESSES`."""
    updates: dict[str, Any] = {}
    errors: list[str] = []
    if "wallet_protection" in payload:
        if isinstance(payload["wallet_protection"], bool):
            updates["wallet_protection"] = payload["wallet_protection"]
        else:
            errors.append("wallet_protection must be a boolean")
    if "protected_wallets" in payload:
        raw = payload["protected_wallets"]
        # No list longer than the supported set: a valid one never repeats a wallet (KI-389).
        too_long = isinstance(raw, list) and len(raw) > len(SUPPORTED_WALLETS)
        unknown = [] if too_long else [w for w in (raw if isinstance(raw, list) else [raw])
                                       if str(w or "").lower() not in SUPPORTED_WALLETS]
        if not isinstance(raw, list) or too_long or unknown:
            errors.append(f"protected_wallets must be a list of: {', '.join(SUPPORTED_WALLETS)}")
        else:
            updates["protected_wallets"] = list(_wallet_list(raw))
    if "wallet_addresses" in payload:
        raw = payload["wallet_addresses"]
        items = raw if isinstance(raw, list) and len(raw) <= MAX_WALLET_ADDRESSES else None
        bad = [a for a in items or [] if not _ADDRESS.match(str(a or "").strip())]
        if items is None or bad:
            errors.append(f"wallet_addresses must be a list of up to {MAX_WALLET_ADDRESSES} addresses like 0x followed by 40 hex characters")
        else:
            updates["wallet_addresses"] = list(_address_list(items))
    return updates, errors
