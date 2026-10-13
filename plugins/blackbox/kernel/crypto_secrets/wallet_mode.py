"""Web3 wallet protection: an opt-in mode, and the wallets the operator chose to protect.

Founder direction (Amos, 2026-10-12): wallet protection is a mode the operator turns
on in Settings, choosing which wallets to guard. Off (the default), the wallet rules —
key-store access, seed phrases, labelled private keys — neither flag nor block, and
the dashboard hides the wallet panel. Redaction is NOT part of the mode: seed phrases
and private keys are always scrubbed from Blackbox's own logs (privacy, never a switch).

Config keys under ``plugins.entries.blackbox``::

    wallet_protection: true          # the mode (default false)
    protected_wallets: [metamask]    # which wallets (default: every supported one)

Pattern: Value Object (:class:`WalletProtection`) + a validate-then-persist step the
settings writer calls (:func:`validate`).

Usage::

    mode = current()
    mode.enabled, mode.wallets           # False, ("metamask", "phantom", "exodus", ...)
    mode.allows_finding(finding_dict)    # False while the mode is off
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

#: Wallets Blackbox can protect today: id -> display name.
SUPPORTED_WALLETS: Dict[str, str] = {"metamask": "MetaMask", "phantom": "Phantom",
                                     "exodus": "Exodus", "electrum": "Electrum", "solana-cli": "Solana CLI"}
#: Wallets on the way (key-store IDs verified, rules not written yet) — shown as "coming soon".
PLANNED_WALLETS: Tuple[str, ...] = ("Rabby", "Coinbase Wallet", "Trust Wallet", "OKX Wallet", "Keplr", "Solflare")
#: Findings that belong to the mode: seed phrases, labelled private keys and Solana keys (any wallet)…
WALLET_SECRET_IDENTIFIERS = frozenset({"secret:seed-phrase", "secret:wallet-private-key", "secret:solana-private-key"})
#: …and key-store access, which names its wallet in ``fields["wallet"]``.
WALLET_FILE_SUFFIX = ":crypto-wallet"
#: ``fields["wallet"]`` of a Firefox extension key store: Firefox names each install's
#: storage by a random UUID, so the folder cannot be tied to one wallet. It belongs to
#: EVERY chosen wallet — counted whenever the mode is on with any wallet chosen.
ANY_EXTENSION_WALLET = "any-extension"


@dataclass(frozen=True)
class WalletProtection:
    """``enabled`` — the mode is on; ``wallets`` — supported wallet ids to guard."""

    enabled: bool = False
    wallets: Tuple[str, ...] = tuple(SUPPORTED_WALLETS)

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
        if identifier.endswith(WALLET_FILE_SUFFIX):
            fields = finding.get("fields")
            return self.protects(str((fields.get("wallet") if isinstance(fields, Mapping) else None) or ""))
        return True

    def as_json(self) -> Dict[str, Any]:
        """What the dashboard and the settings page show."""
        return {"enabled": self.enabled, "wallets": list(self.wallets),
                "supported": [{"id": key, "name": name} for key, name in SUPPORTED_WALLETS.items()],
                "planned": list(PLANNED_WALLETS)}


def _wallet_list(raw: Any) -> Tuple[str, ...]:
    """Supported wallet ids from *raw* (a list), lower-cased, deduplicated, in order."""
    out: List[str] = []
    for item in raw if isinstance(raw, list) else []:
        wallet = str(item or "").strip().lower()
        if wallet in SUPPORTED_WALLETS and wallet not in out:
            out.append(wallet)
    return tuple(out)


def from_entry(entry: Mapping[str, Any]) -> WalletProtection:
    """The mode as the ``blackbox`` config entry states it (defaults when absent)."""
    enabled = entry.get("wallet_protection") is True
    wallets = _wallet_list(entry["protected_wallets"]) if "protected_wallets" in entry else tuple(SUPPORTED_WALLETS)
    return WalletProtection(enabled=enabled, wallets=wallets)


def current() -> WalletProtection:
    """The mode in force now, read from the Hermes config like every other setting."""
    from ..config import _blackbox_entry   # the one reader of plugins.entries.blackbox

    return from_entry(_blackbox_entry())


def validate(payload: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """``(config updates, errors)`` for the mode's keys in a settings *payload*.
    Unknown wallets are refused, never stored."""
    updates: Dict[str, Any] = {}
    errors: List[str] = []
    if "wallet_protection" in payload:
        if isinstance(payload["wallet_protection"], bool):
            updates["wallet_protection"] = payload["wallet_protection"]
        else:
            errors.append("wallet_protection must be a boolean")
    if "protected_wallets" in payload:
        raw = payload["protected_wallets"]
        unknown = [w for w in (raw if isinstance(raw, list) else [raw]) if str(w or "").lower() not in SUPPORTED_WALLETS]
        if not isinstance(raw, list) or unknown:
            errors.append(f"protected_wallets must be a list of: {', '.join(SUPPORTED_WALLETS)}")
        else:
            updates["protected_wallets"] = list(_wallet_list(raw))
    return updates, errors
