"""Trader Shield's setting: an opt-in mode, the wallets the operator chose, their own addresses.

Founder direction (Amos, 2026-10-12): wallet protection is a mode the operator turns
on in Settings, choosing which wallets to guard. Off (the default), the wallet rules —
key-store access, seed phrases, labelled private keys — neither flag nor block, and
the dashboard hides the wallet panel. Redaction is NOT part of the mode: seed phrases
and private keys are always scrubbed from Blackbox's own logs (privacy, never a switch).

Config, under ``plugins.entries.blackbox``::

    shields:
      trader:
        enabled: true                # the mode (default false)
        wallets: [metamask]          # which wallets (default: every supported one)
        addresses: ["0x…"]           # the operator's OWN public addresses (optional, opt-in):
                                     # a raw 64-hex key that opens one of them is recognised

Which wallets exist is data, not code: the shield's packs (``shields/trader/wallets/``),
handed in once by :func:`use_packs`; ``supported`` ones may be chosen, ``planned`` ones
are shown as coming soon.

An install saved before shields keeps the three legacy keys ``wallet_protection`` /
``protected_wallets`` / ``wallet_addresses``; :func:`from_entry` still reads them (so it
stays engaged without a save), and the first save retires them (:func:`validate`).

The mode is the shields contract's :class:`~..contract.ShieldMode`, built by :func:`build`:
options ``wallets`` and ``addresses``, the addresses marked personal so ``as_json()``
leaves them out unless the Settings editor asks (F-035).

Usage::

    mode = current()
    wallets(mode), addresses(mode)       # ("metamask", "phantom", ...), ()
    allows_finding(finding_dict, mode)   # False while the mode is off
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional

from ..contract import Pack, ShieldMode

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

#: The mode's options: the chosen wallet ids, and the operator's own addresses (personal).
WALLETS, ADDRESSES = "wallets", "addresses"
#: The three keys this setting lived under before shields; one save retires them (F-009).
LEGACY_KEYS = ("wallet_protection", "protected_wallets", "wallet_addresses")

#: Most addresses an operator may list (each costs a key derivation only when a 64-hex
#: value appears in a call, ~2 ms; the list is matched as a set).
MAX_WALLET_ADDRESSES = 50
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


#: Trader's wallet packs in display order, handed in once by the shield (:func:`use_packs`).
_packs: tuple[Pack, ...] = ()


def use_packs(packs: Iterable[Pack]) -> None:
    """Set the wallet packs the mode chooses from (the shield calls this once, at import)."""
    global _packs
    _packs = tuple(packs)


def wallet_packs() -> tuple[Pack, ...]:
    """Every wallet pack in display order: supported, planned, then unavailable ones."""
    return _packs


def supported_wallets() -> dict[str, str]:
    """The wallets Blackbox can protect now: pack id -> display name, in display order."""
    return {pack.id: pack.name for pack in _packs if pack.status == "supported"}


def belongs_to_mode(identifier: str) -> bool:
    """Whether a finding identifier is a Trader Shield finding — THE list the mode gate
    and the dashboard's wallet events both use."""
    return (identifier in WALLET_SECRET_IDENTIFIERS or identifier.endswith(WALLET_FILE_SUFFIX)
            or identifier.endswith(KEYCHAIN_FILE_SUFFIX))


def build(enabled: bool = False, wallets: Optional[tuple[str, ...]] = None,
          addresses: tuple[str, ...] = ()) -> ShieldMode:
    """Trader's mode: ``enabled``; ``wallets`` — supported wallet ids to guard (None:
    every supported one);
    ``addresses`` — the operator's own public addresses, lower-case (kept on this
    machine only; never put in a finding, a log line or a report)."""
    chosen = tuple(supported_wallets()) if wallets is None else tuple(wallets)
    return ShieldMode(enabled=enabled, options={WALLETS: chosen, ADDRESSES: tuple(addresses)},
                      personal=frozenset({ADDRESSES}))


def wallets(mode: ShieldMode) -> tuple[str, ...]:
    """The wallet ids *mode* guards."""
    return tuple(mode.options.get(WALLETS, ()))


def addresses(mode: ShieldMode) -> tuple[str, ...]:
    """The operator's own addresses in *mode* (personal: never shown outside Settings)."""
    return tuple(mode.options.get(ADDRESSES, ()))


def protects(mode: ShieldMode, wallet_id: str) -> bool:
    """Whether the wallet *wallet_id* is guarded under *mode* — THE rule the gate
    and the dashboard both use. ``ANY_EXTENSION_WALLET`` (a store no folder name ties
    to one wallet) is guarded whenever any wallet is chosen."""
    wallet_id = str(wallet_id or "").lower()
    if wallet_id == ANY_EXTENSION_WALLET:
        return mode.enabled and bool(wallets(mode))
    return mode.enabled and wallet_id in wallets(mode)


def allows_finding(finding: Mapping[str, Any], mode: ShieldMode) -> bool:
    """Whether a finding may flag or block under *mode*. Findings that are
    not wallet findings are always allowed (this mode governs wallets only)."""
    identifier = str(finding.get("identifier") or "")
    if identifier in WALLET_SECRET_IDENTIFIERS:
        return mode.enabled
    if identifier.endswith(KEYCHAIN_FILE_SUFFIX):
        return mode.enabled
    if identifier.endswith(WALLET_FILE_SUFFIX):
        fields = finding.get("fields")
        return protects(mode, str((fields.get("wallet") if isinstance(fields, Mapping) else None) or ""))
    return True


def _wallet_list(raw: Any) -> tuple[str, ...]:
    """Supported wallet ids from *raw* (a list), lower-cased, deduplicated, in order."""
    supported = supported_wallets()
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        wallet = str(item or "").strip().lower()
        if wallet in supported and wallet not in out:
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


def from_entry(entry: Mapping[str, Any]) -> ShieldMode:
    """The mode as the ``blackbox`` config entry states it (defaults when absent).

    ``shields.trader`` when present; otherwise the three legacy keys, so an install that
    never saved since shields arrived stays engaged."""
    shields = entry.get("shields")
    section = shields.get("trader") if isinstance(shields, Mapping) else None
    if not isinstance(section, Mapping):   # never saved since shields: the legacy keys
        section = {"enabled": entry.get("wallet_protection"), ADDRESSES: entry.get("wallet_addresses")}
        if "protected_wallets" in entry:
            section[WALLETS] = entry["protected_wallets"]
    chosen = _wallet_list(section[WALLETS]) if WALLETS in section else None
    return build(enabled=section.get("enabled") is True, wallets=chosen,
                 addresses=_address_list(section.get(ADDRESSES)))


def current() -> ShieldMode:
    """The mode in force now, read from the Hermes config like every other setting."""
    from ...kernel.config import _blackbox_entry   # the one reader of plugins.entries.blackbox

    return from_entry(_blackbox_entry())


def validate(payload: Mapping[str, Any]) -> tuple[str, dict[str, Any], list[str], tuple[str, ...]]:
    """``("trader", section, errors, superseded keys)`` for ``payload["shields"]["trader"]``.

    Unknown wallets and non-booleans are refused, never stored; ``wallets`` holds at most
    every supported wallet once, ``addresses`` at most :data:`MAX_WALLET_ADDRESSES`. A
    section that touches the mode is written COMPLETE — fields the payload leaves out
    keep their current value — because the same save retires the legacy keys (F-009):
    an Engage that sends only ``enabled`` keeps an earlier choice of wallets and addresses.
    """
    shields = payload.get("shields")
    raw = shields.get("trader") if isinstance(shields, Mapping) else None
    if raw is None or raw == {}:
        return "trader", {}, [], LEGACY_KEYS
    if not isinstance(raw, Mapping):
        return "trader", {}, ["shields.trader must be an object"], LEGACY_KEYS
    updates, errors = _validated_fields(raw)
    if errors or not updates:
        return "trader", {}, errors, LEGACY_KEYS
    now = current()
    section = {"enabled": now.enabled, WALLETS: list(wallets(now)), ADDRESSES: list(addresses(now)), **updates}
    return "trader", section, [], LEGACY_KEYS


def _validated_fields(raw: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """``(fields, errors)`` for the mode's fields in one ``shields.trader`` object."""
    updates: dict[str, Any] = {}
    errors: list[str] = []
    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            updates["enabled"] = raw["enabled"]
        else:
            errors.append("shields.trader.enabled must be a boolean")
    if WALLETS in raw:
        chosen, supported = raw[WALLETS], supported_wallets()
        # No list longer than the supported set: a valid one never repeats a wallet (KI-389).
        too_long = isinstance(chosen, list) and len(chosen) > len(supported)
        unknown = [] if too_long else [w for w in (chosen if isinstance(chosen, list) else [chosen])
                                       if str(w or "").lower() not in supported]
        if not isinstance(chosen, list) or too_long or unknown:
            errors.append(f"shields.trader.wallets must be a list of: {', '.join(supported)}")
        else:
            updates[WALLETS] = list(_wallet_list(chosen))
    if ADDRESSES in raw:
        listed = raw[ADDRESSES]
        items = listed if isinstance(listed, list) and len(listed) <= MAX_WALLET_ADDRESSES else None
        bad = [a for a in items or [] if not _ADDRESS.match(str(a or "").strip())]
        if items is None or bad:
            errors.append(f"shields.trader.addresses must be a list of up to {MAX_WALLET_ADDRESSES} "
                          "addresses like 0x followed by 40 hex characters")
        else:
            updates[ADDRESSES] = list(_address_list(items))
    return updates, errors
