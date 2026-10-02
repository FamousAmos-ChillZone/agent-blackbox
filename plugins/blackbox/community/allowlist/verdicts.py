"""The allowlist verdict on one threat identifier (R9, plan §06, look-alike rule inverted).

* HOLD_EXACT — the identifier names an allowlisted brand BYTE-FOR-BYTE
  (``ioc:domain:paypal.com``, a URL on it, ``dep:npm:lodash@*`` name-level):
  almost certainly a report against the real thing → HELD, weight 0, until
  a curator looks.
* SUPPORT_CONFUSABLE — the name merely LOOKS like an allowlisted one
  (skeleton match after homoglyph folding, or edit distance ≤ 2): almost
  certainly impersonation → the report is SUPPORTED and tagged
  ``confusable-of:<name>``. A look-alike never holds.
* HOLD_WARNINGLIST — a name-level (``@*``) or ``kind=vulnerability`` report
  against a popular package → HELD; a version-pinned malware report on the
  same package COUNTS (hijacked popular packages are the real threat).
* NONE — nothing to say.

Pure functions over the loaded tables; nothing here reads the network.

Usage::

    verdict = check("ioc:domain:paypa1.com")           # SUPPORT_CONFUSABLE, confusable_of="paypal.com"
    verdict = check("dep:npm:lodash@*")                 # HOLD_WARNINGLIST (and HOLD_EXACT if lodash were allowlisted)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Optional

from ...kernel import threat_ids
from . import tables

#: Edit distance at or under this (after skeleton folding) is a look-alike.
CONFUSABLE_DISTANCE = 2
#: Homoglyph folding: what an eye reads the same (plan: "skeleton match").
_SKELETON = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "5": "s", "7": "t", "8": "b", "9": "g",
                           "$": "s", "@": "a", "4": "a", "6": "b", "-": "", "_": "", ".": ""})


class AllowlistVerdict(Enum):
    NONE = "none"
    HOLD_EXACT = "hold-exact"
    SUPPORT_CONFUSABLE = "support-confusable"
    HOLD_WARNINGLIST = "hold-warninglist"


@dataclass(frozen=True)
class Verdict:
    """``verdict`` plus ``confusable_of`` (the allowlisted name a look-alike
    resembles, else empty) and a one-line ``reason``."""

    verdict: AllowlistVerdict
    reason: str
    confusable_of: str = ""

    @property
    def holds(self) -> bool:
        return self.verdict in (AllowlistVerdict.HOLD_EXACT, AllowlistVerdict.HOLD_WARNINGLIST)


def skeleton(name: str) -> str:
    """The homoglyph-folded form two eyes would confuse (``paypa1`` → ``paypal``, ``rn`` → ``m``)."""
    return name.lower().translate(_SKELETON).replace("rn", "m").replace("vv", "w").replace("cl", "d")


def edit_distance(a: str, b: str, limit: int = CONFUSABLE_DISTANCE) -> int:
    """Levenshtein distance, capped at ``limit + 1`` (early exit keeps the
    per-name cost small over a few hundred allowlisted names)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def confusable_of(name: str, allowlisted: Iterable[str]) -> Optional[str]:
    """The allowlisted name *name* looks like (skeleton equality, or edit
    distance ≤ 2 on the registrable label), or None. Never the name itself."""
    label = name.lower()
    folded = skeleton(label)
    for candidate in sorted(allowlisted):
        if candidate == label:
            continue
        if skeleton(candidate) == folded or edit_distance(label, candidate) <= CONFUSABLE_DISTANCE:
            return candidate
    return None


def _host_of(identifier: str) -> str:
    """The host an ``ioc:domain:`` / ``ioc:url:`` identifier names."""
    value = identifier.split(":", 2)[2] if identifier.count(":") >= 2 else ""
    if identifier.startswith("ioc:url:"):
        value = value.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
    return value.split(":")[0].lower().strip(".")


def check(identifier: str, fields: Optional[Mapping[str, str]] = None,
          loaded: Optional[tables.AllowTables] = None) -> Verdict:
    """The verdict for one community threat identifier (*fields* — the
    report's closed fields, for ``kind``)."""
    table = loaded or tables.load()
    kind = str((fields or {}).get("kind") or "").lower()
    if identifier.startswith(("ioc:domain:", "ioc:url:")):
        host = _host_of(identifier)
        if not host:
            return Verdict(AllowlistVerdict.NONE, "no host in the identifier")
        key = tables.allowlist_key(host)
        if key in table.domains:
            return Verdict(AllowlistVerdict.HOLD_EXACT, f"names the allowlisted domain {key} byte-for-byte")
        lookalike = confusable_of(key, table.domains)
        if lookalike:
            return Verdict(AllowlistVerdict.SUPPORT_CONFUSABLE, f"looks like {lookalike} — likely impersonation", lookalike)
        return Verdict(AllowlistVerdict.NONE, "not an allowlisted domain")
    parts = threat_ids.parse_dependency_identifier(identifier)
    if parts is None:
        return Verdict(AllowlistVerdict.NONE, "not a domain, URL or dependency")
    ecosystem, name, version = parts
    if table.is_warninglisted_package(ecosystem, name):
        if version == "*" or kind == "vulnerability":
            return Verdict(AllowlistVerdict.HOLD_WARNINGLIST,
                           f"name-level or vulnerability report against the popular package {ecosystem}:{name}")
        return Verdict(AllowlistVerdict.NONE, f"version-pinned {kind or 'report'} on a popular package counts (evidence-first lane)")
    lookalike = confusable_of(name.lower(), {p.split(":", 1)[1] for p in table.packages if p.startswith(ecosystem.lower() + ":")})
    if lookalike:
        return Verdict(AllowlistVerdict.SUPPORT_CONFUSABLE, f"looks like the popular package {lookalike} — likely typosquat", lookalike)
    return Verdict(AllowlistVerdict.NONE, "not a warninglisted package")
