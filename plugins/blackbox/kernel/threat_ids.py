"""Deterministic threat identifiers and URIs — the shared naming vocabulary.

Two independent nodes that see the same threat must compute the same
identifier (``dep:npm:pkg@1.2.3``, ``injection:<hash>``, ``ioc:domain:…``) so
they converge on one Threat knowledge asset. Byte-for-byte compatible with the
original TypeScript builders and the OpenClaw port (tests/parity pins it).

Usage: ``threat_ids.dependency_identifier("npm", "left-pad", "1.3.0")`` ·
``threat_ids.ioc_identifier("domain", "Evil.Example.")`` · ``threat_ids.report_uri(ident, reporter)``.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Hashing / slugs / URIs
# ---------------------------------------------------------------------------


def stable_hash(value: str, length: int = 24) -> str:
    """SHA-256 hex digest of *value*, truncated to *length* chars."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_SLUG_TRIM_RE = re.compile(r"^-+|-+$")


def slug(value: str) -> str:
    """Lowercase, replace runs of non ``[a-z0-9._-]`` with ``-``, cap at 96 chars."""
    lowered = _SLUG_RE.sub("-", str(value).lower())
    trimmed = _SLUG_TRIM_RE.sub("", lowered)[:96]
    return trimmed or "unknown"


# The legacy ``urn:guardian:`` subject schemes (and ontology IRI in
# kernel/constants.py) remain byte-stable so the already-published threat corpus stays
# addressable and queryable.
def threat_uri(identifier: str) -> str:
    """Stable curated-threat subject URI for a threat *identifier*."""
    return f"urn:guardian:threat:{slug(identifier)}"


def report_uri(identifier: str, agent_address: str) -> str:
    """Per-submitter namespaced report subject URI.

    SWM root entities are first-writer-wins, so each submitter's sighting of a
    threat gets its own subject: ``urn:guardian:report:{addrLower}:{h}`` where
    ``h`` is ``sha256(identifier)[:16]``. Counting distinct reporters of a
    threat therefore counts distinct namespaces. Raises ``ValueError`` for a
    blank address (no fallback identity, LES-003).
    """
    addr = str(agent_address or "").strip().lower()
    if not addr:
        # LES-003 / KI-003: a shared placeholder ("anonymous") would merge every
        # identity-less node onto one subject — refuse, never substitute.
        raise ValueError("a report subject needs a resolved reporter address")
    return f"urn:guardian:report:{addr}:{stable_hash(identifier, 16)}"


# ---------------------------------------------------------------------------
# Identifier builders
# ---------------------------------------------------------------------------


def canonical_package_name(ecosystem: str, name: str) -> str:
    """Canonicalize a package name so the same package always maps to one key.

    PyPI treats names case- AND separator-insensitively (PEP 503): ``Foo.Bar``,
    ``foo-bar`` and ``foo_bar`` are the same project, so runs of ``-_.`` collapse
    to a single ``-``. Every other ecosystem is only lowercased (npm is
    case-insensitive; RubyGems/cargo/go names are separator-*sensitive*, so
    collapsing there would wrongly merge distinct packages).
    """
    canon = name.strip().lower()
    if ecosystem.strip().lower() == "pypi":
        canon = re.sub(r"[-_.]+", "-", canon)
    return canon


def dependency_key(ecosystem: str, name: str, version: str) -> str:
    """The ruleset lookup key ``{ecosystem}:{canonical-name}@{version}``.

    Shared by the detector and the ruleset builder so a graph id and a live
    lookup are byte-identical for any spelling of the same package.
    """
    return f"{ecosystem.strip().lower()}:{canonical_package_name(ecosystem, name)}@{version.strip()}"


def dependency_identifier(ecosystem: str, name: str, version: str) -> str:
    """``dep:{ecosystem}:{canonical-name}@{version}`` (see :func:`dependency_key`)."""
    return f"dep:{dependency_key(ecosystem, name, version)}"


def parse_dependency_identifier(identifier: str) -> Optional[Tuple[str, str, str]]:
    """``(ecosystem, name, version)`` of a ``dep:`` identifier, else None."""
    if not identifier.startswith("dep:") or "@" not in identifier:
        return None
    try:
        _, ecosystem, rest = identifier.split(":", 2)
        name, version = rest.rsplit("@", 1)
    except ValueError:
        return None
    return (ecosystem, name, version) if ecosystem and name and version else None


def injection_identifier(pattern: str) -> str:
    """``injection:{sha256(pattern)[:24]}``."""
    return f"injection:{stable_hash(pattern, 24)}"


def escalation_identifier(tool_name: str, arg_shape: str) -> str:
    """``escalation:{tool}:{argShape}`` — the human-readable escalation id.

    The shape is kept literal (not hashed) so the id is legible, e.g.
    ``escalation:shell:remote-script-pipe``. The detector emits lowercase
    hyphenated slugs, so both tool and shape are lowercased here — a
    graph rule that differs only in case still matches.
    """
    return f"escalation:{tool_name.strip().lower()}:{arg_shape.strip().lower()}"


def fileaccess_identifier(tool_name: str, category: str) -> str:
    """``fileaccess:{tool}:{category}`` — e.g. ``fileaccess:read_file:ssh-private-key``.

    Both parts are kept literal (lowercased) so the id is legible and two nodes
    that touch the same sensitive-path category converge on one threat KA.
    """
    return f"fileaccess:{tool_name.strip().lower()}:{category.strip().lower()}"


def skill_version_identifier(name: str, version: str) -> str:
    """``skill:{name}@{version}`` — the known-bad (graph-matched) skill id."""
    return f"skill:{name.strip().lower()}@{version.strip()}"


def skill_artifact_identifier(artifact_hash: str, danger_shape: str) -> str:
    """``skill:artifact:{sha256}:{shape}`` — a local/unknown skill named by its
    code hash, never its name (Refine R1, KI-159)."""
    return f"skill:artifact:{artifact_hash.strip().lower()}:{danger_shape.strip().lower()}"


def skill_shape_identifier(name: str, danger_shape: str) -> str:
    """``skill:{name}:{dangerShape}`` — a heuristic dangerous-code/permission id."""
    return f"skill:{name.strip().lower()}:{danger_shape.strip()}"


# ---------------------------------------------------------------------------
# IOC identifiers (network + crypto indicators)
# ---------------------------------------------------------------------------

#: The indicator types a published ``ioc:`` threat can carry. ``domain``/``url``/
#: ``ip`` are network indicators; ``hash`` is a file digest; ``wallet``/
#: ``contract`` are crypto addresses. All match against agent tool-call text.
IOC_TYPES = ("domain", "url", "ip", "hash", "wallet", "contract")

EVM_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _idna_host(host: str) -> str:
    """Punycode-normalize an internationalized hostname (KI-026).

    The unicode and punycode spellings of one domain are the SAME network
    name; without this, ``münchen.example`` and ``xn--mnchen-3ya.example``
    would derive different identifiers and split corroboration counting.
    ASCII hosts pass through untouched; malformed labels fail open verbatim
    (a broken name that cannot match is safer than a dropped finding).
    """
    if all(ord(ch) < 128 for ch in host):
        return host
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    """Canonicalize an IOC value so a graph id and a live match are identical.

    Domains/URLs/IPs/EVM-addresses/hashes lower-case (the network + EVM name
    spaces are case-insensitive); base58 crypto addresses (BTC/Solana) are
    case-*sensitive* and kept verbatim. URLs drop a trailing slash and lower
    only scheme+host so the path stays exact; IPs drop any ``:port``.
    Internationalized domain/URL hosts are punycode-normalized so unicode and
    punycode spellings of one domain converge on one identifier.
    """
    t = (ioc_type or "").strip().lower()
    raw = str(value or "").strip()
    if not raw:
        return ""
    if t == "domain":
        return _idna_host(raw.rstrip(".").lower())
    if t == "url":
        parts = raw.split("://", 1)
        if len(parts) == 2:
            host_path = parts[1].split("/", 1)
            host = _idna_host(host_path[0].lower())
            rest = ("/" + host_path[1]) if len(host_path) == 2 else ""
            raw = f"{parts[0].lower()}://{host}{rest}"
        return raw.rstrip("/")
    if t == "ip":
        return raw.split(":", 1)[0]
    if t == "hash":
        return raw.lower()
    if t in ("wallet", "contract"):
        return raw.lower() if EVM_ADDRESS_RE.fullmatch(raw) else raw
    return raw


def ioc_identifier(ioc_type: str, value: str) -> str:
    """``ioc:{type}:{normalized-value}`` — the shared IOC id (see :func:`normalize_ioc_value`)."""
    return f"ioc:{(ioc_type or '').strip().lower()}:{normalize_ioc_value(ioc_type, value)}"
