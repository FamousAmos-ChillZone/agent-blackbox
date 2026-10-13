"""What a job asks the lab to test: the identifier, query-stripped, and the
target it names.

Data protection (F-023): a URL query string, fragment or user name/password
can carry personal data, so :func:`strip_query` runs at the API boundary before
the identifier is stored, logged or handed to a sandbox. It mirrors the
curator's ``curate/lab/jobs.strip_query`` byte for byte (the runner may not
import it; ``tests/plugins/test_blackbox_lab_evidence.py`` pins the parity),
and :func:`threat_digest` is the first part of the job key the curator built.

Identifier shapes the lab understands (``kernel/threat_ids.py`` names them):

* ``dep:npm:<name>@<version>`` / ``dep:pypi:<name>@<version>`` — a package
* ``url:<https url>`` / ``ioc:url:<url>`` — a page or a skill file
* ``domain:<host>`` / ``ioc:domain:<host>`` — a domain
* ``ioc:wallet:<address>`` / ``wallet:<address>`` — a public wallet

Anything else parses to :data:`TargetKind.UNSUPPORTED`; the job then reads
could-not-tell, never a guess.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit, urlunsplit

#: Longest identifier the API accepts (a URL rarely needs more; a body cap backs it).
MAX_IDENTIFIER_CHARS = 2048
#: Where the URL inside an identifier begins: its scheme followed by ``://``.
_URL_START = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_PACKAGE = re.compile(r"^dep:(npm|pypi):((?:@[a-z0-9._~-]+/)?[A-Za-z0-9._~-]+)@([A-Za-z0-9._+!-]+)$")
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_EVM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_ADDRESS = re.compile(r"^(bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$")


class TargetKind(Enum):
    PACKAGE = "package"
    URL = "url"
    DOMAIN = "domain"
    WALLET = "wallet"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class Target:
    """What the probe looks at. ``ecosystem``/``name``/``version`` are set for a
    package, ``url`` for a URL, ``host`` for a URL or domain, ``address`` and
    ``chain`` (``"evm"``/``"btc"``) for a wallet."""

    kind: TargetKind
    host: str = ""
    url: str = ""
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    address: str = ""
    chain: str = ""


def strip_query(identifier: str) -> str:
    """*identifier* without a URL query string, fragment or user name/password.
    Works on a bare URL and on a prefixed one (``url:https://…``); an identifier
    without ``://`` is returned unchanged."""
    url_start = _URL_START.search(identifier)
    if url_start is None:
        return identifier
    prefix, url = identifier[:url_start.start()], identifier[url_start.start():]
    scheme, netloc, path, _query, _fragment = urlsplit(url)
    return prefix + urlunsplit((scheme, netloc.rpartition("@")[2], path, "", ""))


def threat_digest(identifier: str) -> str:
    """sha256 hex of the query-stripped identifier — the curator's job-key prefix."""
    return hashlib.sha256(strip_query(identifier).encode("utf-8")).hexdigest()


def parse_target(identifier: str) -> Target:
    """The :class:`Target` a (query-stripped) identifier names."""
    package = _PACKAGE.match(identifier)
    if package:
        return Target(TargetKind.PACKAGE, ecosystem=package.group(1), name=package.group(2),
                      version=package.group(3))
    for prefix in ("ioc:url:", "url:"):
        if identifier.startswith(prefix):
            return _url_target(identifier[len(prefix):])
    for prefix in ("ioc:domain:", "domain:"):
        if identifier.startswith(prefix):
            host = identifier[len(prefix):].rstrip(".").lower()
            return Target(TargetKind.DOMAIN, host=host) if _HOST.match(host) else _UNSUPPORTED
    for prefix in ("ioc:wallet:", "wallet:"):
        if identifier.startswith(prefix):
            return _wallet_target(identifier[len(prefix):])
    return _UNSUPPORTED


_UNSUPPORTED = Target(TargetKind.UNSUPPORTED)


def _url_target(url: str) -> Target:
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".").lower()
    if parts.scheme not in ("http", "https") or not _HOST.match(host):
        return _UNSUPPORTED
    return Target(TargetKind.URL, host=host, url=url)


def _wallet_target(address: str) -> Target:
    if _EVM_ADDRESS.match(address):
        return Target(TargetKind.WALLET, address=address.lower(), chain="evm")
    if _BTC_ADDRESS.match(address):
        return Target(TargetKind.WALLET, address=address, chain="btc")
    return _UNSUPPORTED
