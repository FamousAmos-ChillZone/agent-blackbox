"""The program that runs INSIDE each sandbox: ``python -m threat_lab.probe <step> …``.

Three steps, each printing one JSON report on stdout:

* ``look <identifier>`` — level 1: unauthenticated look-ups only. DNS and the
  TLS certificate for a domain or URL; the public registry record for a
  package; the public transaction history of a wallet. No page is rendered,
  nothing is submitted, no keyed source is asked (those run on the Umanitek
  node, F-056).
* ``fetch <identifier> <dest>`` — level 2, network on: download the package
  archive or skill file to *dest* and nothing else. A pip/npm client is never
  used: both can run code on download.
* ``read <path>`` — level 2, network OFF and files read-only: apply
  :mod:`threat_lab.rules` to the downloaded file.

Status values: ``ok``, ``unreachable``, ``tls-error``, ``too-large``,
``malformed`` (a registry answer without the expected fields), ``unsupported``. Every host the probe opened a connection to is listed under
``hosts`` — that list is the evidence's ``contacted_hosts``.

The probe imports nothing from the plugin and holds no credentials.
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

from . import rules
from .identifiers import Target, TargetKind, parse_target

HTTP_TIMEOUT_SECONDS = 15.0
MAX_METADATA_BYTES = 5_000_000
MAX_DOWNLOAD_BYTES = 50_000_000
MAX_REDIRECTS = 3
USER_AGENT = "threat-lab/1 (+public look-up only)"
#: Unauthenticated public wallet-history endpoints.
EVM_RPC_URL = "https://ethereum-rpc.publicnode.com"
BTC_ADDRESS_URL = "https://blockstream.info/api/address/{address}"


class _TooLarge(Exception):
    """A body past its cap."""


def _status_of(error: BaseException) -> str:
    """The report status for an error a look-up or download raised."""
    if isinstance(error, _TooLarge):
        return "too-large"
    # urllib wraps a certificate failure in URLError(reason=SSLError).
    if isinstance(error, ssl.SSLError) or isinstance(getattr(error, "reason", None), ssl.SSLError):
        return "tls-error"
    if isinstance(error, OSError):
        return "unreachable"
    return "malformed"


#: What a look-up or download may raise: network errors, and a registry answer
#: that is not the JSON shape expected.
_PROBE_ERRORS = (_TooLarge, OSError, ValueError, KeyError, IndexError, TypeError, AttributeError)


class _Fetch:
    """HTTPS fetches that record every host contacted and cap every body."""

    def __init__(self) -> None:
        self.hosts: list[str] = []
        recorder = self

        class _Redirects(urllib.request.HTTPRedirectHandler):
            max_redirections = MAX_REDIRECTS

            def redirect_request(self, request, fp, code, message, headers, new_url):
                if urlsplit(new_url).scheme != "https":
                    raise urllib.error.URLError("redirect off https")
                recorder._note(new_url)
                return super().redirect_request(request, fp, code, message, headers, new_url)

        self._opener = urllib.request.build_opener(_Redirects)

    def _note(self, url: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        if host and host not in self.hosts:
            self.hosts.append(host)

    def get(self, url: str, cap: int, body: Optional[bytes] = None) -> bytes:
        """The body at *url* (POST when *body* is given). Raises :class:`_TooLarge`
        past *cap* bytes and ``OSError`` (incl. ssl errors) when unreachable."""
        if urlsplit(url).scheme != "https":
            raise urllib.error.URLError("https only")
        self._note(url)
        headers = {"User-Agent": USER_AGENT}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers)
        with self._opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            data = response.read(cap + 1)
        if len(data) > cap:
            raise _TooLarge(url)
        return data


def look(identifier: str) -> dict[str, object]:
    """Level 1 report for *identifier*."""
    target = parse_target(identifier)
    fetch = _Fetch()
    status, details = "unsupported", {}
    try:
        if target.kind in (TargetKind.DOMAIN, TargetKind.URL):
            status, details = _look_host(target.host, fetch)
        elif target.kind is TargetKind.PACKAGE:
            metadata = json.loads(fetch.get(_registry_url(target), MAX_METADATA_BYTES))
            status, details = "ok", {"registry": _registry_summary(target, metadata)}
        elif target.kind is TargetKind.WALLET:
            status, details = "ok", {"wallet": _wallet_history(target, fetch)}
    except _PROBE_ERRORS as error:
        status = _status_of(error)
    return {"step": "look", "status": status, "hosts": fetch.hosts, "details": details}


def fetch_artifact(identifier: str, destination: str) -> dict[str, object]:
    """Level 2 download of *identifier*'s code to *destination*."""
    target = parse_target(identifier)
    fetch = _Fetch()
    report: dict[str, object] = {"step": "fetch", "status": "unsupported", "hosts": fetch.hosts}
    try:
        if target.kind is TargetKind.PACKAGE:
            metadata = json.loads(fetch.get(_registry_url(target), MAX_METADATA_BYTES))
            url = _archive_url(target, metadata)
        elif target.kind is TargetKind.URL:
            url = target.url
        else:
            return report
        data = fetch.get(url, MAX_DOWNLOAD_BYTES)
    except _PROBE_ERRORS as error:
        report["status"] = _status_of(error)
        return report
    with open(destination, "wb") as handle:
        handle.write(data)
    report.update(status="ok", sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    return report


def read(path: str) -> dict[str, object]:
    """Level 2 reading report for the file at *path*."""
    with open(path, "rb") as handle:
        data = handle.read(rules.MAX_TOTAL_BYTES + 1)
    report = json.loads(rules.read_artifact(data).to_json())
    report.update(step="read", status="ok")
    return report


def _look_host(host: str, fetch: _Fetch) -> tuple[str, dict[str, object]]:
    addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    fetch.hosts.append(host)
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=HTTP_TIMEOUT_SECONDS) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            certificate = tls.getpeercert(binary_form=True) or b""
            subject = tls.getpeercert() or {}
    return "ok", {"addresses": addresses, "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
                  "not_after": subject.get("notAfter", "")}


def _registry_url(target: Target) -> str:
    if target.ecosystem == "npm":
        return f"https://registry.npmjs.org/{quote(target.name, safe='@')}/{quote(target.version)}"
    return f"https://pypi.org/pypi/{quote(target.name)}/{quote(target.version)}/json"


def _registry_summary(target: Target, metadata: dict) -> dict[str, object]:
    if target.ecosystem == "npm":
        scripts = metadata.get("scripts") or {}
        return {"install_scripts": sorted(s for s in rules.NPM_INSTALL_SCRIPTS if s in scripts),
                "tarball_shasum": (metadata.get("dist") or {}).get("shasum", "")}
    info = metadata.get("info") or {}
    return {"files": [entry.get("packagetype", "") for entry in metadata.get("urls") or []],
            "yanked": bool(info.get("yanked"))}


def _archive_url(target: Target, metadata: dict) -> str:
    if target.ecosystem == "npm":
        return metadata["dist"]["tarball"]
    files = metadata["urls"]
    # The source distribution carries setup.py (the install hook); a wheel otherwise.
    chosen = [entry for entry in files if entry.get("packagetype") == "sdist"] or files
    return chosen[0]["url"]


def _wallet_history(target: Target, fetch: _Fetch) -> dict[str, object]:
    if target.chain == "evm":
        request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount",
                              "params": [target.address, "latest"]}).encode("ascii")
        answer = json.loads(fetch.get(EVM_RPC_URL, MAX_METADATA_BYTES, body=request))
        return {"chain": "evm", "transaction_count": int(str(answer.get("result", "0x0")), 16)}
    answer = json.loads(fetch.get(BTC_ADDRESS_URL.format(address=target.address), MAX_METADATA_BYTES))
    chain_stats = answer.get("chain_stats") or {}
    return {"chain": "btc", "transaction_count": int(chain_stats.get("tx_count", 0))}


def main(argv: list[str]) -> int:
    if argv[:1] == ["look"] and len(argv) == 2:
        report = look(argv[1])
    elif argv[:1] == ["fetch"] and len(argv) == 3:
        report = fetch_artifact(argv[1], argv[2])
    elif argv[:1] == ["read"] and len(argv) == 2:
        report = read(argv[1])
    else:
        print('{"status":"usage"}')
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
