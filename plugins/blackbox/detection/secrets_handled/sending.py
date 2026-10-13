"""How a secret leaves the machine: commands that send, web addresses, network-calling scripts.

A secret VALUE an agent merely handles (a key in its own config) is flagged; the same
value on its way OFF the machine is exfiltration and blocks. These predicates say
whether a tool call's text sends what it holds. Pure, linear-time regex checks.

Usage::

    looks_like_egress("curl -d @- https://x")      # -> True: a command that sends data
    looks_like_script_send("requests.post(url)")   # -> True: script code that calls the network
    url_payloads("GET https://x/?d=a+b")           # -> "https://x/?d=a b": what rides in each URL
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

# Commands that SEND data off-box — a secret value alongside one of these is
# exfiltration (critical/block), not routine handling.
_EGRESS_RE = re.compile(
    r"\b(?:nc|ncat|netcat|telnet|sendmail)\b"
    r"|\b(?:curl|wget)\b[\s\S]{0,300}(?:\s-d\b|--data|--data-binary|--data-raw|\s-F\b|--form|\s-T\b|--upload-file)"
    r"|\|\s*(?:nc|ncat|curl|wget)\b",
    re.IGNORECASE,
)


def looks_like_egress(text: str) -> bool:
    """True when *text* contains a command that sends data off the machine."""
    return bool(text and _EGRESS_RE.search(text))


#: A web address in text (the part a secret would ride in: path, query, fragment).
_URL = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)
#: Script code that talks to the network — an HTTP client, a raw socket, mail. A wallet
#: secret in the same code is being sent (python requests/httpx/urllib, JS fetch/axios/
#: http(s).request, PowerShell Invoke-WebRequest/-RestMethod, Ruby Net::HTTP, PHP curl).
_SCRIPT_SEND_RE = re.compile(
    r"\brequests\.(?:get|post|put|patch|request)\s*\(|\bhttpx\.(?:get|post|put|patch|request|Client|AsyncClient)\b"
    r"|\burlopen\s*\(|\burllib\.request\b|\bfetch\s*\(|\baxios(?:\.(?:get|post|put|patch|request))?\s*\("
    r"|\bhttps?\.(?:request|get)\s*\(|\bXMLHttpRequest\b|\bInvoke-(?:WebRequest|RestMethod)\b|\b(?:iwr|irm)\s"
    r"|\bsmtplib\b|\bsocket\.(?:connect|create_connection)\b|\bnet\.connect\s*\(|\bNet::HTTP\b|\bcurl_exec\s*\(",
    re.IGNORECASE,
)


def url_payloads(text: str) -> str:
    """Every web address in *text*, decoded (``+`` and ``%20`` back to spaces), one per
    line — what a secret looks like after it has been written into a URL."""
    return "\n".join(unquote_plus(url) for url in _URL.findall(text or ""))


def looks_like_script_send(text: str) -> bool:
    """True when *text* holds script code that makes a network call."""
    return bool(text and _SCRIPT_SEND_RE.search(text))
