"""The site a prompt injection was found on, as a reportable indicator (threat-profiles D8).

When a VERIFIED injection pattern is found in a page a web tool fetched, the
page's site is itself a threat indicator. It is reported as its registrable
domain (``evil.example`` for ``a.b.evil.example``; a shared-hosting tenant such
as ``evil.github.io`` stays the tenant) — never the path, query or full URL. A
host on the allowlist (popular brands and platforms where anyone can post) is
never reported: a comment on a big platform says nothing about the platform.

Why the registrable domain and not the full host: an attacker can give every
target its own sub-domain and then watch which reporter names which one. Cutting
to the registrable domain makes that cost a domain per target.

Usage::

    injection_host_identifier("https://x.evil.example/page?q=1")   # "ioc:domain:evil.example"
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlsplit

from ...kernel import public_suffix, threat_ids
from .. import allowlist

#: Platforms where anyone can publish a page: an injection posted there names the
#: poster, not the platform. Never reported (beside the allowlist's own brands).
USER_CONTENT_PLATFORMS = frozenset({
    "reddit.com", "medium.com", "substack.com", "stackoverflow.com", "stackexchange.com", "wikipedia.org",
    "pastebin.com", "quora.com", "discord.com", "t.me", "telegram.org", "notion.so", "notion.site",
    "bitbucket.org", "ycombinator.com", "dev.to", "hashnode.dev", "wordpress.com", "blogspot.com", "tumblr.com",
})


def injection_host_identifier(url: str) -> Optional[str]:
    """``ioc:domain:<registrable domain>`` for the page at *url*, or None when
    there is no reportable site (no host, an IP, a bare public suffix, a
    malformed name, or an allowlisted site)."""
    try:
        host = (urlsplit(str(url or "").strip()).hostname or "").strip(".").lower()
    except ValueError:
        return None
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return None
    domain = public_suffix.registrable_domain(host)
    if not domain or not threat_ids.ioc_value_is_well_formed("domain", domain):
        return None
    if domain in USER_CONTENT_PLATFORMS or allowlist.load().is_allowlisted_domain(domain):
        return None
    return threat_ids.ioc_identifier("domain", domain)
