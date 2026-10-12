"""The site a verified prompt injection was found on, as its own finding (threat-profiles D8).

When a VERIFIED injection pattern turns up in a page a web tool fetched during
this turn, the page's site is a threat indicator too: it is raised as an IOC
finding ``ioc:domain:<registrable domain>`` with reason ``injection-host``, so
the operator sees which site carried it and other nodes flag that site. Only
verified matches trigger this (LES-018: an untrusted pattern never makes this
node publish anything), only the registrable domain is used, and popular or
user-content platforms are never named (:func:`..community.injection_host_identifier`).

Usage (from the pre-API hook)::

    findings += injection_site_findings(findings, request_messages, rs)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Tuple

from .. import community, detection
from . import session_context

_URL_KEYS = ("url", "uri", "href", "link")


def _call_urls(messages: List[Any]) -> Dict[str, Tuple[str, str]]:
    """``tool_call_id`` -> (fetch tool name, the URL it was given)."""
    urls: Dict[str, Tuple[str, str]] = {}
    for msg in messages:
        calls = msg.get("tool_calls") if isinstance(msg, Mapping) else None
        for call in calls if isinstance(calls, list) else []:
            function = call.get("function") if isinstance(call, Mapping) else None
            if not isinstance(function, Mapping) or not call.get("id"):
                continue
            tool = str(function.get("name") or "").lower()
            if not tool.startswith(detection.FETCH_TOOL_PREFIXES):
                continue
            args = function.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            url = next((str(args[k]) for k in _URL_KEYS if isinstance(args, Mapping) and args.get(k)), "")
            if url:
                urls[str(call["id"])] = (tool, url)
    return urls


def _fetched_pages(messages: List[Any]) -> List[Tuple[str, str, str]]:
    """(fetch tool, url, page text) for every fetched page returned since the last user turn."""
    start = max((i for i, m in enumerate(messages) if isinstance(m, Mapping) and m.get("role") == "user"), default=0)
    urls = _call_urls(messages)
    pages = []
    for msg in messages[start:]:
        if isinstance(msg, Mapping) and msg.get("role") == "tool" and str(msg.get("tool_call_id") or "") in urls:
            pages.append((*urls[str(msg["tool_call_id"])], session_context._message_text(msg.get("content"))))
    return pages


def injection_site_findings(findings: List[detection.Finding], request_messages: Any, rs: Any) -> List[detection.Finding]:
    """One ``injection-host`` IOC finding per site that carried a VERIFIED
    injection found in a fetched page this turn (deduplicated)."""
    verified = {f.identifier: f for f in findings
                if f.category == "injection" and f.source == "public" and f.fields.get("context") == "in-fetched-page"}
    if not verified:
        return []
    messages = request_messages if isinstance(request_messages, list) else []
    out: Dict[str, detection.Finding] = {}
    for tool, url, text in _fetched_pages(messages):
        matched = [f for f in detection.detect_injection(text, rs, "in-fetched-page") if f.identifier in verified]
        site = community.injection_host_identifier(url) if matched else None
        if not site or site in out:
            continue
        injection = verified[matched[0].identifier]
        domain = site.split(":", 2)[2]
        out[site] = detection.Finding(
            identifier=site, category="ioc", severity=injection.severity, tool_name=tool,
            title=f"Site carried a prompt injection ({injection.title})", matched=domain,
            evidence=f"domain {domain} served {injection.identifier}", confirmed=False, source="heuristic",
            kind="injection-host",
            fields={"ioc_type": "domain", "ioc_context": "fetched-by-tool", "reason": "injection-host"})
    return list(out.values())
