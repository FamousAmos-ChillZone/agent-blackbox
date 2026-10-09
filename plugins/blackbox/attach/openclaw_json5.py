"""A minimal JSON5 -> JSON converter for OpenClaw's config files.

OpenClaw configs allow comments and trailing commas; this strips them so the
stdlib ``json`` can parse the result. (Quality item G10: no tests yet.)
"""

from __future__ import annotations

import json
import re
from typing import List

def _json5_to_json(text: str) -> str:
    """Convert the JSON5 features commonly used by OpenClaw into strict JSON.

    OpenClaw officially accepts comments, trailing commas, unquoted object keys,
    and single-quoted strings.  Blackbox only needs those syntax features to
    merge one plugin entry; uncommon numeric JSON5 extensions fail safely rather
    than risking replacement of the user's config.
    """
    out: List[str] = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "/" and i + 1 < length and text[i + 1] == "/":
            i += 2
            while i < length and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < length and text[i + 1] == "*":
            i += 2
            while i + 1 < length and text[i : i + 2] != "*/":
                if text[i] in "\r\n":
                    out.append(text[i])
                i += 1
            if i + 1 >= length:
                raise ValueError("unterminated JSON5 block comment")
            i += 2
            continue
        if ch == '"':
            start = i
            i += 1
            escaped = False
            while i < length:
                cur = text[i]
                i += 1
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == '"':
                    break
            else:
                raise ValueError("unterminated JSON5 string")
            out.append(text[start:i])
            continue
        if ch == "'":
            i += 1
            value: List[str] = []
            while i < length:
                cur = text[i]
                i += 1
                if cur == "'":
                    break
                if cur != "\\":
                    value.append(cur)
                    continue
                if i >= length:
                    raise ValueError("unterminated JSON5 escape")
                esc = text[i]
                i += 1
                if esc in "\r\n":
                    if esc == "\r" and i < length and text[i] == "\n":
                        i += 1
                    continue
                mapped = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0"}
                if esc in mapped:
                    value.append(mapped[esc])
                elif esc == "x" and i + 2 <= length:
                    value.append(chr(int(text[i : i + 2], 16)))
                    i += 2
                elif esc == "u" and i + 4 <= length:
                    value.append(chr(int(text[i : i + 4], 16)))
                    i += 4
                else:
                    value.append(esc)
            else:
                raise ValueError("unterminated JSON5 string")
            out.append(json.dumps("".join(value), ensure_ascii=False))
            continue
        out.append(ch)
        i += 1

    cleaned = "".join(out)

    # Quote unquoted object keys without touching string contents.
    keyed: List[str] = []
    i = 0
    while i < len(cleaned):
        ch = cleaned[i]
        if ch == '"':
            start = i
            i += 1
            escaped = False
            while i < len(cleaned):
                cur = cleaned[i]
                i += 1
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == '"':
                    break
            keyed.append(cleaned[start:i])
            continue
        if ch in "{,":
            keyed.append(ch)
            i += 1
            while i < len(cleaned) and cleaned[i].isspace():
                keyed.append(cleaned[i])
                i += 1
            match = re.match(r"[$A-Za-z_][$A-Za-z0-9_]*", cleaned[i:])
            if match:
                key = match.group(0)
                end = i + len(key)
                look = end
                while look < len(cleaned) and cleaned[look].isspace():
                    look += 1
                if look < len(cleaned) and cleaned[look] == ":":
                    keyed.append(json.dumps(key))
                    i = end
                    continue
            continue
        keyed.append(ch)
        i += 1

    # Remove trailing commas outside strings.
    strictish = "".join(keyed)
    final: List[str] = []
    i = 0
    while i < len(strictish):
        ch = strictish[i]
        if ch == '"':
            start = i
            i += 1
            escaped = False
            while i < len(strictish):
                cur = strictish[i]
                i += 1
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == '"':
                    break
            final.append(strictish[start:i])
            continue
        if ch == ",":
            look = i + 1
            while look < len(strictish) and strictish[look].isspace():
                look += 1
            if look < len(strictish) and strictish[look] in "}]":
                i += 1
                continue
        final.append(ch)
        i += 1
    return "".join(final)
