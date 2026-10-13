"""Which files a shell command reads, copies or packs up — the shell channel's file view.

A file tool names its path in an argument; a shell command hides it among
words. An agent (or a poisoned skill steering it) reaches a secret file through
the terminal far more often than through a file tool: ``cat``, ``cp -r``,
``tar czf``, ``zip -r``, ``rsync``, ``ditto``, ``base64``. This module turns a
command line into the paths those commands touch, so a path rule (protected
paths, wallet key stores) sees the shell channel as well as the file tools.

Words are split the way a POSIX shell splits them (quotes and backslash
escapes respected), so ``~/Library/Application\\ Support/...`` stays ONE path.
A command line the shell parser cannot split (an unbalanced quote) falls back
to plain whitespace splitting, so a malformed command still yields its paths.

Usage::

    for arg in shell_file_args("tar czf out.tgz ~/Library/Application\\\\ Support/Google/Chrome"):
        arg.path        # "out.tgz", then "~/Library/Application Support/Google/Chrome"
        arg.recursive   # True for both: tar packs whole folders

Pure and deterministic; reads no files.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import List

#: Commands that read a file's contents.
_READ_COMMANDS = frozenset({
    "cat", "less", "more", "head", "tail", "bat", "xxd", "hexdump", "strings", "od", "nl",
    "base64", "base32", "sqlite3", "jq",
    "type", "get-content", "gc",                       # Windows cmd / PowerShell
})
#: Commands that copy, move or pack whole folders: an argument that is a
#: folder hands over everything inside it.
_RECURSIVE_COMMANDS = frozenset({
    "cp", "scp", "rsync", "tar", "zip", "7z", "7za", "rar", "ditto", "mv", "gzip", "rg",
    "copy", "xcopy", "robocopy", "copy-item", "cpi", "compress-archive", "move-item",   # Windows
})
#: Commands that read whole folders only with a recursive flag.
_RECURSIVE_WITH_FLAG = {"grep": ("-r", "-R", "--recursive"), "egrep": ("-r", "-R"), "fgrep": ("-r", "-R")}
_SEPARATORS = frozenset({";", "&&", "||", "|", "&", ">", ">>", "<", "|&"})


@dataclass(frozen=True)
class ShellFileArg:
    """One path a shell command touches. ``path`` is the word as written (``~``
    and ``$HOME`` NOT expanded — matching code expands); ``recursive`` is True
    when the command takes a folder argument as everything inside it."""

    path: str
    command: str
    recursive: bool


#: A Windows path (``C:\\Users``, ``%APPDATA%\\``): backslash is a separator there,
#: not an escape, so such a line is split without POSIX escaping.
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\|%[A-Za-z_]+%\\")


def _words(command: str) -> List[str]:
    try:
        if _WINDOWS_PATH.search(command):
            lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            return [word.strip("\"'") for word in lexer]
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:  # an unbalanced quote: still find the paths
        return command.split()


def _looks_like_path(word: str) -> bool:
    return "/" in word or "\\" in word or word.startswith(("~", ".", "$HOME", "%")) or "." in word


def shell_file_args(command: str) -> List[ShellFileArg]:
    """Every path argument of a read, copy or archive command in *command*.

    Flags (``-r``, ``-czf``) are skipped; an argument after a separator
    (``;``, ``&&``, ``|``, a redirect) belongs to the next command. Duplicates
    are removed, first occurrence kept.
    """
    if not command:
        return []
    words = _words(command)
    out: List[ShellFileArg] = []
    seen: set = set()
    index = 0
    while index < len(words):
        name = words[index].rsplit("/", 1)[-1].lower()
        reads = name in _READ_COMMANDS
        recursive = name in _RECURSIVE_COMMANDS
        flags = _RECURSIVE_WITH_FLAG.get(name)
        if not (reads or recursive or flags):
            index += 1
            continue
        end = index + 1
        while end < len(words) and words[end] not in _SEPARATORS:
            end += 1
        arguments = words[index + 1:end]
        if flags:
            recursive = any(word in flags or (word.startswith("-") and not word.startswith("--")
                                              and ("r" in word or "R" in word)) for word in arguments)
        for word in arguments:
            if word.startswith("-") or not _looks_like_path(word) or word in seen:
                continue
            seen.add(word)
            out.append(ShellFileArg(path=word, command=name, recursive=recursive))
        index = end
    return out
