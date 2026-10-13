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
#: Copy and move commands whose LAST path argument is where things go, not what is read
#: (unless ``-t``/``--target-directory`` names the destination up front).
_COPY_COMMANDS = frozenset({"cp", "scp", "rsync", "mv", "ditto", "copy", "xcopy", "robocopy", "copy-item", "cpi", "move-item"})
#: Archivers whose FIRST path argument is the archive being written (tar names it after ``f``).
_ARCHIVE_FIRST = frozenset({"zip", "7z", "7za", "rar"})


@dataclass(frozen=True)
class ShellFileArg:
    """One path a shell command touches. ``path`` is the word as written (``~``
    and ``$HOME`` NOT expanded — matching code expands); ``recursive`` is True
    when the command takes a folder argument as everything inside it."""

    path: str
    command: str
    recursive: bool
    #: True for where a copy or archive WRITES (``cp src DEST``, ``tar czf OUT.tgz``) —
    #: nothing is read from it. Rules about what leaves a file skip these.
    destination: bool = False


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
    are removed, first occurrence kept. Where a copy or archive writes is marked
    ``destination`` (:func:`_destinations`).
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
        paths = [word for word in arguments if not word.startswith("-") and _looks_like_path(word)]
        written = _destinations(name, arguments, paths)
        for word in paths:
            if word in seen:
                continue
            seen.add(word)
            out.append(ShellFileArg(path=word, command=name, recursive=recursive, destination=word in written))
        index = end
    return out


def _destinations(name: str, arguments: List[str], paths: List[str]) -> set:
    """The path arguments *name* writes to rather than reads: a copy's last path
    (``-t DIR`` names it up front instead), tar's word after an ``f`` flag when it
    creates (``c``/``r``/``u``; extracting or listing reads it), zip's
    and 7z's first path, Compress-Archive's ``-DestinationPath``."""
    if name in _COPY_COMMANDS:
        for flag, value in zip(arguments, arguments[1:]):
            if flag in ("-t", "--target-directory"):
                return {value}
        targets = [word for word in arguments if word.startswith("--target-directory=")]
        if targets:
            return {targets[0].split("=", 1)[1]}
        return {paths[-1]} if len(paths) >= 2 else set()
    if name == "tar":
        # Short flags, plus tar's old-style first word without a dash (``tar xzf in.tgz``).
        clusters = [word.lstrip("-") for position, word in enumerate(arguments)
                    if (word.startswith("-") and not word.startswith("--")) or (position == 0 and word.isalpha())]
        if any(set(cluster) & {"x", "t"} for cluster in clusters) or {"--extract", "--list", "--get"} & set(arguments):
            return set()   # extracting or listing: the archive is READ
        for flag, value in zip(arguments, arguments[1:]):
            if not flag.startswith("--") and "f" in flag.lstrip("-") and flag.lstrip("-").isalpha():
                return {value}
        return set()
    if name in _ARCHIVE_FIRST:
        return {paths[0]} if paths else set()
    if name == "compress-archive":
        lowered = [word.lower() for word in arguments]
        if "-destinationpath" in lowered:
            position = lowered.index("-destinationpath")
            return {arguments[position + 1]} if position + 1 < len(arguments) else set()
    return set()
