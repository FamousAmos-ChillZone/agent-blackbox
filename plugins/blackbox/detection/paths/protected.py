"""The user's protected paths: a file an agent must not touch unless the operator says so.

The operator lists paths in ``protected_paths`` (defaults: :data:`kernel.config.DEFAULT_PROTECTED_PATHS`
— SSH keys, ``.env`` files, key files, cloud credentials, Blackbox's own state). These
are personal, locally-configured rules (``source="custom"``): they always flag, they
block in block mode (the user wrote the rule), and they are NEVER reported to the
community graph — the matched pattern is the user's own configuration.

Two channels, one rule (KI-363): a file tool names its path; a terminal command
names it among words (``cat .env``, ``tar czf x.tgz ~/.ssh``), read through
:mod:`.shell_files`. A terminal command counts when it READS a protected file or
hands a folder holding one whole to a copy or archive — never for where a copy
writes (``cp .env.example .env`` sets a project up; it reads no secret).

A template (``.env.example``, ``.env.sample``…) is not a secret: it matches only
a pattern that names the template itself.

The macOS keychain has a second door: the ``security`` tool prints a saved
password or dumps the keychain without touching its file (macOS stealers take
the browsers' "Safe Storage" key this way). While a protected pattern covers
``Library/Keychains``, those ``security`` commands count as reading it
(:func:`_reads_keychain`; options checked against ``security <verb> -h``, macOS 15).

Usage::

    detect_custom_fileaccess("read_file", {"path": "~/.ssh/id_rsa"}, ["~/.ssh/*"])
    detect_custom_fileaccess("terminal", {"command": "cat .env"}, [".env"])
    # -> [Finding(category="fileaccess", source="custom", severity="critical", ...)]
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Any, Iterable, List, Tuple

from .. import action_parsing, shell_shapes
from ..finding import Finding
from ...kernel import threat_ids
from . import shell_files

#: Endings that mark a file as a template to copy, not the secret itself.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".default")
#: ``security`` verbs that reveal secrets, with the options that make them do it
#: (empty: the verb always does). ``export`` reveals keys unless limited to certificates.
_KEYCHAIN_SECRET_VERBS = {
    "find-generic-password": ("-w", "-g"),
    "find-internet-password": ("-w", "-g"),
    "dump-keychain": ("-d", "-r"),
    "export": (),
}
_EXPORT_HARMLESS_TYPES = {"certs", "pubkeys"}
#: Words after which the next word is a command being run (not an argument).
_COMMAND_POSITION = frozenset({";", "&&", "||", "|", "&", "sudo", "exec", "command", "nohup", "time", "env"})
#: ``NAME=`` before a command (``K=$(security …)`` after the substitution is opened up).
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: What a secret-printing ``security`` command is taken to read: the user's keychain folder.
_KEYCHAIN_FOLDER = "~/Library/Keychains/login.keychain-db"


def _protected_path_match(path: str, pattern: str) -> bool:
    """True when *path* matches a user's protected-path *pattern*.

    Patterns are matched three ways so plain paths, directories, and globs all
    behave intuitively: exact/glob match on the full expanded path, glob match
    on the basename (``*.pem``), and prefix match when the pattern names a
    directory (``~/secrets`` protects everything under it).
    """
    try:
        norm_path = os.path.normpath(os.path.expanduser(str(path or "")))
        norm_pat = os.path.normpath(os.path.expanduser(str(pattern or "")))
        if not norm_path or not norm_pat:
            return False
        if norm_path.lower().endswith(_TEMPLATE_SUFFIXES) and not norm_pat.lower().endswith(_TEMPLATE_SUFFIXES):
            return False
        if fnmatch.fnmatch(norm_path, norm_pat):
            return True
        if fnmatch.fnmatch(os.path.basename(norm_path), norm_pat):
            return True
        # Directory-prefix semantics for glob-free patterns.
        if not any(ch in norm_pat for ch in "*?[") and (
            norm_path == norm_pat or norm_path.startswith(norm_pat.rstrip(os.sep) + os.sep)
        ):
            return True
    except Exception:  # pragma: no cover - fail open
        return False
    return False


def _folder_holds(folder: str, pattern: str) -> bool:
    """True when copying *folder* whole would take a file *pattern* protects: the
    pattern names a place under the home or root (``~/.ssh/*``) and *folder* is that
    place or one of its parents (``tar czf x.tgz ~`` takes ``~/.ssh`` with it).
    Name-only patterns (``.env``, ``*.pem``) say nothing about where, so a folder
    copy is not matched against them."""
    expanded = os.path.expanduser(str(pattern or ""))
    if not os.path.isabs(expanded):
        return False
    place = expanded.split("*", 1)[0].split("?", 1)[0].split("[", 1)[0]
    place = os.path.normpath(place if place.endswith(os.sep) or place == expanded else os.path.dirname(place))
    norm_folder = os.path.normpath(os.path.expanduser(str(folder or "")))
    if not os.path.isabs(norm_folder):
        return False
    return place == norm_folder or place.startswith(norm_folder.rstrip(os.sep) + os.sep)


def _reads_keychain(command: str) -> bool:
    """True when *command* runs ``security`` in a way that prints keychain secrets."""
    words = command.replace(";", " ; ").replace("$(", " ").replace("`", " ").split()
    for index, word in enumerate(words):
        if word.rsplit("/", 1)[-1] != "security" or index + 1 >= len(words):
            continue
        before = words[index - 1] if index else ";"
        if before not in _COMMAND_POSITION and not _ASSIGNMENT.match(before):   # "echo security …" only mentions it
            continue
        verb, options = words[index + 1], words[index + 2:]
        if verb not in _KEYCHAIN_SECRET_VERBS:
            continue
        if verb == "export":
            types = [value.lower() for flag, value in zip(options, options[1:]) if flag == "-t"]
            if not types or not set(types) <= _EXPORT_HARMLESS_TYPES:
                return True
            continue
        wanted = {flag.lstrip("-") for flag in _KEYCHAIN_SECRET_VERBS[verb]}
        if any(option.startswith("-") and not option.startswith("--") and wanted & set(option.lstrip("-"))
               for option in options):
            return True
    return False


def _accesses(tool_name: str, args: Any) -> List[Tuple[str, str, str]]:
    """``(tool, path, mode)`` for each file this call reads or copies: the file tool's
    path, or every path a terminal command reads, copies or archives (``mode`` is
    ``read`` or ``copy``; where a copy writes is left out)."""
    access = action_parsing.file_access_arg(tool_name, args)
    if access:
        return [(access["tool"], access["path"], access["mode"])]
    tool = (tool_name or "").strip().lower()
    if tool not in shell_shapes.SHELL_TOOLS:
        return []
    command = shell_shapes.command_from_args(tool_name, args)
    found = [(tool, arg.path, "copy" if arg.recursive else "read")
             for arg in shell_files.shell_file_args(command) if not arg.destination]
    if _reads_keychain(command):
        found.append((tool, _KEYCHAIN_FOLDER, "read"))
    return found


def detect_custom_fileaccess(
    tool_name: str, args: Any, protected_paths: Iterable[str]
) -> List[Finding]:
    """Match a file tool or terminal command against the USER'S protected-path list.

    These are personal, locally-configured rules (``source="custom"``): they
    always flag, they block in block mode (the user wrote the rule), and they
    are NEVER reported to the community graph — the matched pattern is the
    user's own configuration, not shared threat intel. One finding per call.
    """
    patterns = [p for p in (protected_paths or []) if str(p or "").strip()]
    if not patterns:
        return []
    for tool, path, mode in _accesses(tool_name, args):
        for pattern in patterns:
            if _protected_path_match(path, pattern) or (mode == "copy" and _folder_holds(path, pattern)):
                return [
                    Finding(
                        identifier=threat_ids.fileaccess_identifier(tool, "user-protected"),
                        category="fileaccess",
                        severity="critical",
                        title="Access to a user-protected path",
                        tool_name=tool,
                        matched="user-protected",
                        evidence=f"{mode} path matching protected pattern {str(pattern)[:120]}",
                        confirmed=False,
                        source="custom",
                        fields={},
                    )
                ]
    return []
