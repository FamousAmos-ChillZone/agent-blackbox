"""The user's protected paths: a file an agent must not touch unless the operator says so.

The operator lists paths in ``protected_paths`` (defaults: :data:`kernel.config.DEFAULT_PROTECTED_PATHS`
— SSH keys, ``.env`` files, key files, cloud credentials, Blackbox's own state). These
are personal, locally-configured rules (``source="custom"``): they always flag, they
block in block mode (the user wrote the rule), and they are NEVER reported to the
community graph — the matched pattern is the user's own configuration.

Usage::

    detect_custom_fileaccess("read_file", {"path": "~/.ssh/id_rsa"}, ["~/.ssh/*"])
    # -> [Finding(category="fileaccess", source="custom", severity="critical", ...)]
"""

from __future__ import annotations

import fnmatch
import os
from typing import Any, Iterable, List

from .. import action_parsing
from ..finding import Finding
from ...kernel import threat_ids


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


def detect_custom_fileaccess(
    tool_name: str, args: Any, protected_paths: Iterable[str]
) -> List[Finding]:
    """Match file-access tool calls against the USER'S protected-path list.

    These are personal, locally-configured rules (``source="custom"``): they
    always flag, they block in block mode (the user wrote the rule), and they
    are NEVER reported to the community graph — the matched pattern is the
    user's own configuration, not shared threat intel.
    """
    patterns = [p for p in (protected_paths or []) if str(p or "").strip()]
    if not patterns:
        return []
    access = action_parsing.file_access_arg(tool_name, args)
    if not access:
        return []
    for pattern in patterns:
        if _protected_path_match(access["path"], pattern):
            tool = access["tool"]
            return [
                Finding(
                    identifier=threat_ids.fileaccess_identifier(tool, "user-protected"),
                    category="fileaccess",
                    severity="critical",
                    title="Access to a user-protected path",
                    tool_name=tool,
                    matched="user-protected",
                    evidence=f"{access['mode']} path matching protected pattern {str(pattern)[:120]}",
                    confirmed=False,
                    source="custom",
                    fields={},
                )
            ]
    return []
