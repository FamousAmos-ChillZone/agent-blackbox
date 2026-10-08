"""The command line the dashboard runs for its verified-graph sync.

The dashboard runs ``blackbox sync`` in a child process so a long network
transfer stays isolated from the web server (see ``server._network_sync_once``).

Usage: pass ``network_sync_argv(3600)`` as the argv of the child process
(the caller sets stdin, capture and timeout).
"""

from __future__ import annotations

import sys
from typing import List


def network_sync_argv(timeout: int = 3600) -> List[str]:
    """Run the canonical verified graph sync in an isolated process."""
    return [
        sys.executable,
        "-m",
        "hermes_cli.main",
        "blackbox",
        "sync",
        "--wait",
        "--timeout",
        str(max(1, int(timeout))),
        "--require-rules",
    ]
