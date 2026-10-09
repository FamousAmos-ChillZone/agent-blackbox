"""Chat — ``blackbox chat``: a Hermes session preconfigured as the Blackbox assistant.

Public surface: :func:`cmd_chat` (the command handler) and
:func:`add_blackbox_chat_args` (its argparse options). Internals in :mod:`.command`.
"""

from __future__ import annotations

from .command import add_blackbox_chat_args, cmd_chat

__all__ = ["add_blackbox_chat_args", "cmd_chat"]
