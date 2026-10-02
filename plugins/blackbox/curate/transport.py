"""Proposals travel between curator nodes by private point-to-point message (Refine R6).

Plan §09 TRANSPORT: a proposal is stored in each curator's private memory and
sent to the other curator over the network's private messaging — never in a
shared graph before approval. ONE hand-off: the first curator proposes, the
second approves and publishes. The message text is the proposal's JSON behind
a fixed prefix; what matters inside it is the signed envelope, which the
receiver verifies against the key manifest (:mod:`.verbs`), never the message.

Usage::

    transport.send_proposal(client, peer, proposal)
    for proposal in transport.receive_proposals(client, InboxCursor()): store.save(proposal)
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..kernel import node_routes
from ..kernel.dkg_client import DkgClient
from . import keys
from .proposal import Proposal, ProposalError, ProposalState

logger = logging.getLogger(__name__)

PROPOSAL_PREFIX = "blackbox-proposal:"
_CURSOR_FILE = "inbox_cursor.json"


class InboxCursor:
    """Where this curator stopped reading its inbox (``since``, ``since_id``);
    persisted so no message is read twice or skipped. One lock, atomic write."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _CURSOR_FILE)
        self._lock = threading.Lock()

    def read(self) -> Dict[str, int]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {"since": int(data.get("since", 0)), "since_id": int(data.get("since_id", 0))}
        except (OSError, ValueError, TypeError, AttributeError):
            return {"since": 0, "since_id": 0}

    def advance(self, message: node_routes.InboxMessage) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(f"{self._path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
            tmp.write_text(json.dumps({"since": message.ts, "since_id": message.id}), encoding="utf-8")
            os.replace(tmp, self._path)


def send_proposal(client: DkgClient, peer: str, proposal: Proposal) -> Dict[str, Any]:
    """Send *proposal* to the other curator; returns the node's delivery result."""
    return node_routes.send_message(client, peer, PROPOSAL_PREFIX + proposal.to_json())


def parse_message(text: str) -> Optional[Proposal]:
    """The proposal a message carries, as PROPOSED; None for any other message."""
    if not text.startswith(PROPOSAL_PREFIX):
        return None
    try:
        proposal = Proposal.from_json(text[len(PROPOSAL_PREFIX):])
    except ProposalError:
        return None
    if proposal.state is ProposalState.DRAFT:
        proposal = proposal.transition(ProposalState.PROPOSED)
    return proposal if proposal.state is ProposalState.PROPOSED else None


def receive_proposals(client: DkgClient, cursor: InboxCursor) -> List[Proposal]:
    """Every proposal in the inbox since the cursor, advancing it past each
    message read (proposal or not)."""
    position = cursor.read()
    found: List[Proposal] = []
    for message in node_routes.inbox(client, since=position["since"], since_id=position["since_id"]):
        proposal = parse_message(message.text)
        if proposal is not None:
            found.append(proposal)
        cursor.advance(message)
    return found
