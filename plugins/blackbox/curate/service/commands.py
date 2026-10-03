"""``blackbox curate policy`` — read, accept or withdraw the automation policy (Community Curation C9).

Accepting is a typed act, like every curator consent: the operator types the
first 8 hex characters of the policy's hash, shown under the text. No node is
contacted; the acceptance is a local file.
"""

from __future__ import annotations

import time
from typing import Optional

from .. import keys
from ..consent import CODE_CHARS
from ..publishing import VerbError
from . import policy
from .policy_consent import PolicyConsent


def policy_command(*, accept: bool, withdraw: bool, code: Optional[str]) -> int:
    """Show the policy and where this machine stands; ``--accept --code`` or ``--withdraw`` change it."""
    consent = PolicyConsent()
    text, key_hex = policy.policy_text(), keys.curator_key_store().public_key_hex()
    shown_code = policy.policy_hash()[:CODE_CHARS]
    if withdraw:
        print("standing consent withdrawn: the service signs nothing on its own from its next beat"
              if consent.withdraw() else "there was no standing consent on this machine")
        return 0
    if accept:
        if (code or "").strip().lower() != shown_code:
            raise VerbError(f"type the code shown under the policy to accept it (--code {shown_code} for the text as it is now)")
        consent.accept(text, key_hex=key_hex, day=time.strftime("%Y-%m-%d", time.gmtime()))
        print(f"accepted for curator key {key_hex[:16]}…: the service may now sign what this policy allows")
        return 0
    print(text)
    held = consent.acceptance()
    if consent.accepted(text, key_hex):
        print(f"ACCEPTED on {held.day} for this machine's curator key. `blackbox curate policy --withdraw` stops the service signing.")
    elif held is not None:
        print("NOT ACCEPTED: the policy text or this machine's key changed since the last acceptance. The service signs nothing.")
    else:
        print("NOT ACCEPTED: the service prepares proposals and waits for a person.")
    print(f"To accept this exact text: blackbox curate policy --accept --code {shown_code}")
    return 0
