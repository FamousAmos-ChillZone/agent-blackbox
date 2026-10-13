"""Merge operator-wallet findings without duplicating stronger detections."""
from typing import Any, List
from .. import detection
from ..kernel import constants, crypto_secrets


def own_key_findings(raw: List[detection.Finding], tool_name: str, args: Any) -> List[detection.Finding]:
    """Raw keys of the operator's own listed addresses (Trader Shield), unless the
    labelled-key rule already raised the same finding at least as high."""
    found = detection.detect_own_wallet_keys(tool_name, args, lambda: crypto_secrets.wallet_mode.current().addresses)
    rank = constants.SEVERITY_RANK
    have = max((rank.get(f.severity, -1) for f in raw if f.identifier == "secret:wallet-private-key"), default=-1)
    return [f for f in found if rank.get(f.severity, -1) > have]

