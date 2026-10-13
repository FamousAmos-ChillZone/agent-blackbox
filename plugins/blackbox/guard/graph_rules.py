"""Resolve per-action graph rules and preserve explicit degraded-read evidence."""
import logging
from .. import audit, ruleset

logger = logging.getLogger(__name__)


def detection_rules(cfg, tool_name, args):
    if getattr(cfg, 'detection_backend', 'legacy-cache') == "legacy-cache":
        return ruleset.get(cfg), {"backend": "legacy-cache"}
    from ..ruleset import read_for_action
    from .. import killlist
    if getattr(cfg, 'detection_backend', 'legacy-cache') != "dkg":
        from ..ruleset import DetectionRead
        read = DetectionRead(ruleset.Ruleset(), code="INVALID_DETECTION_BACKEND")
    else:
        read = read_for_action(cfg, tool_name, args)
    if read.state != "available":
        # Preserve the existing fail-open host policy, but never record a
        # failed graph check as a successful clean scan. Local checks still run.
        try:
            audit.record(event="protection_degraded", detail=read.evidence())
        except Exception:
            pass
        logger.warning("blackbox: graph protection degraded (%s); local checks remain active", read.code)
        try:
            previous = killlist.LastGoodStore().current()
            read.rules.kill_list = previous.as_cache() if previous is not None else {}
        except Exception:
            pass  # local secret/path policies must run even with a corrupt trust store
    return read.rules, read.evidence()

