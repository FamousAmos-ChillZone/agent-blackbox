"""How long a community statement lives, per threat type (plan §03 table).

Community stages expire on the READER's own observation time, never the
sender's clock (KI-105); verified rules never expire by time (KI-117). R2
uses these lifetimes to bound pending tombstones (lifetime + 7 days); R3 uses
them for the EXPIRED stage.

Usage::

    from .lifetimes import lifetime_days
    lifetime_days("ioc:ip:203.0.113.7")   # 47
"""

from __future__ import annotations

#: Days a community statement lives, by identifier prefix (most specific first).
#: From the plan's per-type table: IPs and URLs churn fast; wallets and
#: malicious packages stay bad for a long time.
_LIFETIME_DAYS = (
    ("ioc:ip:", 47),
    ("ioc:url:", 47),
    ("ioc:domain:", 300),
    ("ioc:wallet:", 460),
    ("ioc:contract:", 460),
    ("injection:", 300),
    ("dep:", 460),
    ("escalation:", 460),
    ("fileaccess:", 300),
    ("skill:", 300),
)
#: For types the table does not name (e.g. ``ioc:hash:``).
DEFAULT_LIFETIME_DAYS = 300
#: How long past its target's lifetime a tombstone for an unseen target is kept.
TOMBSTONE_GRACE_DAYS = 7


def lifetime_days(identifier: str) -> int:
    """The community lifetime, in days, of the threat *identifier* names."""
    for prefix, days in _LIFETIME_DAYS:
        if identifier.startswith(prefix):
            return days
    return DEFAULT_LIFETIME_DAYS
