"""Curator statement types and which statement about a threat is current (Refine R7a).

Curator statements are signed blobs that any node can re-share, so "latest"
can never come from when a row arrived or from the sender's ``publishedAt``
clock (KI-105/109). It comes from the per-threat SEQUENCE number inside the
signed envelope (:mod:`.envelope`):

* per (threat, statement type), the highest sequence wins;
* across types, a TERMINAL statement (revocation, rejection) dominates every
  statement with a lower sequence, so an old promotion replayed after a
  revocation loses (KI-143). A later, higher-sequence promotion (a deliberate
  re-promotion) still wins. At an equal sequence the terminal one wins:
  safety is asymmetric (LES-016).

Each type is also classified as raising or reducing enforcement, which is
what reader policy (R7b) needs: holds, freezes and caps apply only to
statements that RAISE enforcement; reducing ones always get through.

Pattern: Enum (:class:`CuratorStatement`) + Value Object
(:class:`OrderedStatement`) + pure resolution functions.

Usage::

    from ..kernel.signing import statement_order as order
    seen = [order.OrderedStatement("dep:npm:x@1", order.CuratorStatement.PROMOTION, 3),
            order.OrderedStatement("dep:npm:x@1", order.CuratorStatement.REVOCATION, 5)]
    order.current_by_threat(seen)["dep:npm:x@1"].kind   # CuratorStatement.REVOCATION
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Tuple


class CuratorStatement(Enum):
    """The curator statement types (the envelope's ``statement_type``)."""

    PROMOTION = "blackbox.promotion"     # a threat enters the verified tier (raises)
    PAUSE = "blackbox.pause"             # community ingest paused — the two-key pause flag (raises; KI-118)
    REVOCATION = "blackbox.revocation"   # a verified threat is withdrawn (reduces; terminal)
    REJECTION = "blackbox.rejection"     # a reported threat is refused (reduces; terminal)

    @property
    def terminal(self) -> bool:
        """True for statements that end a threat's run (revocation, rejection)."""
        return self in _TERMINAL

    @property
    def raises_enforcement(self) -> bool:
        """True when the statement can make Blackbox block or flag MORE."""
        return self in _RAISING


_TERMINAL = frozenset({CuratorStatement.REVOCATION, CuratorStatement.REJECTION})
_RAISING = frozenset({CuratorStatement.PROMOTION, CuratorStatement.PAUSE})


@dataclass(frozen=True)
class OrderedStatement:
    """One verified curator statement about a threat: ``threat`` (identifier),
    ``kind`` (:class:`CuratorStatement`), ``sequence`` (the signed per-threat
    sequence number)."""

    threat: str
    kind: CuratorStatement
    sequence: int

    @property
    def rank(self) -> Tuple[int, bool]:
        """Sort key: higher sequence first; at a tie, terminal beats non-terminal."""
        return self.sequence, self.kind.terminal


def current_by_type(statements: Iterable[OrderedStatement]) -> Dict[Tuple[str, CuratorStatement], OrderedStatement]:
    """The highest-sequence statement per (threat, type)."""
    current: Dict[Tuple[str, CuratorStatement], OrderedStatement] = {}
    for statement in statements:
        key = (statement.threat, statement.kind)
        if key not in current or statement.sequence > current[key].sequence:
            current[key] = statement
    return current


def current_by_threat(statements: Iterable[OrderedStatement]) -> Dict[str, OrderedStatement]:
    """The one statement that decides each threat: the highest sequence, a
    terminal statement winning a tie. A replayed lower-sequence statement
    never overrides a terminal one."""
    current: Dict[str, OrderedStatement] = {}
    for statement in current_by_type(statements).values():
        held = current.get(statement.threat)
        if held is None or statement.rank > held.rank:
            current[statement.threat] = statement
    return current
