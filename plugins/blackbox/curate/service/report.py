"""What one beat of the curator service did, and its working state (Community Curation C9).

* :class:`HumanItem` — one thing that waits for a person.
* :class:`BeatReport` — the frozen result of a beat (what ``blackbox curate run`` prints).
* :class:`Run` — the state the beat's steps share while they run.
* :func:`standing` — the line the consent ledger records for an automatic decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ...community import reputation
from ..context import CurateContext
from ..proposal import ProposalStore
from . import policy
from .budget import ServiceBudget
from .policy import PolicyDecision


@dataclass(frozen=True)
class HumanItem:
    """One thing that waits for a person: ``subject`` (a threat, ``author:<key>``
    or a proposal id) and ``why`` the service did not do it."""

    subject: str
    why: str


@dataclass(frozen=True)
class BeatReport:
    """What one beat did. ``may_sign`` — the service was allowed to sign
    (``why_not`` says why not). ``heartbeat`` — "published", "not due", or
    what stopped it. ``received`` / ``dropped`` — proposals taken from the
    inbox / messages that were not a curator's proposal. ``cosigned`` /
    ``proposed`` — proposal ids this beat co-signed and published / signed
    first. ``published`` — single-key statements it published. ``limited`` —
    raising statements left for tomorrow by the service's own daily limit.
    ``human`` — what waits for a person. ``errors`` — steps that failed."""

    may_sign: bool
    why_not: str = ""
    heartbeat: str = "not due"
    received: int = 0
    dropped: int = 0
    cosigned: Tuple[str, ...] = ()
    proposed: Tuple[str, ...] = ()
    published: Tuple[str, ...] = ()
    credited: int = 0
    kept_alive: int = 0
    limited: int = 0
    human: Tuple[HumanItem, ...] = ()
    errors: Tuple[str, ...] = ()

    def summary(self) -> str:
        signing_state = "signing" if self.may_sign else f"NOT signing ({self.why_not})"
        return (f"beat: {signing_state} · heartbeat {self.heartbeat} · received {self.received} · co-signed {len(self.cosigned)} · "
                f"proposed {len(self.proposed)} · published {len(self.published)} · credited {self.credited} · "
                f"kept alive {self.kept_alive} · held by the daily limit {self.limited} · "
                f"{len(self.human)} for a person · {len(self.errors)} error(s)")


@dataclass
class Run:
    """The state of one beat (mutable while the steps run; frozen into a :class:`BeatReport`)."""

    ctx: CurateContext
    store: ProposalStore
    ledger: reputation.ReputationLedger
    budget: ServiceBudget
    today: str
    my_key: str
    why_not: str
    heartbeat: str = "not due"
    received: int = 0
    dropped: int = 0
    credited: int = 0
    kept_alive: int = 0
    limited: int = 0
    acknowledged: int = 0
    cosigned: List[str] = field(default_factory=list)
    proposed: List[str] = field(default_factory=list)
    published: List[str] = field(default_factory=list)
    human: List[HumanItem] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    addresses: Optional[Dict[str, str]] = None
    #: Identifiers a step already acted on in THIS beat: the view was read when the beat
    #: began, so a later step must not act on what an earlier one just changed.
    settled: Set[str] = field(default_factory=set)

    @property
    def may_sign(self) -> bool:
        return not self.why_not

    def report(self) -> BeatReport:
        return BeatReport(may_sign=self.may_sign, why_not=self.why_not, heartbeat=self.heartbeat, received=self.received,
                          dropped=self.dropped, cosigned=tuple(self.cosigned), proposed=tuple(self.proposed),
                          published=tuple(self.published), credited=self.credited, kept_alive=self.kept_alive,
                          limited=self.limited, human=tuple(self.human), errors=tuple(self.errors))


def standing(decision: PolicyDecision) -> str:
    """The standing-consent line the consent ledger records for an automatic decision."""
    return f"{decision.action.value}: {decision.reason} (policy {policy.policy_hash()[:8]})"
