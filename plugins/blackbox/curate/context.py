"""What every `blackbox curate` verb needs resolved once (Refine R6, Community Curation C4).

:class:`CurateContext` holds the config, the node client, the network id, the
trusted curator view (both authorities, combined), the AUTHORITY this machine
acts for, whether that authority is in a development setup (``sandbox`` — no
pinned root, so consent by ``--yes`` and a locally held root are allowed), and
the compiled ruleset the composition root injected (the ruleset depends on
this package, never the reverse).

A curator machine acts for exactly one authority (``kernel.signing.authority``):
the VERIFIED one publishes its manifest and enforcement statements in the
verified graph; the COMMUNITY one publishes everything in the community graph
and may only ever cause FLAG. Which one is decided once, in
:func:`acting_authority`, and every verb routes by it.

Pattern: a Facade over the kernel + community pieces the verbs use.

Usage::

    ctx = build_context(compiled_ruleset, authority="community", interest=["author:<key>"])
    ctx.manifest                      # the acting authority's key manifest (None: publish one first)
    ctx.graph_for(CuratorStatement.COUNTED_AUTHORS)   # where this authority publishes that kind
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from .. import community
from ..kernel import constants
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient
from ..kernel.signing import trust_anchors
from ..kernel.signing.authority import VERIFIED_GRAPH, Authority, home_graph
from ..kernel.signing.key_manifest import KeyManifest
from ..kernel.signing.statement_order import CuratorStatement
from . import keys

#: cfg -> the compiled Ruleset (injected by cli.py).
CompiledRuleset = Callable[[Any], Any]


@dataclass(frozen=True)
class CurateContext:
    cfg: BlackboxConfig
    client: DkgClient
    environment: str
    view: community.CuratorView
    sandbox: bool
    compiled: Optional[Any]
    authority: Authority = Authority.VERIFIED

    @property
    def manifest(self) -> Optional[KeyManifest]:
        """The ACTING authority's trusted key manifest (None: none published yet)."""
        if self.authority is Authority.COMMUNITY:
            return self.view.community.manifest if self.view.community is not None else None
        return self.view.manifest

    @property
    def own_view(self) -> community.CuratorView:
        """The acting authority's own view (its statements only, its own sequence order)."""
        if self.authority is Authority.COMMUNITY:
            return self.view.community if self.view.community is not None else community.CuratorView()
        return self.view

    @property
    def verified_graph(self) -> str:
        return self.cfg.context_graph_id

    @property
    def community_graph(self) -> str:
        return self.cfg.community_graph_id

    @property
    def manifest_graph(self) -> str:
        """The graph the acting authority's manifest is bound to and published in."""
        return self.community_graph if self.authority is Authority.COMMUNITY else self.verified_graph

    def graph_for(self, kind: CuratorStatement) -> Optional[str]:
        """The graph id where the acting authority publishes a *kind* statement,
        or None when it may not sign that kind at all."""
        home = home_graph(self.authority, kind)
        if home is None:
            return None
        return self.verified_graph if home == VERIFIED_GRAPH else self.community_graph


def acting_authority(cfg: BlackboxConfig, environment: str, view: community.CuratorView,
                     requested: Optional[str] = None) -> Authority:
    """Which authority this curator machine acts for. An explicit *requested*
    value wins. Otherwise: the authority whose trusted manifest lists this
    machine's curator key; else COMMUNITY when only a community root is
    trusted here; else VERIFIED (the behaviour before the community authority existed)."""
    if requested:
        return Authority(requested)
    my_key = keys.curator_key_store().public_key_hex()
    if view.community is not None and view.community.manifest is not None and my_key in view.community.manifest.curator_keys:
        return Authority.COMMUNITY
    if view.manifest is not None and my_key in view.manifest.curator_keys:
        return Authority.VERIFIED
    has_community_root = bool(cfg.community_graph_id and cfg.community_graph_id != cfg.context_graph_id
                              and trust_anchors.community_roots(cfg.community_graph_id))
    if has_community_root and not trust_anchors.trusted_roots(environment):
        return Authority.COMMUNITY
    return Authority.VERIFIED


def is_sandbox(authority: Authority, cfg: BlackboxConfig, environment: str) -> bool:
    """True when *authority* has no pinned root here (a development setup)."""
    if authority is Authority.COMMUNITY:
        return not trust_anchors.community_root_pinned(cfg.community_graph_id)
    return not constants.CURATOR_ROOT_KEYS.get(environment)


def build_context(compiled_ruleset: Optional[CompiledRuleset], *, authority: Optional[str] = None,
                  interest: Iterable[str] = ()) -> CurateContext:
    """Resolve the context from the live node. The node must be reachable.
    *interest* — identifiers the verb is about (their statements are looked up)."""
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    environment = community.network_environment(client.status())
    view = community.read_curator_view(client, cfg, environment, interest=interest)
    acting = acting_authority(cfg, environment, view, authority)
    compiled = compiled_ruleset(cfg) if compiled_ruleset is not None else None
    return CurateContext(cfg=cfg, client=client, environment=environment, view=view,
                         sandbox=is_sandbox(acting, cfg, environment), compiled=compiled, authority=acting)


def verified_identifiers(compiled: Any, among: Iterable[str]) -> set:
    """Which of *among* the verified tier already lists (the delta view's "already
    verified"). Asked for a known set — the community store's identifiers, a
    read's reports — because the verified tier is looked up live, never listed."""
    if compiled is None:
        return set()
    subset = getattr(compiled, "verified_subset", None)
    if callable(subset):
        return set(subset(among))
    wanted = {str(identifier) for identifier in among}   # a plain compiled object: scan its public rules
    return {str(rule.get("identifier") or "") for _category, rule in compiled.iter_rules()
            if rule.get("source") == "public" and str(rule.get("identifier") or "") in wanted}
