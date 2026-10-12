"""The host egress policy, seen from the runner (proposal §03.5, build item LR2).

The policy itself is ``integrations/threat-lab/egress.nft``, loaded on the lab
host with ``nft -f``: the kernel enforces it on the host side of the lab bridge,
where no sample can reach it. A sandbox that goes over the new-connection or
the new-destination cap lands in the ruleset's ``offenders`` set and loses its
network at once; this module is how the runner sees that, so it can kill the
sandbox and report ``scanning-killed``.

Pattern: Strategy. The sandbox asks an ``EgressGuard`` whether an address has
offended; :class:`NftablesEgressGuard` reads the live set with ``nft --json``,
tests pass a fake. The answer has three outcomes (LES-011): ``True``, ``False``,
or ``None`` when ``nft`` could not be read. Only ``True`` kills a sandbox; a
read that failed is never taken for "it scanned" (the kernel still drops the
traffic either way).

The ruleset file is the one source for the bridge, table and set names: this
module reads them out of it, so a rename there cannot leave the runner watching
the wrong set.

Usage::

    guard = NftablesEgressGuard()
    guard.check_loaded(docker="docker", network="threat-lab")   # LabConfigError when not
    guard.check_loaded(docker="docker", network=None)           # a microVM lab: the bridge itself
    guard.reset()                                   # serve start-up: no stale offenders
    guard.offended("172.30.0.5")                    # True / False / None
    guard.forget("172.30.0.5")                      # a sandbox at that address is new, or gone
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Protocol

from .config import LabConfigError

RULESET_PATH = Path(__file__).resolve().parents[1] / "egress.nft"
#: The table and set names the ruleset declares (a runner test pins them to the file).
TABLE_FAMILY, TABLE_NAME = "inet", "threat_lab"
OFFENDERS_SET = "offenders"
#: Every set the ruleset keys by a sandbox address alone: a new sandbox given a
#: departed one's address must inherit neither its offence nor its spent caps.
PER_ADDRESS_SETS = (OFFENDERS_SET, "connection_rate", "destination_rate")
_NFT_TIMEOUT_SECONDS = 5.0
#: br_netfilter's switch: on, frames between two sandboxes on the lab bridge pass the
#: ruleset's forward hook (where they are dropped); off, they bypass it.
BRIDGE_NETFILTER = Path("/proc/sys/net/bridge/bridge-nf-call-iptables")
#: Where Linux lists network interfaces; a bridge has a ``bridge/`` folder there.
NETWORK_INTERFACES = Path("/sys/class/net")
_BRIDGE_DEFINE = re.compile(r'^define LAB_BRIDGE = "([a-z0-9_-]{1,15})"$', re.MULTILINE)


def lab_bridge(ruleset: Path = RULESET_PATH) -> str:
    """The bridge interface the ruleset guards (its ``LAB_BRIDGE`` define)."""
    matched = _BRIDGE_DEFINE.search(ruleset.read_text(encoding="utf-8"))
    if not matched:
        raise LabConfigError(f"{ruleset} defines no LAB_BRIDGE")
    return matched.group(1)


class EgressGuard(Protocol):
    """``offended``: True / False / None (could not tell). ``forget``: drop the
    address from every per-address set (its sandbox is new, or gone)."""

    def offended(self, address: str) -> Optional[bool]: ...

    def forget(self, address: str) -> None: ...


class NftablesEgressGuard:
    """Reads and clears the live ``offenders`` set. Needs CAP_NET_ADMIN (root)."""

    def __init__(self, nft: str = "nft") -> None:
        self._nft = nft

    def offended(self, address: str) -> Optional[bool]:
        listed = self._call("--json", "list", "set", TABLE_FAMILY, TABLE_NAME, OFFENDERS_SET)
        if listed is None:
            return None
        try:
            return address in _set_elements(json.loads(listed))
        except (ValueError, TypeError, KeyError):
            return None

    def forget(self, address: str) -> None:
        # Absent already (timed out, never added) is fine: nft says so and nothing changes.
        for name in PER_ADDRESS_SETS:
            self._call("delete", "element", TABLE_FAMILY, TABLE_NAME, name, "{", address, "}")

    def reset(self) -> None:
        """Empty the per-address sets: a runner that died mid-job may have left
        an address there that a new sandbox will be given."""
        for name in PER_ADDRESS_SETS:
            if self._call("flush", "set", TABLE_FAMILY, TABLE_NAME, name) is None:
                raise LabConfigError(f"could not flush the egress set {name!r} (is the runner root?)")

    def check_loaded(self, docker: str, network: Optional[str], bridge_netfilter: Path = BRIDGE_NETFILTER,
                     interfaces: Path = NETWORK_INTERFACES) -> None:
        """Fail closed: refuse to run sandboxes unless the policy is loaded,
        br_netfilter is on, and *network* is the Docker network on the bridge
        the policy guards. A microVM lab has no Docker network (*network* None):
        its TAP devices join the bridge itself, which must then exist."""
        if self._call("list", "table", TABLE_FAMILY, TABLE_NAME) is None:
            raise LabConfigError(f"egress policy not loaded: run `nft -f {RULESET_PATH}` as root")
        try:
            switched_on = bridge_netfilter.read_text(encoding="utf-8").strip() == "1"
        except OSError:
            switched_on = False
        if not switched_on:
            raise LabConfigError("br_netfilter is off: `modprobe br_netfilter` and "
                                 "`sysctl net.bridge.bridge-nf-call-iptables=1`, or sandboxes can reach each other")
        expected = lab_bridge()
        if network is None:
            if not (interfaces / expected / "bridge").is_dir():
                raise LabConfigError(f"the lab bridge {expected!r} does not exist: "
                                     f"`ip link add {expected} type bridge` and give it the lab network's first address")
            return
        try:
            bridge = subprocess.run(
                [docker, "network", "inspect", network, "--format",
                 '{{index .Options "com.docker.network.bridge.name"}}'],
                capture_output=True, text=True, timeout=_NFT_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LabConfigError(f"could not inspect docker network {network!r}: {error}") from None
        if bridge.returncode != 0 or bridge.stdout.strip() != expected:
            raise LabConfigError(
                f"docker network {network!r} is not on bridge {expected!r}; create it with "
                f"`docker network create -o com.docker.network.bridge.name={expected} "
                f"-o com.docker.network.bridge.enable_icc=false {network}`")

    def _call(self, *args: str) -> Optional[str]:
        try:
            done = subprocess.run([self._nft, *args], capture_output=True, text=True,
                                  timeout=_NFT_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return done.stdout if done.returncode == 0 else None


def _set_elements(listing: dict) -> List[str]:
    """The addresses in ``nft --json list set`` output. A timed set lists each
    element as ``{"elem": {"val": address, "timeout": …, "expires": …}}``."""
    elements: List[str] = []
    for entry in listing["nftables"]:
        for element in entry.get("set", {}).get("elem", []):
            value = element["elem"]["val"] if isinstance(element, dict) else element
            if isinstance(value, str):
                elements.append(value)
    return elements
