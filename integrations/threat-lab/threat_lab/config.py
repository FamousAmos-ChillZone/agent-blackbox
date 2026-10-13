"""The lab runner's settings: where it keeps files, which image it runs, and the
caps every sandbox gets (proposal §03.5).

A runner is one of two labs, chosen by whether ``microvm`` is set:

* Lab 1 (levels 1–2): gVisor containers from a Docker image;
* Lab 2 (level 4, "run"): Firecracker microVMs on a KVM host, booted from a
  kernel + root filesystem pair (:class:`MicroVMSettings`). Its ``image`` is
  ``<name>@sha256:<image_digest(kernel, rootfs)>`` — the same pinned form, so
  the job key carries the microVM image's hash just as it carries a container
  image's (``threat_lab.microvm.image_digest`` defines it).

The lab holds no keys, wallet or credentials, so nothing here is secret. The
image MUST be pinned by digest (``name@sha256:<hex>``): that digest is the
image hash in every job key, and a tag could silently point at a different
image between two runs of the "same" job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

#: Levels a gVisor lab (Lab 1) serves.
GVISOR_LEVELS = (1, 2)
#: Levels a Firecracker lab (Lab 2) serves. Level 3 is urlscan.io, on the curator, never here.
MICROVM_LEVELS = (4,)
#: Every level some lab runner serves.
LAB_LEVELS = GVISOR_LEVELS + MICROVM_LEVELS
#: Raw artifacts are kept this long, then the retention sweep deletes them (§03.5 ground rules).
RETENTION_DAYS = 90
#: Wall-clock cap for a whole job. Below the curator's deadline (jobs.DEADLINE_SECONDS: 120 s for
#: levels 1–2, 300 s for level 4), so the lab reports the cap (deadline-reached) before the
#: curator gives up on it; level 4 is the proposal's 5-minute microVM deadline less that margin.
DEFAULT_DEADLINE_SECONDS: Dict[int, float] = {1: 60.0, 2: 90.0, 4: 280.0}
_PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:([0-9a-f]{64})$")


class LabConfigError(ValueError):
    """A setting the runner refuses to start with."""


@dataclass(frozen=True)
class SandboxCaps:
    """Per-sandbox limits. ``memory_mb`` is also the swap ceiling (no swap)."""

    cpus: float = 1.0
    memory_mb: int = 512
    pids: int = 128
    #: Largest probe report read back from a sandbox; more is a broken probe.
    max_report_bytes: int = 1_000_000


@dataclass(frozen=True)
class MicroVMSettings:
    """A Firecracker lab's host settings (level 4).

    ``kernel`` and ``rootfs`` are the clean image: never booted themselves —
    every job boots a fresh copy of ``rootfs`` (no snapshot is ever made or
    restored). ``bridge_network`` is the lab bridge's IPv4 subnet: its first
    address is the bridge (the guests' gateway), and slot *n*'s guest gets the
    address ``GUEST_ADDRESS_OFFSET + n`` in it. ``slots`` is how many microVMs
    run at once (one per worker; 2 on a 4-vCPU / 16 GB host, F-034). The
    jailer runs Firecracker as ``uid``:``gid`` in a chroot."""

    kernel: Path
    rootfs: Path
    firecracker: str = "firecracker"
    jailer: str = "jailer"
    ip: str = "ip"
    tcpdump: str = "tcpdump"
    uid: int = 65534
    gid: int = 65534
    vcpus: int = 2
    memory_mb: int = 2048
    bridge_network: str = "172.30.4.0/24"
    slots: int = 2

    def __post_init__(self) -> None:
        if self.slots < 1 or self.vcpus < 1 or self.memory_mb < 128:
            raise LabConfigError("a microVM lab needs at least one slot, one vCPU and 128 MiB")


@dataclass(frozen=True)
class LabConfig:
    """Everything the runner needs. ``home`` holds ``artifacts/`` and ``work/``;
    ``image`` is the digest-pinned sandbox image; ``network`` is the Docker
    network level 1 and the level-2 download use — on the lab host, the network
    on the bridge ``egress.nft`` guards (``serve`` and ``run`` refuse to start
    otherwise); ``runtime`` is the OCI runtime (gVisor's ``runsc``).
    ``microvm`` set makes this a Firecracker lab serving level 4 only."""

    home: Path
    image: str
    network: str = "threat-lab"
    runtime: str = "runsc"
    docker: str = "docker"
    caps: SandboxCaps = field(default_factory=SandboxCaps)
    deadline_seconds: Dict[int, float] = field(default_factory=lambda: dict(DEFAULT_DEADLINE_SECONDS))
    microvm: Optional[MicroVMSettings] = None

    def __post_init__(self) -> None:
        if not _PINNED_IMAGE.match(self.image):
            raise LabConfigError("image must be pinned by digest: name@sha256:<64 hex>")
        if self.network == "none":
            raise LabConfigError("network names the level-1 network; level 2 turns it off itself")

    @property
    def served_levels(self) -> Tuple[int, ...]:
        """The levels this lab runs: 4 on a Firecracker lab, 1–2 otherwise."""
        return MICROVM_LEVELS if self.microvm is not None else GVISOR_LEVELS

    @property
    def image_sha256(self) -> str:
        """The image hash every job key served here must carry."""
        return _PINNED_IMAGE.match(self.image).group(1)

    @property
    def artifacts_dir(self) -> Path:
        return self.home / "artifacts"

    @property
    def work_dir(self) -> Path:
        return self.home / "work"
