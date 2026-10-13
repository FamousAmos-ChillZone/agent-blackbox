"""One fresh gVisor sandbox per probe, destroyed after (proposal §03.5, F-011).

Pattern: Strategy. :class:`LabRunner` asks a ``Sandbox`` to run one probe
command and gets a :class:`SandboxResult`; :class:`GVisorSandbox` is the real
one (``docker run --runtime=runsc --rm`` from the digest-pinned image), tests
pass a recording fake.

Every container is: read-only root, all capabilities dropped,
no-new-privileges, unprivileged user, CPU/memory/pid caps, no swap, a small
noexec ``/tmp``, the job's work folder as the only mount, and a unique name so
a probe past its deadline can be killed by name. ``network="none"`` turns the
network off entirely (level 2 after the download).

On the lab network the host's egress policy (``egress.nft``) caps new
connections and new destinations per sandbox address. When an
:class:`~threat_lab.egress.EgressGuard` is given, a probe on the network is
watched while it runs: the moment the guard says its address went over a cap,
the container is killed, the kill is logged, and the result says
``scanning_killed`` (the runner turns it into the ``scanning-killed`` note).
The address's per-address state is cleared when the sandbox is first seen and
again when it is gone, so the next sandbox given that address starts clean.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Protocol, Tuple

from .config import LabConfig
from .egress import EgressGuard
from .watch import CaughtScanning, watch

logger = logging.getLogger("threat_lab.sandbox")

NO_NETWORK = "none"
#: The exit status Docker reports for a container the kernel killed (SIGKILL: OOM).
_KILLED_STATUS = 137
_KILL_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class SandboxSpec:
    """One probe run: ``probe_args`` after ``python -m threat_lab.probe``; the
    network (a network name or :data:`NO_NETWORK`); the host folder mounted at
    ``/work`` and whether the probe may write it; the wall-clock cap."""

    probe_args: tuple[str, ...]
    network: str
    work_dir: Path
    work_writable: bool
    timeout_seconds: float


@dataclass(frozen=True)
class SandboxResult:
    """What came back. ``timed_out``: killed at the deadline. ``out_of_memory``:
    killed by the kernel (status 137) before it. ``scanning_killed``: killed
    because the egress policy caught its address over a cap. ``report`` is the
    probe's stdout (empty when it was cut off). ``recordings``: raw files the
    sandbox made on the host (a microVM's traffic capture), kept by sha256."""

    exit_code: Optional[int]
    report: bytes
    timed_out: bool = False
    out_of_memory: bool = False
    oversized: bool = False
    scanning_killed: bool = False
    recordings: tuple[bytes, ...] = ()


class Sandbox(Protocol):
    def run(self, spec: SandboxSpec) -> SandboxResult: ...


class GVisorSandbox:
    """Runs each spec in a new ``runsc`` container from ``config.image``;
    watches networked probes when *egress* is given (the lab host always gives it)."""

    def __init__(self, config: LabConfig, egress: Optional[EgressGuard] = None) -> None:
        self._config = config
        self._egress = egress

    def command(self, spec: SandboxSpec, name: str) -> list[str]:
        """The exact ``docker run`` argv for *spec* (tests read it)."""
        caps = self._config.caps
        mount_mode = "rw" if spec.work_writable else "ro"
        return [
            self._config.docker, "run", "--rm", "--name", name,
            f"--runtime={self._config.runtime}",
            f"--network={spec.network}",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65534:65534",
            f"--cpus={caps.cpus}",
            f"--memory={caps.memory_mb}m",
            f"--memory-swap={caps.memory_mb}m",
            f"--pids-limit={caps.pids}",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",   # no-tmp: ok — the sandbox container's own capped /tmp, never the host's
            f"--volume={spec.work_dir}:/work:{mount_mode}",
            self._config.image,
            "python", "-m", "threat_lab.probe", *spec.probe_args,
        ]

    def run(self, spec: SandboxSpec) -> SandboxResult:
        name = f"threat-lab-{uuid.uuid4().hex}"
        process = subprocess.Popen(self.command(spec, name), stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        watched: list[str] = []
        try:
            if self._egress is not None and spec.network != NO_NETWORK:
                report = watch(process, spec.timeout_seconds, self._egress, lambda: self._address(name), watched)
            else:
                report, _ = process.communicate(timeout=spec.timeout_seconds)
        except subprocess.TimeoutExpired:
            self._kill(name, process)
            return SandboxResult(exit_code=None, report=b"", timed_out=True)
        except CaughtScanning:
            self._kill(name, process)
            logger.warning("sandbox %s at %s went over the egress caps (scanning): killed", name, watched[0])
            return SandboxResult(exit_code=None, report=b"", scanning_killed=True)
        finally:
            for address in watched:
                self._egress.forget(address)
        if len(report) > self._config.caps.max_report_bytes:
            return SandboxResult(exit_code=process.returncode, report=b"", oversized=True)
        return SandboxResult(exit_code=process.returncode, report=report,
                             out_of_memory=process.returncode == _KILLED_STATUS)

    def _address(self, name: str) -> Optional[str]:
        """The container's IPv4 address on its network, or None while it starts."""
        try:
            inspected = subprocess.run(
                [self._config.docker, "inspect", "--format",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
                capture_output=True, text=True, timeout=_KILL_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            return None
        try:
            return str(ipaddress.IPv4Address(inspected.stdout.strip()))
        except ValueError:
            return None

    def _kill(self, name: str, process: subprocess.Popen[bytes]) -> None:
        # Killing the docker client alone would leave the container running:
        # kill the container by name, then reap the client.
        try:
            subprocess.run([self._config.docker, "kill", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=_KILL_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            pass
        process.kill()
        process.communicate()
