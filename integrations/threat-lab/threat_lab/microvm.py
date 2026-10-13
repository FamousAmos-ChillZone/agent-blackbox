"""One fresh Firecracker microVM per level-4 job, destroyed after (proposal §03.5, F-011).

Pattern: Strategy — :class:`FirecrackerSandbox` is a ``Sandbox`` like
``GVisorSandbox``: :class:`~threat_lab.runner.LabRunner` hands it one spec and
gets a :class:`~threat_lab.sandbox.SandboxResult` back.

**Image-only boot, never a snapshot.** Restoring one snapshot more than once is
documented insecure (duplicated entropy, identifiers and tokens). Firecracker
loads a snapshot only through its API socket (``PUT /snapshot/load``), so every
microVM here starts with ``--no-api --config-file``: there is no socket to load
one through. The config is built by :func:`boot_config` and checked by
:func:`assert_image_only` before every boot (allowlisted sections only). The
root filesystem is a fresh COPY of the clean image for each job, hashed and
compared with the pinned image digest before it boots, and deleted after.

**Per boot:** KVM checked (:mod:`threat_lab.kvm`; no KVM → the job is not run,
the run FAILED); a slot taken (``settings.slots`` microVMs at once — a job past
them WAITS); a jail prepared under the job's work folder (kernel, the rootfs
copy, a read-only job drive with ``{"identifier"}``, a raw report drive, the
config); a TAP device for the slot attached to the lab bridge that
``egress.nft`` guards, so the LR2 host policy applies to every packet; tcpdump
recording that TAP; the jailer started (chroot, unprivileged uid/gid, cgroup
memory cap) exec-ing Firecracker. While it runs it is watched (:mod:`threat_lab.watch`):
past the deadline or caught scanning → killed. After: tcpdump stopped, TAP
deleted, slot released, the report read off the report drive and joined with
what the HOST recorded (:mod:`threat_lab.traffic`).

Usage::

    sandbox = FirecrackerSandbox(config, egress)          # config.microvm set
    result = sandbox.run(SandboxSpec(("run", identifier), "", work, True, 280.0))
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import queue
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import LabConfig, LabConfigError, MicroVMSettings
from .egress import EgressGuard, lab_bridge
from .kvm import kvm_problem
from .sandbox import SandboxResult, SandboxSpec
from .traffic import is_recording, read_pcap
from .watch import CaughtScanning, watch

logger = logging.getLogger("threat_lab.microvm")

#: The only sections a boot config may have: a kernel, drives, a machine size, a NIC.
BOOT_SECTIONS = frozenset({"boot-source", "drives", "machine-config", "network-interfaces"})
#: Slot n's guest is this many addresses past the bridge network's base (.1 is the bridge).
GUEST_ADDRESS_OFFSET = 10
REPORT_DRIVE_BYTES = 2 * 1024 * 1024
#: Firecracker's own memory on top of the guest's, in the jail's cgroup memory cap.
_VMM_OVERHEAD_MB = 256
_DRIVE_ALIGNMENT = 4096
_HELPER_TIMEOUT_SECONDS = 15.0
_TCPDUMP_START_SECONDS = 3.0
#: Popen's status for a VMM ended by SIGKILL that we did not send: the cgroup's memory cap.
_KILLED_STATUS = -9


def image_digest(kernel: Path, rootfs: Path) -> str:
    """The microVM image's hash, the one its job keys carry:
    ``sha256("kernel:" + sha256(kernel) + "\\nrootfs:" + sha256(rootfs))``."""
    return hashlib.sha256(f"kernel:{_file_sha256(kernel)}\nrootfs:{_file_sha256(rootfs)}".encode("ascii")).hexdigest()


def check_image(config: LabConfig) -> None:
    """Fail closed at start-up: the kernel and rootfs must hash to the pinned image."""
    settings = _settings(config)
    for path in (settings.kernel, settings.rootfs):
        if not path.is_file():
            raise LabConfigError(f"microVM image file {path} does not exist")
    if image_digest(settings.kernel, settings.rootfs) != config.image_sha256:
        raise LabConfigError("the microVM kernel + rootfs do not hash to the pinned --image digest")


def boot_config(settings: MicroVMSettings, guest: str, gateway: str, prefix: int, tap: str) -> Dict[str, Any]:
    """The Firecracker config for one boot, with in-jail paths. The guest's
    address comes from the kernel's own ``ip=`` set-up; ``init`` runs the job."""
    netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    return {
        "boot-source": {
            "kernel_image_path": "/vmlinux",
            "boot_args": (f"console=ttyS0 reboot=k panic=1 pci=off rw init=/opt/threat-lab/init.sh "
                          f"ip={guest}::{gateway}:{netmask}::eth0:off"),
        },
        "drives": [
            {"drive_id": "rootfs", "path_on_host": "/rootfs.ext4", "is_root_device": True, "is_read_only": False},
            {"drive_id": "job", "path_on_host": "/job.img", "is_root_device": False, "is_read_only": True},
            {"drive_id": "report", "path_on_host": "/report.img", "is_root_device": False, "is_read_only": False},
        ],
        "machine-config": {"vcpu_count": settings.vcpus, "mem_size_mib": settings.memory_mb, "smt": False},
        "network-interfaces": [{"iface_id": "eth0", "guest_mac": _mac(guest), "host_dev_name": tap}],
    }


def assert_image_only(config: Dict[str, Any], argv: List[str]) -> None:
    """Refuse a boot that could resume state: an API socket, or any config
    section beyond :data:`BOOT_SECTIONS`, or the word snapshot anywhere."""
    if "--no-api" not in argv or any("api-sock" in arg or "snapshot" in arg for arg in argv):
        raise AssertionError("a microVM boots with --no-api and no snapshot argument")
    if set(config) - BOOT_SECTIONS or "snapshot" in json.dumps(config).lower():
        raise AssertionError(f"a microVM config holds only {sorted(BOOT_SECTIONS)}")


class FirecrackerSandbox:
    """Runs each spec (``("run", identifier)``) in a fresh microVM. Thread-safe;
    at most ``settings.slots`` at once. *kvm_check* answers None when KVM is
    ready (tests inject one; the lab host uses :func:`~threat_lab.kvm.kvm_problem`)."""

    def __init__(self, config: LabConfig, egress: Optional[EgressGuard] = None,
                 kvm_check: Callable[[], Optional[str]] = kvm_problem) -> None:
        self._config = config
        self._settings = _settings(config)
        self._egress = egress
        self._kvm_check = kvm_check
        self._network = ipaddress.IPv4Network(self._settings.bridge_network)
        self._bridge = lab_bridge()
        self._slots: "queue.Queue[int]" = queue.Queue()
        for slot in range(self._settings.slots):
            self._slots.put(slot)

    def command(self, vm_id: str, jail_base: Path) -> List[str]:
        """The exact jailer argv for one boot (tests read it)."""
        settings = self._settings
        memory_cap = (settings.memory_mb + _VMM_OVERHEAD_MB) * 1024 * 1024
        return [settings.jailer, "--id", vm_id, "--exec-file", settings.firecracker,
                "--uid", str(settings.uid), "--gid", str(settings.gid),
                "--chroot-base-dir", str(jail_base), "--cgroup-version", "2",
                "--cgroup", f"memory.max={memory_cap}",
                "--", "--no-api", "--config-file", "/vm.json"]

    def run(self, spec: SandboxSpec) -> SandboxResult:
        problem = self._kvm_check()
        if problem is not None:
            logger.error("level-4 job not run: %s", problem)
            return SandboxResult(exit_code=None, report=b"")
        started = time.monotonic()
        slot = self._slots.get()                      # a job past the slots waits here
        try:
            remaining = spec.timeout_seconds - (time.monotonic() - started)
            return self._boot(spec, slot, remaining)
        finally:
            self._slots.put(slot)

    def _boot(self, spec: SandboxSpec, slot: int, timeout_seconds: float) -> SandboxResult:
        if timeout_seconds <= 0:
            return SandboxResult(exit_code=None, report=b"", timed_out=True)
        vm_id = uuid.uuid4().hex
        guest = str(self._network.network_address + GUEST_ADDRESS_OFFSET + slot)
        gateway = str(self._network.network_address + 1)
        tap = f"tl{slot}{vm_id[:8]}"
        jail_base = spec.work_dir / "jail"
        root = jail_base / Path(self._settings.firecracker).name / vm_id / "root"
        config = boot_config(self._settings, guest, gateway, self._network.prefixlen, tap)
        argv = self.command(vm_id, jail_base)
        assert_image_only(config, argv)
        if not self._prepare_jail(root, config, spec.probe_args[1]):
            return SandboxResult(exit_code=None, report=b"")
        pcap = spec.work_dir / f"{vm_id}.pcap"
        recorder: Optional["subprocess.Popen[bytes]"] = None
        watched: List[str] = []
        try:
            try:
                self._add_tap(tap)
            except RuntimeError as error:
                logger.error("microVM %s: network set-up failed (%s): job not run", vm_id, error)
                return SandboxResult(exit_code=None, report=b"")
            recorder = self._record(tap, pcap)
            process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       stdin=subprocess.DEVNULL)
            cut: Dict[str, bool] = {}
            try:
                if self._egress is not None:
                    watch(process, timeout_seconds, self._egress, lambda: guest, watched)
                else:
                    process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                _kill(process)
                cut = {"timed_out": True}
            except CaughtScanning:
                _kill(process)
                logger.warning("microVM %s at %s went over the egress caps (scanning): killed", vm_id, guest)
                cut = {"scanning_killed": True}
        finally:
            for address in watched:
                self._egress.forget(address)
            _stop(recorder)
            self._helper(self._settings.ip, "link", "del", tap)
        recording = pcap.read_bytes() if pcap.is_file() else b""
        if cut:
            # The capture of a killed run is kept too: what it was doing is the finding's raw record.
            return SandboxResult(exit_code=None, report=b"", recordings=(recording,), **cut)
        return self._result(process.returncode, root / "report.img", recording, guest)

    def _prepare_jail(self, root: Path, config: Dict[str, Any], identifier: str) -> bool:
        """Kernel, a fresh rootfs copy (hash-checked), job + report drives, config."""
        root.mkdir(parents=True)
        shutil.copyfile(self._settings.kernel, root / "vmlinux")
        shutil.copyfile(self._settings.rootfs, root / "rootfs.ext4")
        if image_digest(root / "vmlinux", root / "rootfs.ext4") != self._config.image_sha256:
            logger.error("the microVM image on disk no longer matches the pinned digest: job not run")
            return False
        job = json.dumps({"identifier": identifier}).encode("utf-8")
        (root / "job.img").write_bytes(job + b"\0" * (-len(job) % _DRIVE_ALIGNMENT or _DRIVE_ALIGNMENT))
        with open(root / "report.img", "wb") as drive:
            drive.truncate(REPORT_DRIVE_BYTES)
        (root / "vm.json").write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
        # The jailer drops to uid:gid; the drives Firecracker writes must be writable to it.
        for name, mode in (("vmlinux", 0o444), ("job.img", 0o444), ("vm.json", 0o444),
                           ("rootfs.ext4", 0o666), ("report.img", 0o666)):
            (root / name).chmod(mode)
        return True

    def _add_tap(self, tap: str) -> None:
        ip, settings = self._settings.ip, self._settings
        self._helper(ip, "tuntap", "add", "dev", tap, "mode", "tap",
                     "user", str(settings.uid), "group", str(settings.gid), required=True)
        self._helper(ip, "link", "set", tap, "master", self._bridge, required=True)
        self._helper(ip, "link", "set", tap, "up", required=True)

    def _record(self, tap: str, pcap: Path) -> "subprocess.Popen[bytes]":
        recorder = subprocess.Popen([self._settings.tcpdump, "-i", tap, "-n", "-U", "-s", "512",
                                     "-Z", "root", "-w", str(pcap)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        waited = time.monotonic() + _TCPDUMP_START_SECONDS
        while not pcap.exists() and recorder.poll() is None and time.monotonic() < waited:
            time.sleep(0.05)                          # tcpdump writes its header once it is capturing
        return recorder

    def _helper(self, *argv: str, required: bool = False) -> None:
        try:
            done = subprocess.run(list(argv), capture_output=True, timeout=_HELPER_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            if required:
                raise RuntimeError(f"{argv[:3]} failed: {error}") from None
            return
        if required and done.returncode != 0:
            raise RuntimeError(f"{argv[:3]} failed with status {done.returncode}")

    def _result(self, exit_code: Optional[int], report_drive: Path, recording: bytes, guest: str) -> SandboxResult:
        if exit_code == _KILLED_STATUS:
            return SandboxResult(exit_code=exit_code, report=b"", out_of_memory=True, recordings=(recording,))
        report = _read_report(report_drive, self._config.caps.max_report_bytes)
        if report is None:
            return SandboxResult(exit_code=exit_code, report=b"", oversized=True, recordings=(recording,))
        try:
            guest_report = json.loads(report)
        except ValueError:
            guest_report = None
        if not isinstance(guest_report, dict):
            return SandboxResult(exit_code=exit_code, report=b"", recordings=(recording,))
        joined = with_traffic(guest_report, recording, guest)
        return SandboxResult(exit_code=exit_code, report=json.dumps(joined).encode("utf-8"), recordings=(recording,))


def with_traffic(guest_report: Dict[str, Any], recording: bytes, guest: str) -> Dict[str, Any]:
    """The guest's report plus ``traffic`` — what the HOST recorded on its TAP.
    No readable recording, no ``traffic``: the run then answers nothing about the network."""
    if not is_recording(recording):
        logger.warning("no readable traffic recording for the microVM at %s: its network is not reported", guest)
        return dict(guest_report)
    traffic = read_pcap(recording, guest)
    return {**guest_report, "traffic": {"hosts": list(traffic.hosts), "bait_seen": traffic.bait_seen}}


def _read_report(drive: Path, cap: int) -> Optional[bytes]:
    """The guest's report off the raw drive (``b"<length>\\n<json>"``); b"" when
    it wrote none; None when it claims more than *cap*."""
    try:
        with open(drive, "rb") as handle:
            header = handle.readline(16)
            if not header.rstrip(b"\n").isdigit():
                return b""
            length = int(header)
            if length > cap:
                return None
            return handle.read(length)
    except OSError:
        return b""


def _settings(config: LabConfig) -> MicroVMSettings:
    if config.microvm is None:
        raise LabConfigError("this lab has no microVM settings (it is a gVisor lab)")
    return config.microvm


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _mac(address: str) -> str:
    """A locally administered MAC carrying the guest's IPv4 address (unique per slot)."""
    return "06:00:" + ":".join(f"{octet:02x}" for octet in ipaddress.IPv4Address(address).packed)


def _kill(process: "subprocess.Popen[bytes]") -> None:
    # The jailer exec'd Firecracker in place (no --daemonize, no new pid namespace):
    # this pid IS the VMM, and killing it ends the microVM.
    process.kill()
    process.communicate()


def _stop(recorder: Optional["subprocess.Popen[bytes]"]) -> None:
    if recorder is None:
        return
    recorder.terminate()
    try:
        recorder.wait(timeout=_HELPER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        recorder.kill()
        recorder.wait()
