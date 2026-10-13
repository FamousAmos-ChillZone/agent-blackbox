"""Level 4 in Firecracker microVMs (build item LR3): FirecrackerSandbox, the KVM
guard, the board's two workers, and the level-4 output.

The real sandbox code runs against stand-in ``jailer``, ``ip`` and ``tcpdump``
executables (as LR1/LR2 stand in ``docker`` and ``nft``): the stand-in jailer
logs what it was handed — its argv, the jail's files, the boot config, the
root drive's hash — then behaves as the test asks (report, hang, or wait for a
release). The same assertions run against real Firecracker on the KVM host in
``tests/integration/test_blackbox_lab_microvm.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest


from threat_lab import cli, fixtures, kvm, microvm
from threat_lab.api import JobBoard, JobRefused
from threat_lab.artifacts import ArtifactStore
from threat_lab.config import DEFAULT_DEADLINE_SECONDS, LabConfig, LabConfigError, MicroVMSettings
from threat_lab.identifiers import threat_digest
from threat_lab.output import DONE, FAILED, QUEUED, RUNNING
from threat_lab.runner import JobRequest, LabRunner

PACKAGE = fixtures.MALICIOUS_PACKAGE_IDENTIFIER
GUEST_REPORT = {"status": "ok", "method": "install", "processes": [{"name": "sh", "phase": "install"}]}

_JAILER = '''
import hashlib, json, os, sys, time
args = sys.argv[1:]
value = lambda flag: args[args.index(flag) + 1]
root = os.path.join(value("--chroot-base-dir"), os.path.basename(value("--exec-file")), value("--id"), "root")
with open(os.path.join(root, "rootfs.ext4"), "rb") as handle:
    rootfs_sha256 = hashlib.sha256(handle.read()).hexdigest()
entry = {"argv": args, "root": root, "files": sorted(os.listdir(root)), "pid": os.getpid(),
         "config": json.load(open(os.path.join(root, "vm.json"))), "rootfs_sha256": rootfs_sha256,
         "rootfs_inode": os.stat(os.path.join(root, "rootfs.ext4")).st_ino}
log = os.environ["FAKE_VM_LOG"]
with open(log, "a") as handle:
    handle.write(json.dumps(entry) + "\\n")
mode = os.environ.get("FAKE_VM_MODE", "report")
if mode == "hang":
    time.sleep(60)
if mode == "block":
    while not os.path.exists(os.environ["FAKE_VM_RELEASE"]):
        time.sleep(0.05)
body = os.environ.get("FAKE_VM_REPORT", "").encode()
with open(os.path.join(root, "report.img"), "r+b") as drive:
    drive.write(str(len(body)).encode() + b"\\n" + body)
'''

_IP = '''
import os, sys
open(os.environ["FAKE_IP_LOG"], "a").write(" ".join(sys.argv[1:]) + "\\n")
sys.exit(1 if os.environ.get("FAKE_IP_FAIL") and sys.argv[1] == "tuntap" else 0)
'''

_TCPDUMP = '''
import os, signal, sys, time
args = sys.argv[1:]
open(os.environ["FAKE_TCPDUMP_LOG"], "a").write(str(os.getpid()) + "\\n")
recording = os.environ.get("FAKE_PCAP")
data = open(recording, "rb").read() if recording else b""
open(args[args.index("-w") + 1], "wb").write(data)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    time.sleep(0.05)
'''


def _tool(folder: Path, name: str, body: str) -> str:
    path = folder / name
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """A microVM lab config on stand-in tools, plus the paths the stand-ins log to."""
    tools = tmp_path / "tools"
    tools.mkdir()
    kernel, rootfs = tmp_path / "vmlinux", tmp_path / "rootfs.ext4"
    kernel.write_bytes(b"kernel " * 100)
    rootfs.write_bytes(b"clean root filesystem " * 1000)
    rootfs.chmod(0o444)
    recording = tmp_path / "recording.pcap"
    recording.write_bytes(fixtures.fixture_install_recording())
    logs = {name: tmp_path / f"{name}.log" for name in ("vm", "ip", "tcpdump")}
    monkeypatch.setenv("FAKE_VM_LOG", str(logs["vm"]))
    monkeypatch.setenv("FAKE_IP_LOG", str(logs["ip"]))
    monkeypatch.setenv("FAKE_TCPDUMP_LOG", str(logs["tcpdump"]))
    monkeypatch.setenv("FAKE_PCAP", str(recording))
    monkeypatch.setenv("FAKE_VM_REPORT", json.dumps(GUEST_REPORT))
    settings = MicroVMSettings(kernel=kernel, rootfs=rootfs, jailer=_tool(tools, "jailer", _JAILER),
                               firecracker="/usr/bin/firecracker", ip=_tool(tools, "ip", _IP),
                               tcpdump=_tool(tools, "tcpdump", _TCPDUMP))
    image = f"threat-lab-microvm@sha256:{microvm.image_digest(kernel, rootfs)}"
    config = LabConfig(home=tmp_path / "lab", image=image, microvm=settings)
    return config, logs


def _key(config: LabConfig, identifier: str = PACKAGE) -> str:
    return f"{threat_digest(identifier)}:4:{config.image_sha256}"


def _runner(config: LabConfig, **sandbox_options) -> LabRunner:
    sandbox = microvm.FirecrackerSandbox(config, kvm_check=sandbox_options.pop("kvm_check", lambda: None))
    return LabRunner(config, sandbox, ArtifactStore(config.artifacts_dir))


def _boots(logs) -> list:
    path = logs["vm"]
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return True
    return False


# -- criterion 1a: image-only boot, never a snapshot ---------------------------------

def test_every_microvm_boots_a_fresh_copy_of_the_clean_image_never_a_snapshot(lab):
    config, logs = lab
    runner = _runner(config)
    first = runner.run(JobRequest(_key(config), PACKAGE, 4))
    second = runner.run(JobRequest(_key(config), PACKAGE, 4))
    assert first.state == second.state == DONE

    boots = _boots(logs)
    assert len(boots) == 2
    clean = hashlib.sha256(config.microvm.rootfs.read_bytes()).hexdigest()
    clean_inode = config.microvm.rootfs.stat().st_ino
    for boot in boots:
        argv = boot["argv"]
        assert argv[argv.index("--") + 1:] == ["--no-api", "--config-file", "/vm.json"]
        assert not any("snapshot" in arg or "api-sock" in arg for arg in argv)
        assert set(boot["config"]) == microvm.BOOT_SECTIONS
        assert "snapshot" not in json.dumps(boot["config"]).lower()
        assert boot["files"] == ["job.img", "report.img", "rootfs.ext4", "vm.json", "vmlinux"]
        # The drive it boots is a copy of the clean image: same bytes, its own file.
        assert boot["rootfs_sha256"] == clean and boot["rootfs_inode"] != clean_inode
        assert {drive["path_on_host"] for drive in boot["config"]["drives"]} == {"/rootfs.ext4", "/job.img",
                                                                                "/report.img"}
    assert boots[0]["root"] != boots[1]["root"], "each job its own jail"
    assert not any(Path(boot["root"]).exists() for boot in boots), "the jail is deleted after"
    assert hashlib.sha256(config.microvm.rootfs.read_bytes()).hexdigest() == clean


def test_a_boot_config_that_could_resume_state_is_refused_before_anything_starts(lab, monkeypatch):
    config, logs = lab
    real = microvm.boot_config
    monkeypatch.setattr(microvm, "boot_config", lambda *args: {**real(*args), "snapshot": {"snapshot_path": "/s"}})
    with pytest.raises(AssertionError):
        _runner(config).run(JobRequest(_key(config), PACKAGE, 4))
    assert _boots(logs) == [] and not logs["ip"].exists()


@pytest.mark.parametrize("argv", [["jailer", "--", "--config-file", "/vm.json"],
                                  ["jailer", "--", "--no-api", "--api-sock", "/s", "--config-file", "/vm.json"]])
def test_an_argv_with_an_api_socket_is_refused(argv):
    with pytest.raises(AssertionError):
        microvm.assert_image_only({"boot-source": {}}, argv)


def test_an_image_changed_on_disk_never_boots(lab):
    config, logs = lab
    config.microvm.rootfs.chmod(0o644)
    config.microvm.rootfs.write_bytes(b"tampered")
    outcome = _runner(config).run(JobRequest(_key(config), PACKAGE, 4))
    assert outcome.state == FAILED and _boots(logs) == []
    with pytest.raises(LabConfigError):
        microvm.check_image(config)


# -- criterion 1b: past the deadline → killed → could-not-tell -------------------------

def test_a_job_past_its_deadline_is_killed_and_reads_could_not_tell(lab, monkeypatch):
    config, logs = lab
    monkeypatch.setenv("FAKE_VM_MODE", "hang")
    from dataclasses import replace
    capped = replace(config, deadline_seconds={4: 1.5})
    started = time.monotonic()
    outcome = _runner(capped).run(JobRequest(_key(capped), PACKAGE, 4))
    assert time.monotonic() - started < 10, "the job ends at its deadline, not when the guest does"

    assert outcome.state == DONE
    assert set(outcome.output) - {"job_key", "started_at", "finished_at"} == {"notes"}
    assert outcome.output["notes"] == ["deadline-reached"]          # the curator's Evidence: could-not-tell
    [boot] = _boots(logs)
    assert _gone(boot["pid"]), "the microVM's VMM process was killed"
    assert any(line.startswith("link del tl0") for line in logs["ip"].read_text().splitlines())
    assert all(_gone(int(pid)) for pid in logs["tcpdump"].read_text().split()), "the recorder was stopped"


def test_the_level_four_deadline_is_inside_five_minutes():
    assert DEFAULT_DEADLINE_SECONDS[4] < 5 * 60


# -- criterion 1c: two at once, a third waits ------------------------------------------

def _wait_for(predicate, seconds: float = 20.0) -> None:
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "timed out waiting"
        time.sleep(0.05)


def test_two_microvms_run_at_once_and_a_third_waits(lab, monkeypatch, tmp_path):
    config, logs = lab
    release = tmp_path / "release"
    monkeypatch.setenv("FAKE_VM_MODE", "block")
    monkeypatch.setenv("FAKE_VM_RELEASE", str(release))
    board = JobBoard(config, _runner(config), workers=config.microvm.slots)
    identifiers = [f"dep:npm:pkg-{index}@1.0.0" for index in range(3)]
    keys = [board.submit({"key": _key(config, identifier), "identifier": identifier, "level": 4})["key"]
            for identifier in identifiers]
    try:
        _wait_for(lambda: len(_boots(logs)) == 2)
        time.sleep(0.5)                                    # room for a third to start, if it could
        assert len(_boots(logs)) == 2
        states = sorted(board.status(key)["state"] for key in keys)
        assert states == sorted([RUNNING, RUNNING, QUEUED])
        assert {boot["argv"][boot["argv"].index("--id") + 1] for boot in _boots(logs)}.__len__() == 2
        release.write_text("go")
        _wait_for(lambda: all(board.status(key)["state"] == DONE for key in keys))
        assert len(_boots(logs)) == 3
    finally:
        release.write_text("go")
        board.shutdown()


def test_the_sandbox_itself_never_runs_more_microvms_than_its_slots(lab, monkeypatch, tmp_path):
    """Even without the board (an operator's `run` beside `serve` shares no board): the slot pool holds."""
    config, logs = lab
    release = tmp_path / "release"
    monkeypatch.setenv("FAKE_VM_MODE", "block")
    monkeypatch.setenv("FAKE_VM_RELEASE", str(release))
    runner = _runner(config)
    threads = [threading.Thread(target=runner.run, args=(JobRequest(_key(config), PACKAGE, 4),)) for _ in range(3)]
    for thread in threads:
        thread.start()
    try:
        _wait_for(lambda: len(_boots(logs)) == 2)
        time.sleep(0.5)
        assert len(_boots(logs)) == 2
        guests = {boot["config"]["boot-source"]["boot_args"].split("ip=")[1].split(":")[0] for boot in _boots(logs)}
        assert guests == {"172.30.4.10", "172.30.4.11"}, "one address per slot"
    finally:
        release.write_text("go")
        for thread in threads:
            thread.join(timeout=30)
    assert len(_boots(logs)) == 3


# -- criterion 3: no level-4 job without KVM -------------------------------------------

def test_no_microvm_starts_when_the_host_does_not_report_kvm(lab):
    config, logs = lab
    outcome = _runner(config, kvm_check=lambda: "/dev/kvm does not exist").run(JobRequest(_key(config), PACKAGE, 4))
    assert outcome.state == FAILED and outcome.output is None
    assert _boots(logs) == [] and not logs["ip"].exists() and not logs["tcpdump"].exists()


def test_the_sandbox_checks_kvm_on_this_host_by_default(lab):
    """No stand-in for the check: on a host without KVM (any CI or Mac) nothing boots."""
    config, logs = lab
    sandbox = microvm.FirecrackerSandbox(config)
    if kvm.kvm_problem() is None:
        pytest.skip("this host has KVM")
    outcome = LabRunner(config, sandbox, ArtifactStore(config.artifacts_dir)).run(JobRequest(_key(config), PACKAGE, 4))
    assert outcome.state == FAILED and _boots(logs) == []


def test_kvm_is_ready_only_on_a_definite_yes(tmp_path, monkeypatch):
    assert "does not exist" in kvm.kvm_problem(tmp_path / "kvm")
    plain = tmp_path / "plain"
    plain.write_bytes(b"")
    assert "not a KVM device" in kvm.kvm_problem(plain)
    monkeypatch.setattr(kvm.fcntl, "ioctl", lambda descriptor, request: 12)
    assert kvm.kvm_problem(plain) is None
    monkeypatch.setattr(kvm.fcntl, "ioctl", lambda descriptor, request: 11)
    assert "version 11" in kvm.kvm_problem(plain)
    plain.chmod(0)
    if os.geteuid() != 0:
        assert kvm.kvm_problem(plain) is not None


def test_serve_and_run_refuse_a_microvm_lab_without_kvm(lab, tmp_path, monkeypatch, capsys):
    config, logs = lab
    monkeypatch.setattr(kvm, "KVM_DEVICE", tmp_path / "no-kvm")
    for command in (["run", "--level", "4", "--key", _key(config), "--identifier", PACKAGE], ["serve"]):
        status = cli.main([*command, "--image", config.image, "--home", str(tmp_path / "home"),
                           "--kernel", str(config.microvm.kernel), "--rootfs", str(config.microvm.rootfs)])
        assert status == 2
        assert "no level-4 lab without KVM" in capsys.readouterr().err
    assert _boots(logs) == []


def test_kernel_and_rootfs_come_together(lab, tmp_path, capsys):
    config, _logs = lab
    status = cli.main(["run", "--level", "4", "--key", _key(config), "--identifier", PACKAGE,
                       "--image", config.image, "--home", str(tmp_path), "--kernel", str(config.microvm.kernel)])
    assert status == 2 and "both --kernel and --rootfs" in capsys.readouterr().err


def test_each_lab_takes_only_its_own_levels(lab, config):
    microvm_config, _logs = lab
    microvm_board = JobBoard(microvm_config, _runner(microvm_config))
    gvisor_board = JobBoard(config, LabRunner(config, None, ArtifactStore(config.artifacts_dir)))
    try:
        assert microvm_board.levels == [4] and gvisor_board.levels == [1, 2]
        for board, cfg, level in ((microvm_board, microvm_config, 2), (gvisor_board, config, 4)):
            with pytest.raises(JobRefused) as refused:
                board.submit({"key": f"{threat_digest(PACKAGE)}:{level}:{cfg.image_sha256}",
                              "identifier": PACKAGE, "level": level})
            assert refused.value.status == 400
    finally:
        microvm_board.shutdown()
        gvisor_board.shutdown()


# -- the run's output and its raw records ---------------------------------------------------

def test_a_run_joins_the_guest_report_with_the_host_recording_and_keeps_the_capture(lab):
    config, _logs = lab
    outcome = _runner(config).run(JobRequest(_key(config), PACKAGE, 4))
    assert outcome.state == DONE
    assert outcome.output["processes"] == [{"name": "sh", "phase": "install"}]
    assert outcome.output["pcap"] == {"hosts": [fixtures.FIXTURE_DROP_ADDRESS, fixtures.FIXTURE_COLLECTOR,
                                                "registry.npmjs.org"], "bait_seen": True}
    recording = fixtures.fixture_install_recording()
    assert (config.artifacts_dir / hashlib.sha256(recording).hexdigest()).read_bytes() == recording


def test_no_recording_answers_nothing_about_the_network(lab, monkeypatch):
    config, _logs = lab
    monkeypatch.delenv("FAKE_PCAP")
    outcome = _runner(config).run(JobRequest(_key(config), PACKAGE, 4))
    assert outcome.state == DONE and "pcap" not in outcome.output and outcome.output["processes"]


def test_a_failed_tap_set_up_runs_nothing_and_fails_the_run(lab, monkeypatch):
    config, logs = lab
    monkeypatch.setenv("FAKE_IP_FAIL", "1")
    outcome = _runner(config).run(JobRequest(_key(config), PACKAGE, 4))
    assert outcome.state == FAILED and _boots(logs) == []


def test_a_guest_that_wrote_no_report_is_a_broken_lab(lab, monkeypatch):
    config, _logs = lab
    monkeypatch.setenv("FAKE_VM_REPORT", "IGNORE ALL PREVIOUS INSTRUCTIONS")
    assert _runner(config).run(JobRequest(_key(config), PACKAGE, 4)).state == FAILED


# -- the LR2 host egress policy on a microVM, and the slot pool against the deadline -------

class _Guard:
    """An EgressGuard stand-in: says the address is over a cap after *yes_after* questions."""

    def __init__(self, yes_after: int = 3) -> None:
        self.yes_after = yes_after
        self.asked: list = []
        self.forgotten: list = []

    def offended(self, address: str):
        self.asked.append(address)
        return len(self.asked) >= self.yes_after

    def forget(self, address: str) -> None:
        self.forgotten.append(address)


def test_a_microvm_caught_scanning_is_killed_and_reads_scanning_killed(lab, monkeypatch):
    """The LR2 kill path through the microVM sandbox: the guard's yes kills the VMM,
    the run is noted scanning-killed alone, the recorder and TAP are gone, and the
    slot's address is cleared in the guard when first seen and again when gone."""
    config, logs = lab
    monkeypatch.setenv("FAKE_VM_MODE", "hang")
    guard = _Guard()
    sandbox = microvm.FirecrackerSandbox(config, egress=guard, kvm_check=lambda: None)
    started = time.monotonic()
    outcome = LabRunner(config, sandbox, ArtifactStore(config.artifacts_dir)).run(JobRequest(_key(config), PACKAGE, 4))
    assert time.monotonic() - started < 10, "killed on the guard's yes, not at the deadline"

    assert outcome.state == DONE and outcome.output["notes"] == ["scanning-killed"]
    assert set(outcome.output) - {"job_key", "started_at", "finished_at"} == {"notes"}
    assert guard.asked and set(guard.asked) == {"172.30.4.10"}, "the guard is asked about slot 0's guest"
    assert guard.forgotten == ["172.30.4.10", "172.30.4.10"]
    [boot] = _boots(logs)
    assert _gone(boot["pid"]), "the microVM's VMM process was killed"
    assert any(line.startswith("link del tl0") for line in logs["ip"].read_text().splitlines())
    assert all(_gone(int(pid)) for pid in logs["tcpdump"].read_text().split()), "the recorder was stopped"


def test_a_job_whose_slot_wait_outlasts_its_deadline_never_boots_and_reads_could_not_tell(lab, monkeypatch, tmp_path):
    """One slot held by a running job: a second job that waited past its own
    deadline boots nothing (no microVM for a job already over time) and is noted
    deadline-reached — the same could-not-tell as a job killed mid-run."""
    from dataclasses import replace
    config, logs = lab
    one_slot = replace(config, microvm=replace(config.microvm, slots=1))
    release = tmp_path / "release"
    monkeypatch.setenv("FAKE_VM_MODE", "block")
    monkeypatch.setenv("FAKE_VM_RELEASE", str(release))
    runner = _runner(one_slot)
    holder = threading.Thread(target=runner.run, args=(JobRequest(_key(one_slot), PACKAGE, 4),))
    holder.start()
    outcomes: list = []
    short = replace(one_slot, deadline_seconds={4: 0.5})
    waiter = threading.Thread(
        target=lambda: outcomes.append(LabRunner(short, runner._sandbox, ArtifactStore(short.artifacts_dir))
                                       .run(JobRequest(_key(short, "dep:npm:other@1.0.0"), "dep:npm:other@1.0.0", 4))))
    try:
        _wait_for(lambda: len(_boots(logs)) == 1)
        waiter.start()
        time.sleep(1.0)                                    # well past the waiter's deadline
        assert len(_boots(logs)) == 1 and waiter.is_alive(), "the second job waits for the slot"
    finally:
        release.write_text("go")
        holder.join(timeout=30)
        waiter.join(timeout=30)
    assert len(_boots(logs)) == 1, "a job past its deadline never boots"
    [outcome] = outcomes
    assert outcome.state == DONE and outcome.output["notes"] == ["deadline-reached"]
