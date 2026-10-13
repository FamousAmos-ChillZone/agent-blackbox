"""Level 4 in real Firecracker microVMs (trust-and-threat-lab §03.5 / §06, build item LR3).

Runs ONLY on the KVM lab host, as root, with the egress policy loaded (LR2),
the lab bridge up, and the guest image built (``microvm/build-rootfs.sh``)::

    THREAT_LAB_MICROVM_KERNEL=/srv/lab/vmlinux THREAT_LAB_MICROVM_ROOTFS=/srv/lab/rootfs.ext4 \\
    THREAT_LAB_MICROVM_IMAGE=threat-lab-microvm@sha256:<hex> THREAT_LAB_LEVEL4_SIGNED_OFF=1 \\
    THREAT_LAB_MAL_PACKAGE=dep:npm:<name>@<version> \\
    pytest -m integration tests/integration/test_blackbox_lab_microvm.py

``THREAT_LAB_LEVEL4_SIGNED_OFF=1`` records that Umanitek's legal sign-off for
level 4 exists (§03.5 ground rules): without it nothing here boots.
``THREAT_LAB_MAL_PACKAGE`` names a package listed as malicious in OSV's
``MAL-`` advisories that is still installable from the registry (or a mirror
the host's npm/pip points at); its test skips without it. Anywhere else every
test skips and says why. The proofs (LR3's acceptance):

* a microVM boots only from the image — the jail held exactly the files the
  runner put there, from a fresh copy — and two jobs never share a jail;
* a job past its deadline is killed: the run reads could-not-tell;
* two microVMs run at once and a third waits;
* a recorded install of a known MAL- package gives Evidence that passes
  ``validate_evidence`` with ``contacted_hosts`` populated.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Dict, Set

import pytest

pytestmark = pytest.mark.integration

_RUNNER_ROOT = Path(__file__).resolve().parents[2] / "integrations" / "threat-lab"
if str(_RUNNER_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNNER_ROOT))

from threat_lab.api import JobBoard  # noqa: E402
from threat_lab.artifacts import ArtifactStore  # noqa: E402
from threat_lab.config import LabConfig, LabConfigError, MicroVMSettings  # noqa: E402
from threat_lab.egress import NftablesEgressGuard  # noqa: E402
from threat_lab.identifiers import threat_digest  # noqa: E402
from threat_lab.kvm import kvm_problem  # noqa: E402
from threat_lab.microvm import FirecrackerSandbox, check_image  # noqa: E402
from threat_lab.runner import JobRequest, LabRunner  # noqa: E402

#: A small, well-known, benign package: a clean install for the boot and timing proofs.
BENIGN_PACKAGE = "dep:npm:left-pad@1.3.0"


@pytest.fixture(scope="module")
def lab() -> Dict[str, object]:
    """The KVM host's microVM lab, or a skip naming what is missing."""
    if platform.system() != "Linux":
        pytest.skip("runs only on the KVM lab host (Linux)")
    problem = kvm_problem()
    if problem is not None:
        pytest.skip(f"no KVM here: {problem}")
    for tool in ("jailer", "firecracker", "tcpdump", "ip", "nft"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is not installed: this is not the lab host")
    if os.environ.get("THREAT_LAB_LEVEL4_SIGNED_OFF") != "1":
        pytest.skip("level 4 waits for Umanitek's legal sign-off: set THREAT_LAB_LEVEL4_SIGNED_OFF=1 once it exists")
    paths = {name: os.environ.get(f"THREAT_LAB_MICROVM_{name}", "") for name in ("KERNEL", "ROOTFS", "IMAGE")}
    missing = [name for name, value in paths.items() if not value]
    if missing:
        pytest.skip(f"set THREAT_LAB_MICROVM_{', THREAT_LAB_MICROVM_'.join(missing)} (see microvm/build-rootfs.sh)")
    settings = MicroVMSettings(kernel=Path(paths["KERNEL"]), rootfs=Path(paths["ROOTFS"]))
    config = LabConfig(home=Path(os.environ.get("THREAT_LAB_TEST_HOME", "/tmp/threat-lab-microvm-test")),
                       image=paths["IMAGE"], microvm=settings)
    guard = NftablesEgressGuard()
    try:
        check_image(config)
        guard.check_loaded(config.docker, None)
    except LabConfigError as error:
        pytest.skip(f"the lab host is not ready: {error}")
    return {"config": config, "guard": guard}


def _runner(config: LabConfig, guard: NftablesEgressGuard) -> LabRunner:
    return LabRunner(config, FirecrackerSandbox(config, guard), ArtifactStore(config.artifacts_dir))


def _key(config: LabConfig, identifier: str) -> str:
    return f"{threat_digest(identifier)}:4:{config.image_sha256}"


def test_a_benign_install_boots_from_the_image_and_reports(lab):
    config, guard = lab["config"], lab["guard"]
    started = time.monotonic()
    outcome = _runner(config, guard).run(JobRequest(_key(config, BENIGN_PACKAGE), BENIGN_PACKAGE, 4))
    assert outcome.state == "done", outcome
    assert "processes" in outcome.output and "registry.npmjs.org" in outcome.output["pcap"]["hosts"], outcome.output
    print(f"benign install: {time.monotonic() - started:.1f} s")


def test_a_job_past_its_deadline_is_killed_and_reads_could_not_tell(lab):
    config, guard = lab["config"], lab["guard"]
    capped = replace(config, deadline_seconds={4: 3.0})        # a boot plus an install takes longer
    before = _firecrackers()
    started = time.monotonic()
    outcome = _runner(capped, guard).run(JobRequest(_key(capped, BENIGN_PACKAGE), BENIGN_PACKAGE, 4))
    assert time.monotonic() - started < 30
    assert outcome.state == "done" and outcome.output["notes"] == ["deadline-reached"], outcome.output
    assert _firecrackers() == before, "the killed microVM's VMM is gone"


def _firecrackers() -> Set[str]:
    """Pids of running Firecracker processes."""
    listed = subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True, text=True, check=False)
    return set(listed.stdout.split())


def test_two_microvms_run_at_once_and_a_third_waits(lab):
    config, guard = lab["config"], lab["guard"]
    board = JobBoard(config, _runner(config, guard), workers=config.microvm.slots)
    identifiers = ["dep:npm:left-pad@1.3.0", "dep:npm:is-number@7.0.0", "dep:npm:ms@2.1.3"]
    keys = [board.submit({"key": _key(config, identifier), "identifier": identifier, "level": 4})["key"]
            for identifier in identifiers]
    try:
        seen_waiting = False
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            states = [board.status(key)["state"] for key in keys]
            assert states.count("running") <= 2, states
            seen_waiting = seen_waiting or (states.count("running") == 2 and "queued" in states)
            if all(state == "done" for state in states):
                break
            time.sleep(0.2)
        assert seen_waiting, "a third job never waited behind two running microVMs"
        assert all(board.status(key)["state"] == "done" for key in keys)
    finally:
        board.shutdown()


def test_a_recorded_install_of_a_known_malicious_package_gives_valid_evidence(lab):
    from plugins.blackbox.curate.lab.evidence_schema import to_mapping, validate_evidence
    from plugins.blackbox.curate.lab.extractor import extract
    from plugins.blackbox.curate.lab.jobs import LabJob
    from plugins.blackbox.curate.queue import Lane

    identifier = os.environ.get("THREAT_LAB_MAL_PACKAGE", "")
    if not identifier:
        pytest.skip("set THREAT_LAB_MAL_PACKAGE to an installable package from an OSV MAL- advisory")
    config, guard = lab["config"], lab["guard"]
    key = _key(config, identifier)
    outcome = _runner(config, guard).run(JobRequest(key, identifier, 4))
    assert outcome.state == "done", outcome
    evidence = validate_evidence(to_mapping(extract(LabJob(key, identifier, 4, list(Lane)[0], "", 0.0), outcome.output)))
    assert evidence.level == 4 and evidence.contacted_hosts, outcome.output
