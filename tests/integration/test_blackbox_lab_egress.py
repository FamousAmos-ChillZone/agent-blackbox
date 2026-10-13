"""The lab host's egress policy, end to end (trust-and-threat-lab §03.5 / §06, build item LR2).

Runs ONLY on the lab host, as root, with the policy loaded and the sandbox
image built::

    nft -f integrations/threat-lab/egress.nft
    docker network create -o com.docker.network.bridge.name=threatlab0 \\
        -o com.docker.network.bridge.enable_icc=false threat-lab
    THREAT_LAB_IMAGE=<name>@sha256:<hex> pytest -m integration tests/integration/test_blackbox_lab_egress.py

Anywhere else every test skips and says why. Two proofs:

* a scanning sample is killed, logged, and its run's Evidence (built by the
  curator's own extractor) carries the closed-vocabulary note ``scanning-killed``;
* a sandbox reaches the public web but not the private ranges, the cloud
  metadata address or the lab host.

The scanning sample is polite on purpose (ground rules, F-014; provider terms,
F-013): it trips the new-connection cap by opening HTTPS connections to ONE
public anycast host (``THREAT_LAB_EGRESS_TARGET``, default 1.1.1.1 — point it
at a server you run if you prefer); the distinct-destination cap is the same
offender path and is pinned by the runner's unit tests. Nothing here probes a
third party's network.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import pytest

pytestmark = pytest.mark.integration

_RUNNER_ROOT = Path(__file__).resolve().parents[2] / "integrations" / "threat-lab"
if str(_RUNNER_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNNER_ROOT))

from threat_lab.artifacts import ArtifactStore
from threat_lab.config import LabConfig, LabConfigError
from threat_lab.egress import NftablesEgressGuard
from threat_lab.identifiers import threat_digest
from threat_lab.runner import JobRequest, LabRunner
from threat_lab.sandbox import GVisorSandbox, SandboxSpec

PUBLIC_TARGET = os.environ.get("THREAT_LAB_EGRESS_TARGET", "1.1.1.1")
SCANNING_IDENTIFIER = "url:https://scanner.example.test/"

#: Opens HTTPS connections to one host as fast as it can: a scanner's rate.
_SCANNER = f"""
import socket
for attempt in range(400):
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect(({PUBLIC_TARGET!r}, 443))
    except OSError:
        pass
    finally:
        s.close()
print('{{"status": "ok", "hosts": []}}')
"""


class SampleSandbox(GVisorSandbox):
    """The real sandbox (same flags, network, watch and kill path) running a
    test program in place of the probe."""

    def __init__(self, config: LabConfig, egress: NftablesEgressGuard, program: str) -> None:
        super().__init__(config, egress)
        self._program = program

    def command(self, spec: SandboxSpec, name: str) -> list[str]:
        argv = super().command(spec, name)
        return argv[:argv.index(self._config.image) + 1] + ["python", "-c", self._program]


@pytest.fixture(scope="module")
def lab() -> dict[str, object]:
    """The lab host's config and guard, or a skip naming what is missing."""
    if platform.system() != "Linux":
        pytest.skip("runs only on the lab host (Linux with nftables, Docker and gVisor)")
    for tool in ("nft", "docker"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is not installed: this is not the lab host")
    image = os.environ.get("THREAT_LAB_IMAGE", "")
    if not image:
        pytest.skip("set THREAT_LAB_IMAGE to the digest-pinned sandbox image (name@sha256:<hex>)")
    config = LabConfig(home=Path(os.environ.get("THREAT_LAB_TEST_HOME", "/tmp/threat-lab-egress-test")), image=image)
    guard = NftablesEgressGuard()
    try:
        guard.check_loaded(config.docker, config.network)
    except LabConfigError as error:
        pytest.skip(f"the egress policy is not in place on this host: {error}")
    return {"config": config, "guard": guard}


def test_a_scanning_sample_is_killed_logged_and_noted_in_the_evidence(lab, caplog):
    from plugins.blackbox.curate.lab.evidence_schema import NoteCode
    from plugins.blackbox.curate.lab.extractor import extract
    from plugins.blackbox.curate.lab.jobs import LabJob
    from plugins.blackbox.curate.queue import Lane

    config, guard = lab["config"], lab["guard"]
    key = f"{threat_digest(SCANNING_IDENTIFIER)}:1:{config.image_sha256}"
    runner = LabRunner(config, SampleSandbox(config, guard, _SCANNER), ArtifactStore(config.artifacts_dir))
    caplog.set_level(logging.WARNING, logger="threat_lab")

    outcome = runner.run(JobRequest(key, SCANNING_IDENTIFIER, 1))

    assert outcome.state == "done"
    assert outcome.output["notes"] == ["scanning-killed"], outcome.output
    logged = [record.getMessage() for record in caplog.records]
    assert any("egress caps" in message and "killed" in message for message in logged), logged
    assert any(key in message for message in logged), "the kill is logged against its job"

    job = LabJob(key, SCANNING_IDENTIFIER, 1, list(Lane)[0], "", 0.0)
    evidence = extract(job, outcome.output)
    assert NoteCode.SCANNING_KILLED in evidence.notes
    assert evidence.observations == ()


def _gateway(config: LabConfig) -> str:
    """The lab bridge's address on the host (the sandbox's default gateway)."""
    inspected = subprocess.run(
        [config.docker, "network", "inspect", config.network, "--format", "{{(index .IPAM.Config 0).Gateway}}"],
        capture_output=True, text=True, check=True, timeout=10)
    return inspected.stdout.strip()


def _reachability(config: LabConfig, guard: NftablesEgressGuard, targets: list[str]) -> dict[str, bool]:
    """``{"host:port": connected}`` for each target, tried from inside a real sandbox."""
    program = f"""
import json, socket
reached = {{}}
for target in {targets!r}:
    host, port = target.rsplit(":", 1)
    s = socket.socket(); s.settimeout(3.0)
    try:
        s.connect((host, int(port))); reached[target] = True
    except OSError:
        reached[target] = False
    finally:
        s.close()
print(json.dumps(reached))
"""
    config.work_dir.mkdir(parents=True, exist_ok=True)
    result = SampleSandbox(config, guard, program).run(
        SandboxSpec(("reach",), config.network, config.work_dir, False, 60.0))
    assert result.exit_code == 0 and not result.scanning_killed, result
    return json.loads(result.report)


def test_no_egress_to_private_ranges_the_metadata_address_or_the_lab_host(lab):
    config, guard = lab["config"], lab["guard"]
    gateway = _gateway(config)
    forbidden = ["169.254.169.254:80", "10.0.0.1:443", "172.16.0.1:443", "192.168.0.1:443",
                 "100.64.0.1:443", f"{gateway}:22", f"{gateway}:80", f"{gateway}:443"]
    control = f"{PUBLIC_TARGET}:443"
    reached = _reachability(config, guard, [control, *forbidden])

    # The control: without it, "nothing connected" could just mean no network at all.
    assert reached[control], f"the sandbox could not reach {control}: the test cannot tell"
    assert [target for target in forbidden if reached[target]] == []
