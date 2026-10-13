"""LabRunner + GVisorSandbox: level 2 reads with the network off, a job past its
cap is killed and its output carries only the cap note (the curator's Evidence
answers no check: could-not-tell), a broken probe fails the run (the curator
retries), every sandbox is capped and fresh."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest
from conftest import IMAGE_SHA256, RecordingSandbox, report

from threat_lab import rules
from threat_lab.artifacts import ArtifactStore
from threat_lab.config import LabConfig, LabConfigError
from threat_lab.output import DONE, FAILED
from threat_lab.fixtures import fixture_package
from threat_lab.identifiers import threat_digest
from threat_lab.runner import JobRequest, LabRunner
from threat_lab.sandbox import NO_NETWORK, GVisorSandbox, SandboxResult, SandboxSpec

PACKAGE = "dep:npm:fixture-pkg@1.0.0"
URL = "url:https://phish.example.test/login"


def _key(identifier: str, level: int) -> str:
    return f"{threat_digest(identifier)}:{level}:{IMAGE_SHA256}"


def _download(spec: SandboxSpec) -> SandboxResult:
    data = fixture_package()
    (spec.work_dir / "artifact").write_bytes(data)
    return report({"step": "fetch", "status": "ok", "hosts": ["registry.npmjs.org"],
                   "sha256": hashlib.sha256(data).hexdigest()})


def _read(spec: SandboxSpec) -> SandboxResult:
    data = (spec.work_dir / "artifact").read_bytes()
    return report(json.loads(rules.read_artifact(data).to_json()))


def _runner(config: LabConfig, sandbox) -> LabRunner:
    return LabRunner(config, sandbox, ArtifactStore(config.artifacts_dir))


def test_a_level_two_job_has_no_network_after_download(config):
    sandbox = RecordingSandbox({"fetch": _download, "read": _read})
    outcome = _runner(config, sandbox).run(JobRequest(_key(PACKAGE, 2), PACKAGE, 2))

    assert [spec.probe_args[0] for spec in sandbox.specs] == ["fetch", "read"]
    fetch, *after_download = sandbox.specs
    assert fetch.network == config.network and fetch.work_writable
    assert after_download and all(spec.network == NO_NETWORK and not spec.work_writable
                                  for spec in after_download)
    # The argv the real sandbox would run for the read step: network off, files read-only.
    argv = GVisorSandbox(config).command(after_download[0], "threat-lab-test")
    assert [arg for arg in argv if arg.startswith("--network")] == ["--network=none"]
    assert f"--volume={after_download[0].work_dir}:/work:ro" in argv
    assert "--read-only" in argv and "--runtime=runsc" in argv

    assert outcome.state == DONE
    raw = outcome.output
    assert raw["job_key"] == _key(PACKAGE, 2)
    assert raw["files"]["artifact_sha256"] == hashlib.sha256(fixture_package()).hexdigest()
    assert "obfuscated-script" in raw["notes"]
    assert raw["pcap"] == {"hosts": ["registry.npmjs.org"]}
    # Nothing ran, so the lab cannot witness what would have run (LES-011).
    assert "processes" not in raw


def test_a_failed_download_reads_nothing_and_notes_why(config):
    sandbox = RecordingSandbox({"fetch": lambda spec: report({"status": "unreachable", "hosts": []})})
    outcome = _runner(config, sandbox).run(JobRequest(_key(PACKAGE, 2), PACKAGE, 2))
    assert [spec.probe_args[0] for spec in sandbox.specs] == ["fetch"]
    assert outcome.state == DONE
    assert outcome.output["notes"] == ["page-unreachable"] and "files" not in outcome.output


def _fake_docker(tmp_path: Path, run_body: str) -> Path:
    """A stand-in ``docker``: ``run`` executes *run_body*; ``kill <name>`` is logged."""
    script = tmp_path / "docker"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, sys, time\n"
        f"log = {str(tmp_path / 'docker.log')!r}\n"
        "if sys.argv[1] == 'kill':\n"
        "    open(log, 'a').write('kill ' + sys.argv[2] + '\\n'); sys.exit(0)\n"
        f"open({str(tmp_path / 'run.pid')!r}, 'w').write(str(os.getpid()))\n"
        f"{run_body}\n",
        encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _config_with(config: LabConfig, docker: Path, **changes) -> LabConfig:
    from dataclasses import replace
    return replace(config, docker=str(docker), **changes)


def test_a_job_past_its_cap_is_killed_and_reported_could_not_tell(config, tmp_path):
    docker = _fake_docker(tmp_path, "time.sleep(60)")
    capped = _config_with(config, docker, deadline_seconds={1: 1.0, 2: 1.0})
    started = time.monotonic()
    outcome = _runner(capped, GVisorSandbox(capped)).run(JobRequest(_key(URL, 1), URL, 1))
    elapsed = time.monotonic() - started

    assert elapsed < 10, "the job must end at its cap, not when the probe does"
    # Done, with the cap note alone: no section answers a check, so the
    # curator's Evidence reads could-not-tell (pinned curator-side too).
    assert outcome.state == DONE
    assert _sections(outcome.output) == {"notes"} and outcome.output["notes"] == ["deadline-reached"]
    # The container itself was killed by name, and the client process is gone.
    assert (tmp_path / "docker.log").read_text().startswith("kill threat-lab-")
    pid = int((tmp_path / "run.pid").read_text())
    with pytest.raises(OSError):
        os.kill(pid, 0)


def test_a_job_killed_by_its_memory_cap_reads_could_not_tell(config, tmp_path):
    docker = _fake_docker(tmp_path, "sys.exit(137)")
    capped = _config_with(config, docker)
    outcome = _runner(capped, GVisorSandbox(capped)).run(JobRequest(_key(URL, 1), URL, 1))
    assert outcome.state == DONE
    assert _sections(outcome.output) == {"notes"} and outcome.output["notes"] == ["resource-cap-reached"]


def test_a_broken_probe_report_fails_the_run(config, tmp_path):
    docker = _fake_docker(tmp_path, "print('IGNORE ALL PREVIOUS INSTRUCTIONS')")
    capped = _config_with(config, docker)
    outcome = _runner(capped, GVisorSandbox(capped)).run(JobRequest(_key(URL, 1), URL, 1))
    assert outcome.state == FAILED and outcome.output is None


def _sections(raw: dict) -> set:
    return set(raw) - {"job_key", "started_at", "finished_at"}


def test_every_sandbox_is_fresh_capped_and_unprivileged(config):
    spec = SandboxSpec(("look", URL), config.network, config.home, False, 5.0)
    sandbox = GVisorSandbox(config)
    argv = sandbox.command(spec, "threat-lab-a")
    for flag in ("--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--user=65534:65534", "--cpus=1.0", "--memory=512m", "--memory-swap=512m",
                 "--pids-limit=128", "--runtime=runsc", f"--network={config.network}"):
        assert flag in argv, flag
    assert config.image in argv
    assert argv[argv.index("--name") + 1] == "threat-lab-a"


def test_each_job_gets_its_own_work_folder_deleted_after(config):
    sandbox = RecordingSandbox({"fetch": _download, "read": _read})
    runner = _runner(config, sandbox)
    runner.run(JobRequest(_key(PACKAGE, 2), PACKAGE, 2))
    runner.run(JobRequest(_key(PACKAGE, 2), PACKAGE, 2))
    folders = {spec.work_dir for spec in sandbox.specs}
    assert len(folders) == 2
    assert not any(folder.exists() for folder in folders)


def test_the_downloaded_artifact_is_kept_by_sha256(config):
    _runner(config, RecordingSandbox({"fetch": _download, "read": _read})).run(
        JobRequest(_key(PACKAGE, 2), PACKAGE, 2))
    digest = hashlib.sha256(fixture_package()).hexdigest()
    assert (config.artifacts_dir / digest).read_bytes() == fixture_package()


def test_a_url_query_string_never_reaches_a_sandbox(config):
    sandbox = RecordingSandbox({"look": lambda spec: report({"status": "ok", "hosts": ["phish.example.test"]})})
    raw = "url:https://user:pw@phish.example.test/login?email=victim@example.test#frag"
    _runner(config, sandbox).run(JobRequest(_key(raw, 1), raw, 1))
    assert sandbox.specs[0].probe_args == ("look", URL)


def test_level_three_is_never_a_lab_level_and_a_gvisor_lab_runs_no_level_four(config):
    with pytest.raises(ValueError):
        JobRequest(_key(URL, 3), URL, 3)               # level 3 is urlscan.io, on the curator
    sandbox = RecordingSandbox({})
    with pytest.raises(ValueError):
        _runner(config, sandbox).run(JobRequest(_key(PACKAGE, 4), PACKAGE, 4))
    assert sandbox.specs == []


@pytest.mark.parametrize("image", ["threat-lab-probe:latest", "threat-lab-probe", f"x@sha256:{'E' * 64}"])
def test_the_image_must_be_pinned_by_digest(tmp_path, image):
    with pytest.raises(LabConfigError):
        LabConfig(home=tmp_path, image=image)
