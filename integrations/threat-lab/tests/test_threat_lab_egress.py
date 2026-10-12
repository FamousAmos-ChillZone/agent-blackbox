"""The host egress policy (LR2): the ruleset parses with nft's own parser
(LES-037), says what §03.5 says, and the runner acts on it — a sandbox the
policy lists as an offender is killed and its run reports ``scanning-killed``
alone; a guard that could not tell never kills (LES-011); ``serve``/``run``
refuse to start without the policy loaded.

No root, nft or Docker needed except for the ``nft -c`` test (skipped with its
reason when nft is absent). The real thing runs on the lab host:
``tests/integration/test_blackbox_lab_egress.py``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

import pytest
from conftest import IMAGE_SHA256, RecordingSandbox

from threat_lab import cli, egress
from threat_lab.artifacts import ArtifactStore
from threat_lab.config import LabConfigError
from threat_lab.identifiers import threat_digest
from threat_lab.output import DONE
from threat_lab.runner import JobRequest, LabRunner
from threat_lab.sandbox import NO_NETWORK, GVisorSandbox, SandboxResult, SandboxSpec

RULESET = egress.RULESET_PATH.read_text(encoding="utf-8")
URL = "url:https://scanner.example.test/"
ADDRESS = "172.30.0.5"


def _key(level: int = 1) -> str:
    return f"{threat_digest(URL)}:{level}:{IMAGE_SHA256}"


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!{sys.executable}\nimport json, os, sys, time\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


# --- the ruleset file ---------------------------------------------------------

def test_the_ruleset_parses_with_nft():
    nft = shutil.which("nft")
    if nft is None:
        pytest.skip("nft is not installed here; CI and the lab host run this check")
    checked = subprocess.run([nft, "-c", "-f", str(egress.RULESET_PATH)], capture_output=True, text=True)
    if checked.returncode != 0 and "Operation not permitted" in checked.stderr:
        pytest.skip("nft -c needs CAP_NET_ADMIN here; run the suite as root on the lab host or in CI")
    assert checked.returncode == 0, checked.stderr


def _chain(name: str) -> str:
    matched = re.search(r"\tchain " + name + r" \{\n(.*?)\n\t\}", RULESET, re.DOTALL)
    assert matched, f"chain {name} missing"
    return matched.group(1)


def _rules(name: str) -> List[str]:
    """The chain's rules: not its hook header, blank lines or comments."""
    lines = (line.strip() for line in _chain(name).splitlines())
    return [line for line in lines if line and not line.startswith(("#", "type "))]


def test_only_web_and_dns_leave_and_everything_else_is_dropped():
    rules = _rules("from_lab")
    leaving = [rule for rule in rules if "jump new_connection" in rule]
    assert leaving == [
        "tcp dport { 80, 443 } tcp flags & (fin | syn | rst | ack) == syn ct state new jump new_connection",
        "udp dport 53 ct state new jump new_connection",
    ]
    assert rules[-1] == 'log prefix "threat-lab blocked " drop', "anything else (ICMP, raw IP, other ports) ends in a drop"
    assert not any(rule.endswith("accept") for rule in rules if "established" not in rule)
    # Every drop of a forbidden destination comes before replies are accepted.
    accept = rules.index("ct state established,related accept")
    for forbidden in ("@offenders", "169.254.169.254", "@private_ranges", "oifname $LAB_BRIDGE", "ipv6"):
        assert next(i for i, rule in enumerate(rules) if forbidden in rule) < accept, forbidden


def test_nothing_on_the_lab_bridge_reaches_the_host_or_another_sandbox():
    assert _rules("host_input") == ['iifname $LAB_BRIDGE log prefix "threat-lab host " drop']
    assert "type filter hook input" in _chain("host_input")
    assert _rules("to_lab") == ["ct state established,related accept", "drop"]
    # Sandbox to sandbox (br_netfilter on, which check_loaded demands): in on the bridge, out on it again.
    assert 'oifname $LAB_BRIDGE log prefix "threat-lab sandbox " drop' in _rules("from_lab")


@pytest.mark.parametrize("address", ["169.254.169.254", "10.1.2.3", "172.16.0.1", "172.31.255.254",
                                     "192.168.1.1", "100.64.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.1",
                                     "255.255.255.255", "198.18.0.1"])
def test_the_private_ranges_cover_every_internal_address(address):
    ranges = [ipaddress.ip_network(text) for text in
              re.search(r"set private_ranges \{.*?elements = \{(.*?)\}", RULESET, re.DOTALL).group(1).replace(",", " ").split()]
    assert any(ipaddress.ip_address(address) in network for network in ranges)


def test_both_caps_put_the_sandbox_in_offenders_and_drop():
    rules = _rules("new_connection")
    caps = [rule for rule in rules if "limit rate over" in rule]
    assert len(caps) == 2
    for rule in caps:
        assert rule.endswith('add @offenders { ip saddr } log prefix "threat-lab scan " drop'), rule
    # The destination cap counts only destinations not seen before.
    assert rules.index("ip saddr . ip daddr @seen_destinations accept") == rules.index(caps[1]) - 1


def test_the_runner_reads_the_names_the_ruleset_declares():
    assert egress.lab_bridge() == "threatlab0"
    assert f"table {egress.TABLE_FAMILY} {egress.TABLE_NAME} {{" in RULESET
    # Both ways: a per-address set added to the ruleset but not to PER_ADDRESS_SETS
    # would survive forget/reset, and a reused address would inherit its state.
    keyed_by_address = re.findall(r"\tset (\w+) \{\n\t\ttype ipv4_addr\n\t\tflags dynamic", RULESET)
    assert sorted(keyed_by_address) == sorted(egress.PER_ADDRESS_SETS)


# --- the guard over a stand-in nft --------------------------------------------

def _fake_nft(tmp_path: Path, listed: Optional[str], fail: bool = False) -> Path:
    log = tmp_path / "nft.log"
    return _executable(tmp_path / "nft", (
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        f"if {fail!r}: sys.exit(1)\n"
        f"if sys.argv[1:4] == ['--json', 'list', 'set']: print({listed!r})\n"))


def _listing(*addresses: str) -> str:
    elements = [{"elem": {"val": address, "timeout": 3600, "expires": 3500}} for address in addresses]
    return json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}},
                                     {"set": {"family": "inet", "name": "offenders", "table": "threat_lab",
                                              "type": "ipv4_addr", "elem": elements}}]})


def test_the_guard_answers_yes_no_and_could_not_tell(tmp_path):
    assert egress.NftablesEgressGuard(str(_fake_nft(tmp_path, _listing(ADDRESS)))).offended(ADDRESS) is True
    assert egress.NftablesEgressGuard(str(_fake_nft(tmp_path, _listing("172.30.0.9")))).offended(ADDRESS) is False
    assert egress.NftablesEgressGuard(str(_fake_nft(tmp_path, None, fail=True))).offended(ADDRESS) is None
    assert egress.NftablesEgressGuard(str(_fake_nft(tmp_path, "not json"))).offended(ADDRESS) is None
    assert egress.NftablesEgressGuard(str(tmp_path / "no-such-nft")).offended(ADDRESS) is None


def test_forget_and_reset_cover_every_per_address_set(tmp_path):
    guard = egress.NftablesEgressGuard(str(_fake_nft(tmp_path, "")))
    guard.forget(ADDRESS)
    guard.reset()
    calls = (tmp_path / "nft.log").read_text().splitlines()
    assert calls == [f"delete element inet threat_lab {name} {{ {ADDRESS} }}" for name in egress.PER_ADDRESS_SETS] + [
        f"flush set inet threat_lab {name}" for name in egress.PER_ADDRESS_SETS]
    with pytest.raises(LabConfigError):
        egress.NftablesEgressGuard(str(_fake_nft(tmp_path, None, fail=True))).reset()


def _switch(tmp_path: Path, value: Optional[str]) -> Path:
    path = tmp_path / "bridge-nf-call-iptables"
    if value is not None:
        path.write_text(value + "\n")
    return path


@pytest.mark.parametrize("nft_fails, netfilter, bridge, error", [
    (True, "1", "threatlab0", "not loaded"),
    (False, "0", "threatlab0", "br_netfilter is off"),
    (False, None, "threatlab0", "br_netfilter is off"),
    (False, "1", "docker0", "not on bridge"),
    (False, "1", "", "not on bridge"),
])
def test_check_loaded_fails_closed(tmp_path, nft_fails, netfilter, bridge, error):
    docker = _executable(tmp_path / "docker", f"print({bridge!r})")
    guard = egress.NftablesEgressGuard(str(_fake_nft(tmp_path, "", fail=nft_fails)))
    with pytest.raises(LabConfigError, match=error):
        guard.check_loaded(str(docker), "threat-lab", _switch(tmp_path, netfilter))


def test_check_loaded_passes_on_the_guarded_bridge(tmp_path):
    docker = _executable(tmp_path / "docker", "print('threatlab0')")
    egress.NftablesEgressGuard(str(_fake_nft(tmp_path, ""))).check_loaded(str(docker), "threat-lab",
                                                                          _switch(tmp_path, "1"))


def test_a_microvm_lab_needs_the_bridge_itself_and_asks_docker_nothing(tmp_path):
    """LR3: with no Docker network (network=None) the TAPs join the bridge directly,
    so check_loaded fails closed unless that bridge exists — and never runs docker."""
    guard = egress.NftablesEgressGuard(str(_fake_nft(tmp_path, "")))
    interfaces = tmp_path / "net"
    no_docker = str(tmp_path / "no-such-docker")
    with pytest.raises(LabConfigError, match="does not exist"):
        guard.check_loaded(no_docker, None, _switch(tmp_path, "1"), interfaces)
    (interfaces / egress.lab_bridge() / "bridge").mkdir(parents=True)
    guard.check_loaded(no_docker, None, _switch(tmp_path, "1"), interfaces)
    (interfaces / "docker0" / "bridge").mkdir(parents=True)        # some other bridge is not ours
    with pytest.raises(LabConfigError, match="br_netfilter is off"):
        guard.check_loaded(no_docker, None, _switch(tmp_path, "0"), interfaces)


def test_serve_and_run_refuse_to_start_without_the_policy(config, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # no nft, no docker
    assert cli.main(["run", "--image", config.image, "--home", str(config.home), "--level", "1",
                     "--key", _key(), "--identifier", URL]) == 2
    assert cli.main(["serve", "--image", config.image, "--home", str(config.home), "--port", "0"]) == 2


# --- the sandbox watching a probe ---------------------------------------------

class FakeGuard:
    """Says yes after *yes_after* questions (never, when None); records every call."""

    def __init__(self, answer: Optional[bool] = True, yes_after: int = 2) -> None:
        self.answer, self.yes_after = answer, yes_after
        self.asked: List[str] = []
        self.forgotten: List[str] = []

    def offended(self, address: str) -> Optional[bool]:
        self.asked.append(address)
        return self.answer if len(self.asked) >= self.yes_after else False

    def forget(self, address: str) -> None:
        self.forgotten.append(address)


def _fake_docker(tmp_path: Path, run_body: str) -> Path:
    """``run`` executes *run_body*; ``inspect`` prints the sandbox's address; ``kill`` is logged."""
    log = tmp_path / "docker.log"
    return _executable(tmp_path / "docker", (
        f"log = {str(log)!r}\n"
        "if sys.argv[1] == 'kill':\n"
        "    open(log, 'a').write('kill ' + sys.argv[2] + '\\n'); sys.exit(0)\n"
        f"if sys.argv[1] == 'inspect':\n    print({ADDRESS!r}); sys.exit(0)\n"
        f"{run_body}"))


def _spec(config, network: str, timeout: float = 20.0) -> SandboxSpec:
    return SandboxSpec(("look", URL), network, config.home, False, timeout)


def test_a_sandbox_the_policy_lists_is_killed_logged_and_reported(config, tmp_path, caplog):
    from dataclasses import replace
    configured = replace(config, docker=str(_fake_docker(tmp_path, "time.sleep(60)")))
    guard = FakeGuard(answer=True, yes_after=2)
    caplog.set_level(logging.WARNING, logger="threat_lab")
    started = time.monotonic()
    result = GVisorSandbox(configured, guard).run(_spec(configured, configured.network))

    assert time.monotonic() - started < 10, "killed at the offence, not at the deadline"
    assert result.scanning_killed and not result.timed_out and result.report == b""
    assert (tmp_path / "docker.log").read_text().startswith("kill threat-lab-")
    assert guard.asked and set(guard.asked) == {ADDRESS}
    # Cleared at first sight (a predecessor's state) and again once the sandbox is gone.
    assert guard.forgotten == [ADDRESS, ADDRESS]
    assert any("egress caps" in record.getMessage() and ADDRESS in record.getMessage() for record in caplog.records)


def test_a_guard_that_could_not_tell_never_kills(config, tmp_path):
    from dataclasses import replace
    body = "time.sleep(1); print(json.dumps({'status': 'ok', 'hosts': []}))"
    configured = replace(config, docker=str(_fake_docker(tmp_path, body)))
    guard = FakeGuard(answer=None, yes_after=1)
    result = GVisorSandbox(configured, guard).run(_spec(configured, configured.network))
    assert not result.scanning_killed and result.exit_code == 0
    assert json.loads(result.report) == {"status": "ok", "hosts": []}
    assert guard.asked, "the guard was asked while the probe ran"
    assert not (tmp_path / "docker.log").exists()


def test_a_watched_probe_still_stops_at_its_deadline(config, tmp_path):
    from dataclasses import replace
    configured = replace(config, docker=str(_fake_docker(tmp_path, "time.sleep(60)")))
    result = GVisorSandbox(configured, FakeGuard(answer=False)).run(_spec(configured, configured.network, timeout=1.0))
    assert result.timed_out and not result.scanning_killed


def test_a_probe_with_the_network_off_is_not_watched(config, tmp_path):
    from dataclasses import replace
    configured = replace(config, docker=str(_fake_docker(tmp_path, "print('{}')")))
    guard = FakeGuard()
    GVisorSandbox(configured, guard).run(_spec(configured, NO_NETWORK))
    assert guard.asked == [] and guard.forgotten == []


def test_a_scanning_kill_is_a_done_run_with_the_note_alone(config, caplog):
    sandbox = RecordingSandbox({"look": lambda spec: SandboxResult(exit_code=None, report=b"", scanning_killed=True)})
    caplog.set_level(logging.WARNING, logger="threat_lab")
    outcome = LabRunner(config, sandbox, ArtifactStore(config.artifacts_dir)).run(JobRequest(_key(), URL, 1))
    assert outcome.state == DONE
    assert set(outcome.output) == {"job_key", "started_at", "finished_at", "notes"}
    assert outcome.output["notes"] == ["scanning-killed"]
    assert any(_key() in record.getMessage() and "egress caps" in record.getMessage() for record in caplog.records)
