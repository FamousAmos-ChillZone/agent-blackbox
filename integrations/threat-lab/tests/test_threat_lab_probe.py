"""The in-sandbox probe: identifier parsing, error statuses, and the read step's
report — without any network (look/fetch are exercised on the lab host)."""

from __future__ import annotations

import json
import ssl
import urllib.error

import pytest

from threat_lab import probe
from threat_lab.fixtures import fixture_package
from threat_lab.identifiers import TargetKind, parse_target


@pytest.mark.parametrize("identifier, kind, detail", [
    ("dep:npm:left-pad@1.3.0", TargetKind.PACKAGE, ("npm", "left-pad", "1.3.0")),
    ("dep:npm:@scope/pkg@2.0.0", TargetKind.PACKAGE, ("npm", "@scope/pkg", "2.0.0")),
    ("dep:pypi:requests@2.32.0", TargetKind.PACKAGE, ("pypi", "requests", "2.32.0")),
    ("url:https://Phish.Example.test/login", TargetKind.URL, "phish.example.test"),
    ("ioc:domain:example.test.", TargetKind.DOMAIN, "example.test"),
    ("ioc:wallet:0x" + "A" * 40, TargetKind.WALLET, "0x" + "a" * 40),
    ("url:ftp://example.test/x", TargetKind.UNSUPPORTED, None),
    ("url:https://localhost/", TargetKind.UNSUPPORTED, None),
    ("injection:abc", TargetKind.UNSUPPORTED, None),
])
def test_identifiers_parse_to_targets(identifier, kind, detail):
    target = parse_target(identifier)
    assert target.kind is kind
    if kind is TargetKind.PACKAGE:
        assert (target.ecosystem, target.name, target.version) == detail
    elif kind in (TargetKind.URL, TargetKind.DOMAIN):
        assert target.host == detail
    elif kind is TargetKind.WALLET:
        assert target.address == detail


@pytest.mark.parametrize("error, status", [
    (probe._TooLarge("u"), "too-large"),
    (ssl.SSLError("bad cert"), "tls-error"),
    (urllib.error.URLError(ssl.SSLError("bad cert")), "tls-error"),
    (urllib.error.URLError("refused"), "unreachable"),
    (KeyError("dist"), "malformed"),
])
def test_probe_errors_become_statuses(error, status):
    assert probe._status_of(error) == status


def test_an_unsupported_identifier_is_not_looked_up():
    report = probe.look("injection:abc")
    assert report["status"] == "unsupported" and report["hosts"] == []


def test_fetch_refuses_a_domain_without_contacting_anything(tmp_path):
    report = probe.fetch_artifact("domain:example.test", str(tmp_path / "artifact"))
    assert report["status"] == "unsupported" and not (tmp_path / "artifact").exists()


def test_the_read_step_prints_one_json_report(tmp_path, capsys):
    (tmp_path / "artifact").write_bytes(fixture_package())
    assert probe.main(["read", str(tmp_path / "artifact")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "ok" and report["install_hooks"]


def test_a_bad_command_prints_usage():
    assert probe.main(["run", "anything"]) == 2


def test_plain_http_is_never_fetched():
    with pytest.raises(urllib.error.URLError):
        probe._Fetch().get("http://example.test/", 10)
