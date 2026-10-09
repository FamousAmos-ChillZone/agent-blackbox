"""Refine R1 — the operator's rights over the reporter identity:
`blackbox report --export`, `--restore-key` and `--erase-identity`.

All local, all through the real parser. The export carries a key backup (so
a reinstall does not drop a counted author) and is written owner-only and
never over an existing file; restore refuses to swap identities; erase needs
--confirm and is honest about what it cannot delete.
"""

from __future__ import annotations

import argparse
import json
import stat

import pytest

from plugins.blackbox import audit, cli
from plugins.blackbox.community.report_cli import report_command
from plugins.blackbox.kernel import reporter_key


@pytest.fixture
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path


def _run(*argv):
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    return report_command.cmd_report(parser.parse_args(["report", *argv]))


def _signer():
    return reporter_key.ReporterKeyStore().public_key_hex()


def _ledger_one():
    audit.record_share_outcome(identifier="ioc:domain:evil.example", category="ioc", severity="high",
                               subject="urn:guardian:report:0xabc:1", asset_name="report-1", ok=True,
                               outcome="accepted")


# ------------------------------------------------------------------ export


def test_export_writes_statements_and_a_key_backup_owner_only(home, capsys):
    signer = _signer()
    _ledger_one()
    target = home / "export.json"
    assert _run("--export", str(target)) == 0
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["format"] == "blackbox-reporter-export" and document["reporter_public_key"] == signer
    assert document["reporter_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
    assert [row["identifier"] for row in document["statements"]] == ["ioc:domain:evil.example"]
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert "PRIVATE KEY" in capsys.readouterr().out    # the operator is told what the file holds


def test_export_never_overwrites_a_file(home):
    _signer()
    target = home / "export.json"
    target.write_text("keep me", encoding="utf-8")
    assert _run("--export", str(target)) == 2
    assert target.read_text(encoding="utf-8") == "keep me"


def test_export_without_a_key_exports_nothing(home):
    assert _run("--export", str(home / "export.json")) == 2
    assert not (home / "export.json").exists()


# ------------------------------------------------------------------ restore


def test_export_erase_restore_brings_back_the_same_author(home):
    signer = _signer()
    target = home / "export.json"
    assert _run("--export", str(target)) == 0
    assert _run("--erase-identity", "--confirm") == 0
    assert _run("--restore-key", str(target)) == 0
    assert _signer() == signer


def test_restore_refuses_to_replace_a_different_key(home):
    _signer()
    target = home / "export.json"
    assert _run("--export", str(target)) == 0
    assert _run("--erase-identity", "--confirm") == 0
    other = _signer()                                  # a new identity was created meanwhile
    assert _run("--restore-key", str(target)) == 2
    assert _signer() == other                          # unchanged


def test_restore_is_idempotent_and_accepts_a_bare_pem(home):
    signer = _signer()
    pem_file = home / "key.pem"
    pem_file.write_bytes(reporter_key.ReporterKeyStore().export_pem())
    assert _run("--restore-key", str(pem_file)) == 0
    assert _signer() == signer


def test_restore_refuses_garbage(home):
    junk = home / "junk.json"
    junk.write_text('{"format": "something-else"}', encoding="utf-8")
    assert _run("--restore-key", str(junk)) == 2
    assert not reporter_key.ReporterKeyStore().path.exists()


# ------------------------------------------------------------------ erase


def test_erase_without_confirm_changes_nothing(home, capsys):
    signer = _signer()
    _ledger_one()
    assert _run("--erase-identity") == 2
    out = capsys.readouterr().out
    assert "cannot delete" in out and "--retract" in out and "Nothing was changed" in out
    assert _signer() == signer and audit.read_share_ledger()


def test_erase_destroys_the_key_and_local_records(home):
    signer = _signer()
    _ledger_one()
    assert _run("--erase-identity", "--confirm") == 0
    assert audit.read_share_ledger() == []
    assert not reporter_key.ReporterKeyStore().path.exists()
    assert _signer() != signer                         # the next use is a new identity
