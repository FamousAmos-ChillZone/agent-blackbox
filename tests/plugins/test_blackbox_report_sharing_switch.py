"""Turning community sharing on and off from the command line (KI-299).

Consent and the sharing switch are separate on purpose (unbundled consent):
`blackbox report --consent` records the opt-in; sharing then runs only with
`report: true`. Before this, the second step had no command — only the
dashboard toggle or a hand edit of config.yaml — and the consent message
("(`report: true` in the config)") read like a statement, not an instruction
(fresh installs D/E, bench swm21, 2026-10-07).
"""

from __future__ import annotations

import argparse

from plugins.blackbox.community.report_cli import report_command, report_rights
from plugins.blackbox.kernel.config import load_blackbox_config


def _parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    report_command.add_report_parser(sub)
    return parser.parse_args(["report", *argv])


def test_enable_sharing_turns_report_on_when_consent_is_in_force(real_consent, capsys):
    real_consent.record()

    code = report_command.cmd_report(_parse("--enable-sharing"))

    assert code == 0 and load_blackbox_config().report is True
    assert "sharing is on" in capsys.readouterr().out.lower()


def test_enable_sharing_without_consent_is_refused_and_says_how(real_consent, capsys):
    code = report_command.cmd_report(_parse("--enable-sharing"))

    out = capsys.readouterr().out
    assert code == 1 and load_blackbox_config().report is False
    assert "blackbox report --consent" in out


def test_disable_sharing_turns_report_off(real_consent):
    real_consent.record()
    report_command.cmd_report(_parse("--enable-sharing"))

    code = report_command.cmd_report(_parse("--disable-sharing"))

    assert code == 0 and load_blackbox_config().report is False


def test_consent_says_plainly_that_sharing_is_still_off_and_how_to_turn_it_on(real_consent, capsys):
    code = report_rights.record_consent()

    out = capsys.readouterr().out
    assert code == 0
    assert "still off" in out.lower() and "blackbox report --enable-sharing" in out


def test_consent_when_sharing_is_already_on_says_so(real_consent, capsys):
    real_consent.record()
    report_command.cmd_report(_parse("--enable-sharing"))
    capsys.readouterr()

    report_rights.record_consent()

    assert "sharing is on" in capsys.readouterr().out.lower()


def test_the_new_options_are_not_stored_under_a_name_hermes_reads_first():
    """LES-035: Hermes reads version / yolo / oneshot / command before dispatch."""
    args = _parse("--enable-sharing", "--disable-sharing")
    assert args.enable_sharing is True and args.disable_sharing is True
    # (the older --package-version still stores under `version` here — KI-276,
    # fixed on feat/community-curation; this checks only the new options)
