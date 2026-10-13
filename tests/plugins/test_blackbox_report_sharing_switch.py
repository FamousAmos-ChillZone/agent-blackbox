"""Turning community sharing on and off from the command line (KI-299).

Sharing is ON by default (2026-10-12). `--disable-sharing` sets `report: false`;
`--enable-sharing` turns it back on and, after an opt-out
(`--withdraw-consent`), is itself the opt-back-in. `--consent` records an
acceptance and says plainly whether the `report` switch is on.
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


def test_enable_sharing_after_an_opt_out_opts_back_in(real_consent, capsys):
    real_consent.withdraw()

    code = report_command.cmd_report(_parse("--enable-sharing"))

    assert code == 0 and load_blackbox_config().report is True and real_consent.in_force()
    assert "sharing is on" in capsys.readouterr().out.lower()


def test_disable_sharing_turns_report_off(real_consent):
    real_consent.record()
    report_command.cmd_report(_parse("--enable-sharing"))

    code = report_command.cmd_report(_parse("--disable-sharing"))

    assert code == 0 and load_blackbox_config().report is False


def test_consent_says_plainly_that_sharing_is_still_off_and_how_to_turn_it_on(real_consent, capsys):
    report_command.cmd_report(_parse("--disable-sharing"))
    capsys.readouterr()

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
    assert not {"version", "yolo", "oneshot", "command"} & set(vars(args))   # KI-276 fixed: no option uses them
